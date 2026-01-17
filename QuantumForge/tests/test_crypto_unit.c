#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../qf_crypto.h"

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

void test_secure_zero_memory() {
    printf("Testing secure_zero_memory()... ");
    
    unsigned char buffer[256];
    memset(buffer, 0xAA, sizeof(buffer));
    
    secure_zero_memory(buffer, sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            printf("%s - Memory not cleared at offset %zu\n", TEST_FAIL, i);
            tests_failed++;
            return;
        }
    }
    
    printf("%s\n", TEST_PASS);
    tests_passed++;
}

void test_constant_time_memcmp() {
    printf("Testing constant_time_memcmp()... ");
    
    unsigned char a[] = {0x01, 0x02, 0x03, 0x04};
    unsigned char b[] = {0x01, 0x02, 0x03, 0x04};
    unsigned char c[] = {0x01, 0x02, 0x03, 0x05};
    
    if (constant_time_memcmp(a, b, 4) != 0) {
        printf("%s - Equal buffers not matched\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    if (constant_time_memcmp(a, c, 4) == 0) {
        printf("%s - Different buffers matched\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    printf("%s\n", TEST_PASS);
    tests_passed++;
}

void test_hkdf_extract() {
    printf("Testing qf_hkdf_extract()... ");
    
    unsigned char salt[] = "test_salt_12345";
    unsigned char ikm[] = "input_key_material_test";
    unsigned char prk[EVP_MAX_MD_SIZE];
    size_t prk_len;
    
    if (!qf_hkdf_extract(prk, &prk_len, salt, strlen((char*)salt), ikm, strlen((char*)ikm))) {
        printf("%s - HKDF extract failed\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    if (prk_len != 32) {
        printf("%s - Invalid PRK length: %zu (expected 32)\n", TEST_FAIL, prk_len);
        tests_failed++;
        return;
    }
    
    int all_zero = 1;
    for (size_t i = 0; i < prk_len; i++) {
        if (prk[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        printf("%s - PRK is all zeros\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    printf("%s\n", TEST_PASS);
    tests_passed++;
}

void test_hkdf_expand() {
    printf("Testing qf_hkdf_expand()... ");
    
    unsigned char prk[32];
    memset(prk, 0xBB, sizeof(prk));
    
    unsigned char info[] = "test_info";
    unsigned char okm[64];
    
    if (!qf_hkdf_expand(okm, sizeof(okm), prk, sizeof(prk), info, strlen((char*)info))) {
        printf("%s - HKDF expand failed\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    int all_same = 1;
    for (size_t i = 1; i < sizeof(okm); i++) {
        if (okm[i] != okm[0]) {
            all_same = 0;
            break;
        }
    }
    
    if (all_same) {
        printf("%s - OKM has no entropy\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    printf("%s\n", TEST_PASS);
    tests_passed++;
}

void test_hkdf_full() {
    printf("Testing qf_hkdf() full derivation... ");
    
    unsigned char salt[] = "quantumforge_salt_2026";
    unsigned char ikm[] = "base_key_material_test_12345";
    unsigned char info[] = "application_context";
    unsigned char out_key[32];
    
    if (!qf_hkdf(out_key, sizeof(out_key), salt, strlen((char*)salt), 
                 ikm, strlen((char*)ikm), info, strlen((char*)info))) {
        printf("%s - Full HKDF failed\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    unsigned char out_key2[32];
    if (!qf_hkdf(out_key2, sizeof(out_key2), salt, strlen((char*)salt), 
                 ikm, strlen((char*)ikm), info, strlen((char*)info))) {
        printf("%s - Second HKDF call failed\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    if (memcmp(out_key, out_key2, sizeof(out_key)) != 0) {
        printf("%s - HKDF not deterministic\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    unsigned char different_salt[] = "different_salt_123";
    unsigned char out_key3[32];
    if (!qf_hkdf(out_key3, sizeof(out_key3), different_salt, strlen((char*)different_salt), 
                 ikm, strlen((char*)ikm), info, strlen((char*)info))) {
        printf("%s - Third HKDF call failed\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    if (memcmp(out_key, out_key3, sizeof(out_key)) == 0) {
        printf("%s - Different salts produced same output\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    printf("%s\n", TEST_PASS);
    tests_passed++;
}

void test_aes_decrypt() {
    printf("Testing qf_aes_decrypt()... ");
    
    unsigned char key[32];
    memset(key, 0x42, sizeof(key));
    
    unsigned char iv[16];
    memset(iv, 0x01, sizeof(iv));
    
    unsigned char plaintext_orig[] = "Hello QuantumForge! This is a test payload for AES-256-CBC encryption and decryption.";
    int plaintext_len = strlen((char*)plaintext_orig);
    
    unsigned char ciphertext[256];
    int ciphertext_len;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("%s - Failed to create cipher context\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        printf("%s - Encryption init failed\n", TEST_FAIL);
        EVP_CIPHER_CTX_free(ctx);
        tests_failed++;
        return;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext_orig, plaintext_len) != 1) {
        printf("%s - Encryption update failed\n", TEST_FAIL);
        EVP_CIPHER_CTX_free(ctx);
        tests_failed++;
        return;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        printf("%s - Encryption final failed\n", TEST_FAIL);
        EVP_CIPHER_CTX_free(ctx);
        tests_failed++;
        return;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    unsigned char decrypted[256];
    int decrypted_len;
    
    if (!qf_aes_decrypt(decrypted, &decrypted_len, ciphertext, ciphertext_len, key, iv)) {
        printf("%s - Decryption failed\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    if (decrypted_len != plaintext_len) {
        printf("%s - Decrypted length mismatch: %d != %d\n", TEST_FAIL, decrypted_len, plaintext_len);
        tests_failed++;
        return;
    }
    
    if (memcmp(decrypted, plaintext_orig, plaintext_len) != 0) {
        printf("%s - Decrypted content mismatch\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    printf("%s\n", TEST_PASS);
    tests_passed++;
}

void test_check_entropy_quality() {
    printf("Testing check_entropy_quality()... ");
    
    int result = check_entropy_quality();
    
    if (result != 0 && result != 1) {
        printf("%s - Invalid return value: %d\n", TEST_FAIL, result);
        tests_failed++;
        return;
    }
    
    printf("%s (entropy: %s)\n", TEST_PASS, result ? "sufficient" : "low/N/A");
    tests_passed++;
}

void test_hkdf_rfc5869_vectors() {
    printf("Testing HKDF RFC 5869 Test Vectors... ");
    
    unsigned char ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    
    unsigned char salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                            0x08, 0x09, 0x0a, 0x0b, 0x0c};
    
    unsigned char info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
                            0xf8, 0xf9};
    
    unsigned char expected_okm[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    
    unsigned char okm[42];
    
    if (!qf_hkdf(okm, sizeof(okm), salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info))) {
        printf("%s - HKDF failed on RFC test vector\n", TEST_FAIL);
        tests_failed++;
        return;
    }
    
    if (memcmp(okm, expected_okm, sizeof(expected_okm)) != 0) {
        printf("%s - Output doesn't match RFC 5869 test vector\n", TEST_FAIL);
        printf("Expected: ");
        for (size_t i = 0; i < sizeof(expected_okm); i++) {
            printf("%02x", expected_okm[i]);
        }
        printf("\nGot:      ");
        for (size_t i = 0; i < sizeof(expected_okm); i++) {
            printf("%02x", okm[i]);
        }
        printf("\n");
        tests_failed++;
        return;
    }
    
    printf("%s\n", TEST_PASS);
    tests_passed++;
}

int main() {
    printf("\n");
    printf("========================================\n");
    printf("QuantumForge Crypto Unit Test Suite\n");
    printf("========================================\n\n");
    
    test_secure_zero_memory();
    test_constant_time_memcmp();
    test_check_entropy_quality();
    test_hkdf_extract();
    test_hkdf_expand();
    test_hkdf_full();
    test_hkdf_rfc5869_vectors();
    test_aes_decrypt();
    
    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n\n");
    
    return tests_failed > 0 ? 1 : 0;
}
