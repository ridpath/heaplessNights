#ifndef QF_CRYPTO_H
#define QF_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <strings.h>
#endif

static inline void secure_zero_memory(void *ptr, size_t len) {
#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#elif defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

static inline int constant_time_memcmp(const void *a, const void *b, size_t len) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return CRYPTO_memcmp(a, b, len);
#else
    const unsigned char *_a = (const unsigned char *)a;
    const unsigned char *_b = (const unsigned char *)b;
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= _a[i] ^ _b[i];
    }
    return result;
#endif
}

static inline int check_entropy_quality(void) {
#ifndef _WIN32
    FILE *f = fopen("/proc/sys/kernel/random/entropy_avail", "r");
    if (f) {
        int entropy = 0;
        if (fscanf(f, "%d", &entropy) == 1) {
            fclose(f);
            return entropy >= 128 ? 1 : 0;
        }
        fclose(f);
    }
#endif
    return 1;
}

int qf_hkdf_extract(unsigned char *prk, size_t *prk_len,
                    const unsigned char *salt, size_t salt_len,
                    const unsigned char *ikm, size_t ikm_len) {
    unsigned int len = EVP_MD_size(EVP_sha256());
    
    if (!HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, &len)) {
        return 0;
    }
    
    *prk_len = len;
    return 1;
}

int qf_hkdf_expand(unsigned char *okm, size_t okm_len,
                   const unsigned char *prk, size_t prk_len,
                   const unsigned char *info, size_t info_len) {
    unsigned char prev[EVP_MAX_MD_SIZE];
    unsigned char counter = 1;
    size_t done = 0;
    unsigned int hash_len;
    
    while (done < okm_len) {
        unsigned char *hmac_input;
        size_t hmac_input_len;
        
        if (counter == 1) {
            hmac_input = (unsigned char *)info;
            hmac_input_len = info_len + 1;
        } else {
            hmac_input = prev;
            hmac_input_len = hash_len + info_len + 1;
        }
        
        unsigned char tmp[EVP_MAX_MD_SIZE + 256];
        if (counter > 1) {
            memcpy(tmp, prev, hash_len);
        }
        if (info && info_len > 0) {
            memcpy(tmp + (counter > 1 ? hash_len : 0), info, info_len);
        }
        tmp[(counter > 1 ? hash_len : 0) + info_len] = counter;
        
        if (!HMAC(EVP_sha256(), prk, prk_len, tmp, 
                  (counter > 1 ? hash_len : 0) + info_len + 1, prev, &hash_len)) {
            return 0;
        }
        
        size_t to_copy = okm_len - done;
        if (to_copy > hash_len) {
            to_copy = hash_len;
        }
        
        memcpy(okm + done, prev, to_copy);
        done += to_copy;
        counter++;
        
        if (counter > 255) {
            return 0;
        }
    }
    
    secure_zero_memory(prev, sizeof(prev));
    return 1;
}

int qf_hkdf(unsigned char *out_key, size_t out_len,
            const unsigned char *salt, size_t salt_len,
            const unsigned char *ikm, size_t ikm_len,
            const unsigned char *info, size_t info_len) {
    unsigned char prk[EVP_MAX_MD_SIZE];
    size_t prk_len;
    
    if (!check_entropy_quality()) {
        return 0;
    }
    
    if (!qf_hkdf_extract(prk, &prk_len, salt, salt_len, ikm, ikm_len)) {
        secure_zero_memory(prk, sizeof(prk));
        return 0;
    }
    
    int ret = qf_hkdf_expand(out_key, out_len, prk, prk_len, info, info_len);
    secure_zero_memory(prk, sizeof(prk));
    
    return ret;
}

int qf_aes_decrypt(unsigned char *plaintext, int *plaintext_len,
                   const unsigned char *ciphertext, int ciphertext_len,
                   const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
    
    int len;
    int ret = 0;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        goto cleanup;
    }
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        goto cleanup;
    }
    
    *plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        goto cleanup;
    }
    
    *plaintext_len += len;
    ret = 1;
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#endif
