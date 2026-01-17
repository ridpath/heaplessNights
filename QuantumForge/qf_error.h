#ifndef QF_ERROR_H
#define QF_ERROR_H

#include <errno.h>
#include <string.h>

typedef enum {
    QF_SUCCESS = 0,
    
    QF_ERR_CRYPTO_INIT = 1000,
    QF_ERR_CRYPTO_HKDF_EXTRACT,
    QF_ERR_CRYPTO_HKDF_EXPAND,
    QF_ERR_CRYPTO_AES_INIT,
    QF_ERR_CRYPTO_AES_UPDATE,
    QF_ERR_CRYPTO_AES_FINAL,
    QF_ERR_CRYPTO_ENTROPY_LOW,
    QF_ERR_CRYPTO_KEY_DERIVE,
    
    QF_ERR_MEMORY_ALLOC = 2000,
    QF_ERR_MEMORY_MMAP,
    QF_ERR_MEMORY_MPROTECT,
    QF_ERR_MEMORY_MUNMAP,
    QF_ERR_MEMORY_MEMFD,
    
    QF_ERR_NETWORK_INIT = 3000,
    QF_ERR_NETWORK_CONNECT,
    QF_ERR_NETWORK_SEND,
    QF_ERR_NETWORK_RECV,
    QF_ERR_NETWORK_TIMEOUT,
    QF_ERR_NETWORK_DNS,
    QF_ERR_NETWORK_DOH_QUERY,
    QF_ERR_NETWORK_C2_BEACON,
    
    QF_ERR_FILE_OPEN = 4000,
    QF_ERR_FILE_READ,
    QF_ERR_FILE_WRITE,
    QF_ERR_FILE_CLOSE,
    QF_ERR_FILE_STAT,
    QF_ERR_FILE_UNLINK,
    
    QF_ERR_SYSCALL_EXECVEAT = 5000,
    QF_ERR_SYSCALL_DLOPEN,
    QF_ERR_SYSCALL_DLSYM,
    QF_ERR_SYSCALL_PRCTL,
    QF_ERR_SYSCALL_PTRACE,
    QF_ERR_SYSCALL_FORK,
    QF_ERR_SYSCALL_KILL,
    
    QF_ERR_PAYLOAD_INVALID = 6000,
    QF_ERR_PAYLOAD_DECRYPT,
    QF_ERR_PAYLOAD_CORRUPT,
    QF_ERR_PAYLOAD_TOO_LARGE,
    QF_ERR_PAYLOAD_FORMAT,
    
    QF_ERR_CONFIG_INVALID = 7000,
    QF_ERR_CONFIG_PARSE,
    QF_ERR_CONFIG_MISSING,
    
    QF_ERR_SECURITY_DEBUGGER = 8000,
    QF_ERR_SECURITY_VM_DETECT,
    QF_ERR_SECURITY_SANDBOX,
    QF_ERR_SECURITY_EDR_HOOK,
    QF_ERR_SECURITY_SECCOMP,
    
    QF_ERR_UNKNOWN = 9999,
} qf_error_t;

typedef struct {
    qf_error_t code;
    int sys_errno;
    const char *message;
    const char *file;
    int line;
} qf_error_context_t;

static qf_error_context_t qf_last_error = {QF_SUCCESS, 0, NULL, NULL, 0};

#define QF_SET_ERROR(code, msg) \
    do { \
        qf_last_error.code = (code); \
        qf_last_error.sys_errno = errno; \
        qf_last_error.message = (msg); \
        qf_last_error.file = __FILE__; \
        qf_last_error.line = __LINE__; \
    } while(0)

#define QF_RETURN_ERROR(code, msg) \
    do { \
        QF_SET_ERROR(code, msg); \
        return (code); \
    } while(0)

#define QF_CHECK(expr, code, msg) \
    do { \
        if (!(expr)) { \
            QF_RETURN_ERROR(code, msg); \
        } \
    } while(0)

#define QF_CHECK_SYSCALL(expr, code, msg) \
    do { \
        if ((expr) == -1) { \
            QF_RETURN_ERROR(code, msg); \
        } \
    } while(0)

static inline const char* qf_error_string(qf_error_t code) {
    switch (code) {
        case QF_SUCCESS: return "Success";
        
        case QF_ERR_CRYPTO_INIT: return "Cryptography initialization failed";
        case QF_ERR_CRYPTO_HKDF_EXTRACT: return "HKDF extract phase failed";
        case QF_ERR_CRYPTO_HKDF_EXPAND: return "HKDF expand phase failed";
        case QF_ERR_CRYPTO_AES_INIT: return "AES initialization failed";
        case QF_ERR_CRYPTO_AES_UPDATE: return "AES update failed";
        case QF_ERR_CRYPTO_AES_FINAL: return "AES finalization failed";
        case QF_ERR_CRYPTO_ENTROPY_LOW: return "System entropy too low";
        case QF_ERR_CRYPTO_KEY_DERIVE: return "Key derivation failed";
        
        case QF_ERR_MEMORY_ALLOC: return "Memory allocation failed";
        case QF_ERR_MEMORY_MMAP: return "mmap() failed";
        case QF_ERR_MEMORY_MPROTECT: return "mprotect() failed";
        case QF_ERR_MEMORY_MUNMAP: return "munmap() failed";
        case QF_ERR_MEMORY_MEMFD: return "memfd_create() failed";
        
        case QF_ERR_NETWORK_INIT: return "Network initialization failed";
        case QF_ERR_NETWORK_CONNECT: return "Connection failed";
        case QF_ERR_NETWORK_SEND: return "Send failed";
        case QF_ERR_NETWORK_RECV: return "Receive failed";
        case QF_ERR_NETWORK_TIMEOUT: return "Network timeout";
        case QF_ERR_NETWORK_DNS: return "DNS resolution failed";
        case QF_ERR_NETWORK_DOH_QUERY: return "DNS-over-HTTPS query failed";
        case QF_ERR_NETWORK_C2_BEACON: return "C2 beacon transmission failed";
        
        case QF_ERR_FILE_OPEN: return "Failed to open file";
        case QF_ERR_FILE_READ: return "Failed to read file";
        case QF_ERR_FILE_WRITE: return "Failed to write file";
        case QF_ERR_FILE_CLOSE: return "Failed to close file";
        case QF_ERR_FILE_STAT: return "Failed to stat file";
        case QF_ERR_FILE_UNLINK: return "Failed to unlink file";
        
        case QF_ERR_SYSCALL_EXECVEAT: return "execveat() syscall failed";
        case QF_ERR_SYSCALL_DLOPEN: return "dlopen() failed";
        case QF_ERR_SYSCALL_DLSYM: return "dlsym() failed";
        case QF_ERR_SYSCALL_PRCTL: return "prctl() failed";
        case QF_ERR_SYSCALL_PTRACE: return "ptrace() failed";
        case QF_ERR_SYSCALL_FORK: return "fork() failed";
        case QF_ERR_SYSCALL_KILL: return "kill() failed";
        
        case QF_ERR_PAYLOAD_INVALID: return "Invalid payload";
        case QF_ERR_PAYLOAD_DECRYPT: return "Payload decryption failed";
        case QF_ERR_PAYLOAD_CORRUPT: return "Payload corrupted";
        case QF_ERR_PAYLOAD_TOO_LARGE: return "Payload exceeds size limit";
        case QF_ERR_PAYLOAD_FORMAT: return "Invalid payload format";
        
        case QF_ERR_CONFIG_INVALID: return "Invalid configuration";
        case QF_ERR_CONFIG_PARSE: return "Configuration parse error";
        case QF_ERR_CONFIG_MISSING: return "Required configuration missing";
        
        case QF_ERR_SECURITY_DEBUGGER: return "Debugger detected";
        case QF_ERR_SECURITY_VM_DETECT: return "Virtual machine detected";
        case QF_ERR_SECURITY_SANDBOX: return "Sandbox environment detected";
        case QF_ERR_SECURITY_EDR_HOOK: return "EDR hook detected";
        case QF_ERR_SECURITY_SECCOMP: return "Seccomp filter installation failed";
        
        default: return "Unknown error";
    }
}

static inline void qf_print_error(void) {
    if (qf_last_error.code == QF_SUCCESS) {
        return;
    }
    
    fprintf(stderr, "[ERROR %d] %s\n", qf_last_error.code, 
            qf_error_string(qf_last_error.code));
    
    if (qf_last_error.message) {
        fprintf(stderr, "  Details: %s\n", qf_last_error.message);
    }
    
    if (qf_last_error.sys_errno != 0) {
        fprintf(stderr, "  System: %s (errno=%d)\n", 
                strerror(qf_last_error.sys_errno), qf_last_error.sys_errno);
    }
    
    if (qf_last_error.file) {
        fprintf(stderr, "  Location: %s:%d\n", 
                qf_last_error.file, qf_last_error.line);
    }
}

static inline qf_error_context_t qf_get_last_error(void) {
    return qf_last_error;
}

static inline void qf_clear_error(void) {
    qf_last_error.code = QF_SUCCESS;
    qf_last_error.sys_errno = 0;
    qf_last_error.message = NULL;
    qf_last_error.file = NULL;
    qf_last_error.line = 0;
}

#endif
