#ifndef QF_SECCOMP_H
#define QF_SECCOMP_H

#ifdef __linux__
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <errno.h>

#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#else
#error "Unsupported architecture for seccomp"
#endif

#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

static inline int qf_enable_seccomp_strict() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
        
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(lstat),
        ALLOW_SYSCALL(poll),
        ALLOW_SYSCALL(lseek),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(mprotect),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(rt_sigaction),
        ALLOW_SYSCALL(rt_sigprocmask),
        ALLOW_SYSCALL(rt_sigreturn),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(access),
        ALLOW_SYSCALL(select),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(sendto),
        ALLOW_SYSCALL(recvfrom),
        ALLOW_SYSCALL(bind),
        ALLOW_SYSCALL(listen),
        ALLOW_SYSCALL(accept),
        ALLOW_SYSCALL(getpid),
        ALLOW_SYSCALL(clone),
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(wait4),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(flock),
        ALLOW_SYSCALL(getdents),
        ALLOW_SYSCALL(getcwd),
        ALLOW_SYSCALL(chdir),
        ALLOW_SYSCALL(rename),
        ALLOW_SYSCALL(mkdir),
        ALLOW_SYSCALL(rmdir),
        ALLOW_SYSCALL(unlink),
        ALLOW_SYSCALL(readlink),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(getrlimit),
        ALLOW_SYSCALL(getrusage),
        ALLOW_SYSCALL(sysinfo),
        ALLOW_SYSCALL(times),
        ALLOW_SYSCALL(getuid),
        ALLOW_SYSCALL(getgid),
        ALLOW_SYSCALL(geteuid),
        ALLOW_SYSCALL(getegid),
        ALLOW_SYSCALL(setuid),
        ALLOW_SYSCALL(setgid),
        ALLOW_SYSCALL(arch_prctl),
        ALLOW_SYSCALL(prctl),
        ALLOW_SYSCALL(gettid),
        ALLOW_SYSCALL(futex),
        ALLOW_SYSCALL(set_tid_address),
        ALLOW_SYSCALL(clock_gettime),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(newfstatat),
        ALLOW_SYSCALL(unlinkat),
        ALLOW_SYSCALL(faccessat),
        ALLOW_SYSCALL(pread64),
        ALLOW_SYSCALL(pwrite64),
        ALLOW_SYSCALL(getrandom),
        ALLOW_SYSCALL(memfd_create),
        ALLOW_SYSCALL(execveat),
        
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return -1;
    }
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        return -1;
    }
    
    return 0;
}

static inline int qf_enable_seccomp_relaxed() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
        
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        ALLOW_SYSCALL(execve),
        ALLOW_SYSCALL(ptrace),
        ALLOW_SYSCALL(kill),
        
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    };
    
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        return -1;
    }
    
    return 0;
}

#else

static inline int qf_enable_seccomp_strict() {
    return 0;
}

static inline int qf_enable_seccomp_relaxed() {
    return 0;
}

#endif

#endif
