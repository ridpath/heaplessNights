#ifndef ANTI_ANALYSIS_H
#define ANTI_ANALYSIS_H

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#ifdef __linux__
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sys/syscall.h>
#elif __APPLE__
#include <sys/sysctl.h>
#endif
#endif

static inline uint64_t rdtsc_timing() {
#ifdef _WIN32
    return __rdtsc();
#else
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#endif
}

static inline int check_vm_cpuid() {
    char vendor[13] = {0};
    unsigned int eax, ebx, ecx, edx;
    
#ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
#else
    __asm__ __volatile__ ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
#endif
    
    if (strcmp(vendor, "VMwareVMware") == 0 ||
        strcmp(vendor, "KVMKVMKVM") == 0 ||
        strcmp(vendor, "Microsoft Hv") == 0) {
        return 1;
    }
    
#ifdef _WIN32
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1) {
        return 1;
    }
#else
    __asm__ __volatile__ ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    if ((ecx >> 31) & 1) {
        return 1;
    }
#endif
    
    return 0;
}

static inline int check_vm_virtualbox() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\RSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxGuest", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxMouse", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxSF", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    HMODULE hModule = LoadLibraryA("VBoxHook.dll");
    if (hModule != NULL) {
        FreeLibrary(hModule);
        return 1;
    }
#else
    int fd = open("/sys/class/dmi/id/product_name", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, "VirtualBox") != NULL) {
                return 1;
            }
        }
    }
    fd = open("/proc/scsi/scsi", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, "VBOX") != NULL) {
                return 1;
            }
        }
    }
#endif
    return 0;
}

static inline int check_debugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return 1;
    }
    
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    if (isDebugged) {
        return 1;
    }
    
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        typedef NTSTATUS(WINAPI* pNtQuery)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        pNtQuery NtQueryInformationProcess = (pNtQuery)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        if (NtQueryInformationProcess) {
            DWORD debugPort = 0;
            NtQueryInformationProcess(GetCurrentProcess(), 0x07, &debugPort, sizeof(DWORD), NULL);
            if (debugPort) {
                return 1;
            }
        }
    }
    
    __try {
        DebugBreak();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }
    
#elif __linux__
    char buf[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *tracer = strstr(buf, "TracerPid:");
    if (tracer) {
        int pid = atoi(tracer + 10);
        if (pid != 0) {
            return 1;
        }
    }
    
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return 1;
    }
    ptrace(PTRACE_DETACH, 0, 1, 0);
    
#elif __APPLE__
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    if ((info.kp_proc.p_flag & P_TRACED) != 0) {
        return 1;
    }
#endif
    
    return 0;
}

static inline int check_parent_pid() {
#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = 0;
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentPid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    if (parentPid == 0) {
        CloseHandle(hSnapshot);
        return 0;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == parentPid) {
                char *exeName = pe32.szExeFile;
                if (strstr(exeName, "x64dbg.exe") != NULL ||
                    strstr(exeName, "x32dbg.exe") != NULL ||
                    strstr(exeName, "ollydbg.exe") != NULL ||
                    strstr(exeName, "windbg.exe") != NULL ||
                    strstr(exeName, "ida.exe") != NULL ||
                    strstr(exeName, "ida64.exe") != NULL ||
                    strstr(exeName, "immunity") != NULL ||
                    strstr(exeName, "wireshark.exe") != NULL ||
                    strstr(exeName, "processhacker.exe") != NULL ||
                    strstr(exeName, "procmon.exe") != NULL ||
                    strstr(exeName, "procexp.exe") != NULL) {
                    CloseHandle(hSnapshot);
                    return 1;
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
#else
    pid_t ppid = getppid();
    char path[256];
    char buf[256];
    
#ifdef __linux__
    snprintf(path, sizeof(path), "/proc/%d/comm", ppid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (buf[n-1] == '\n') buf[n-1] = '\0';
            if (strstr(buf, "gdb") != NULL ||
                strstr(buf, "strace") != NULL ||
                strstr(buf, "ltrace") != NULL ||
                strstr(buf, "radare2") != NULL ||
                strstr(buf, "r2") != NULL ||
                strstr(buf, "edb") != NULL ||
                strstr(buf, "valgrind") != NULL) {
                return 1;
            }
        }
    }
#elif __APPLE__
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if (strstr(info.kp_proc.p_comm, "lldb") != NULL ||
            strstr(info.kp_proc.p_comm, "gdb") != NULL ||
            strstr(info.kp_proc.p_comm, "dtruss") != NULL ||
            strstr(info.kp_proc.p_comm, "instruments") != NULL) {
            return 1;
        }
    }
#endif
#endif
    
    return 0;
}

static inline int check_timing_sandbox() {
    uint64_t start, end;
    
#ifdef _WIN32
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    Sleep(1);
    QueryPerformanceCounter(&t2);
    double elapsed = (double)(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
    if (elapsed < 0.5 || elapsed > 2.0) {
        return 1;
    }
#else
    struct timespec req = {0, 1000000};
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    nanosleep(&req, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t2);
    double elapsed = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1000000.0;
    if (elapsed < 0.5 || elapsed > 2.0) {
        return 1;
    }
#endif
    
    start = rdtsc_timing();
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) {
        x += i;
    }
    end = rdtsc_timing();
    
    if ((end - start) < 100000 || (end - start) > 100000000) {
        return 1;
    }
    
    return 0;
}

static inline int check_cpu_count() {
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors < 2;
#elif __linux__
    return sysconf(_SC_NPROCESSORS_ONLN) < 2;
#elif __APPLE__
    int cpu_count;
    size_t len = sizeof(cpu_count);
    sysctlbyname("hw.ncpu", &cpu_count, &len, NULL, 0);
    return cpu_count < 2;
#endif
    return 0;
}

static inline int check_all_anti_analysis(int skip_checks) {
    if (skip_checks) {
        return 0;
    }
    
    if (check_debugger()) {
        return 1;
    }
    
    if (check_parent_pid()) {
        return 1;
    }
    
    if (check_vm_cpuid()) {
        return 1;
    }
    
    if (check_vm_virtualbox()) {
        return 1;
    }
    
    if (check_timing_sandbox()) {
        return 1;
    }
    
    if (check_cpu_count()) {
        return 1;
    }
    
    return 0;
}

#endif
