#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

BOOL resolve_imports(LPVOID pBaseAddress, IMAGE_NT_HEADERS *pNTHeaders) {
    IMAGE_DATA_DIRECTORY *pImportDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size == 0) return TRUE;
    
    IMAGE_IMPORT_DESCRIPTOR *pImportDesc = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD_PTR)pBaseAddress + pImportDir->VirtualAddress);
    
    while (pImportDesc->Name) {
        char *szModName = (char *)((DWORD_PTR)pBaseAddress + pImportDesc->Name);
        HMODULE hModule = LoadLibraryA(szModName);
        if (!hModule) {
            printf("[!] Failed to load module: %s\n", szModName);
            return FALSE;
        }
        printf("[*] Loaded module: %s\n", szModName);
        
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

BOOL process_relocations(LPVOID pBaseAddress, IMAGE_NT_HEADERS *pNTHeaders, DWORD_PTR deltaImageBase) {
    IMAGE_DATA_DIRECTORY *pRelocDir = &pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (pRelocDir->Size == 0) {
        printf("[*] No relocations needed\n");
        return TRUE;
    }
    
    printf("[*] Processing relocations (delta: 0x%llx)\n", deltaImageBase);
    
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

BOOL reflective_dll_load(unsigned char *pDllBuffer, size_t dllSize) {
    if (!pDllBuffer || dllSize < sizeof(IMAGE_DOS_HEADER)) {
        printf("[!] Invalid DLL buffer\n");
        return FALSE;
    }
    
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pDllBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature: 0x%x (expected 0x%x)\n", pDosHeader->e_magic, IMAGE_DOS_SIGNATURE);
        return FALSE;
    }
    printf("[+] DOS header valid (MZ signature found)\n");
    
    IMAGE_NT_HEADERS *pNTHeaders = (IMAGE_NT_HEADERS *)((DWORD_PTR)pDllBuffer + pDosHeader->e_lfanew);
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid PE signature: 0x%x (expected 0x%x)\n", pNTHeaders->Signature, IMAGE_NT_SIGNATURE);
        return FALSE;
    }
    printf("[+] PE header valid (PE signature found)\n");
    
    if (pNTHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && 
        pNTHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        printf("[!] Unsupported architecture: 0x%x\n", pNTHeaders->FileHeader.Machine);
        return FALSE;
    }
    printf("[+] Architecture: %s\n", 
           pNTHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x86");
    
    SIZE_T imageSize = pNTHeaders->OptionalHeader.SizeOfImage;
    printf("[*] Image size: %zu bytes\n", imageSize);
    
    LPVOID pImageBase = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        printf("[!] VirtualAlloc failed: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Allocated memory at: 0x%p\n", pImageBase);
    
    memcpy(pImageBase, pDllBuffer, pNTHeaders->OptionalHeader.SizeOfHeaders);
    printf("[*] Copied PE headers (%d bytes)\n", pNTHeaders->OptionalHeader.SizeOfHeaders);
    
    IMAGE_SECTION_HEADER *pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaders);
    printf("[*] Copying %d sections:\n", pNTHeaders->FileHeader.NumberOfSections);
    for (WORD i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        if (pSectionHeader->SizeOfRawData > 0) {
            LPVOID pSectionDest = (LPVOID)((DWORD_PTR)pImageBase + pSectionHeader->VirtualAddress);
            LPVOID pSectionSrc = (LPVOID)((DWORD_PTR)pDllBuffer + pSectionHeader->PointerToRawData);
            memcpy(pSectionDest, pSectionSrc, pSectionHeader->SizeOfRawData);
            printf("[*]   %.8s -> 0x%p (%d bytes)\n", pSectionHeader->Name, pSectionDest, pSectionHeader->SizeOfRawData);
        }
    }
    
    DWORD_PTR deltaImageBase = (DWORD_PTR)pImageBase - pNTHeaders->OptionalHeader.ImageBase;
    IMAGE_NT_HEADERS *pRelocatedNTHeaders = (IMAGE_NT_HEADERS *)((DWORD_PTR)pImageBase + pDosHeader->e_lfanew);
    
    if (deltaImageBase != 0) {
        if (!process_relocations(pImageBase, pRelocatedNTHeaders, deltaImageBase)) {
            printf("[!] Relocation processing failed\n");
            VirtualFree(pImageBase, 0, MEM_RELEASE);
            return FALSE;
        }
        printf("[+] Relocations processed successfully\n");
    }
    
    if (!resolve_imports(pImageBase, pRelocatedNTHeaders)) {
        printf("[!] Import resolution failed\n");
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] Imports resolved successfully\n");
    
    pSectionHeader = IMAGE_FIRST_SECTION(pRelocatedNTHeaders);
    printf("[*] Setting section protections:\n");
    for (WORD i = 0; i < pRelocatedNTHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        DWORD oldProtect;
        LPVOID pSectionAddr = (LPVOID)((DWORD_PTR)pImageBase + pSectionHeader->VirtualAddress);
        
        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            VirtualProtect(pSectionAddr, pSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READ, &oldProtect);
            printf("[*]   %.8s -> PAGE_EXECUTE_READ\n", pSectionHeader->Name);
        } else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
            VirtualProtect(pSectionAddr, pSectionHeader->Misc.VirtualSize, PAGE_READWRITE, &oldProtect);
            printf("[*]   %.8s -> PAGE_READWRITE\n", pSectionHeader->Name);
        } else {
            VirtualProtect(pSectionAddr, pSectionHeader->Misc.VirtualSize, PAGE_READONLY, &oldProtect);
            printf("[*]   %.8s -> PAGE_READONLY\n", pSectionHeader->Name);
        }
    }
    
    DllEntryProc pDllEntry = (DllEntryProc)((DWORD_PTR)pImageBase + pRelocatedNTHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("[*] DllMain entry point: 0x%p\n", pDllEntry);
    
    if (pDllEntry) {
        printf("[*] Calling DllMain(DLL_PROCESS_ATTACH)...\n");
        BOOL result = pDllEntry((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL);
        if (!result) {
            printf("[!] DllMain returned FALSE\n");
            VirtualFree(pImageBase, 0, MEM_RELEASE);
            return FALSE;
        }
        printf("[+] DllMain returned successfully\n");
    }
    
    printf("[+] Reflective DLL load complete!\n");
    return TRUE;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <test_dll.dll>\n", argv[0]);
        return 1;
    }
    
    printf("[*] QuantumForge Reflective DLL Loader Test\n");
    printf("[*] Loading DLL: %s\n\n", argv[1]);
    
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open file: %s (error: %d)\n", argv[1], GetLastError());
        return 1;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] Failed to get file size\n");
        CloseHandle(hFile);
        return 1;
    }
    printf("[*] File size: %d bytes\n", fileSize);
    
    unsigned char *pDllBuffer = (unsigned char *)malloc(fileSize);
    if (!pDllBuffer) {
        printf("[!] Failed to allocate buffer\n");
        CloseHandle(hFile);
        return 1;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, pDllBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] Failed to read file\n");
        free(pDllBuffer);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);
    printf("[+] DLL loaded into memory\n\n");
    
    BOOL success = reflective_dll_load(pDllBuffer, fileSize);
    
    if (success) {
        printf("\n[SUCCESS] Reflective DLL loader test passed!\n");
        printf("Press Enter to exit...\n");
        getchar();
    } else {
        printf("\n[FAILED] Reflective DLL loader test failed!\n");
    }
    
    free(pDllBuffer);
    return success ? 0 : 1;
}
