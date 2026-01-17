#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            {
                HANDLE hFile = CreateFileA("C:\\temp\\reflective_dll_test.txt", 
                                          GENERIC_WRITE, 
                                          0, 
                                          NULL, 
                                          CREATE_ALWAYS, 
                                          FILE_ATTRIBUTE_NORMAL, 
                                          NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    const char *msg = "Reflective DLL Load Successful!\r\n";
                    DWORD written;
                    WriteFile(hFile, msg, strlen(msg), &written, NULL);
                    CloseHandle(hFile);
                }
                
                MessageBoxA(NULL, 
                           "Test DLL loaded successfully via reflective loader!", 
                           "QuantumForge Test DLL", 
                           MB_OK | MB_ICONINFORMATION);
            }
            break;
            
        case DLL_PROCESS_DETACH:
            break;
            
        case DLL_THREAD_ATTACH:
            break;
            
        case DLL_THREAD_DETACH:
            break;
    }
    
    return TRUE;
}

__declspec(dllexport) void TestFunction() {
    MessageBoxA(NULL, 
               "TestFunction called successfully!", 
               "QuantumForge Test DLL", 
               MB_OK);
}
