#include <windows.h>

// Simple exported function that displays a message box with supplied text.
extern "C" __declspec(dllexport)
void SendText(const char* msg) {
    MessageBoxA(nullptr, msg, "Injected", MB_OK);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}
