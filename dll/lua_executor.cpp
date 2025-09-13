#include <windows.h>

// Address of FrameScript_ExecuteBuffer in Ascension.exe/WoW.exe
static constexpr uintptr_t kFrameScriptExecuteBuffer = 0x00406D70; // adjust if different

typedef int (__cdecl *FrameScriptExecuteBuffer_t)(const char*, const char*, int);

extern "C" __declspec(dllexport)
int RunLua(const char* code) {
    FrameScriptExecuteBuffer_t fn = (FrameScriptExecuteBuffer_t)kFrameScriptExecuteBuffer;
    return fn(code, "Injected", 0);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}
