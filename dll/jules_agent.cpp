#include "jules_agent.h"
#include "ipc_structs.h"
#include <iostream>
#include <windows.h>

// --- Function Pointer Typedefs ---
typedef int (__cdecl *FrameScript_ExecuteBuffer_t)(const char* code, const char* context, int unk);
typedef int (__cdecl *FrameScript_Register_t)(const char* command, void(__cdecl*handler)(const char*, const char*));
typedef long (__stdcall *EndScene_t)(void* device);

// --- Global Pointers & State ---
FrameScript_ExecuteBuffer_t FrameScript_ExecuteBuffer = nullptr;
FrameScript_Register_t FrameScript_Register = nullptr;
EndScene_t o_EndScene = nullptr;
uintptr_t endSceneAddr_ = 0;
bool g_hook_installed = false;
SharedData* g_shared_data = nullptr;
HANDLE g_hMapFile = NULL;

// --- Hooking ---
BYTE original_bytes[5] = {0};

void __stdcall Hooked_EndScene(void* device) {
    if (g_shared_data && !g_shared_data->is_busy && g_shared_data->lua_code[0] != '\0') {
        g_shared_data->is_busy = true;
        ExecuteLua(g_shared_data->lua_code);
        g_shared_data->lua_code[0] = '\0';
        g_shared_data->is_busy = false;
    }
    o_EndScene(device);
}

void InstallHook() {
    if (!endSceneAddr_) return;

    // A 5-byte relative JMP hook is standard.
    DWORD hook_size = 5;

    DWORD curProtection;
    VirtualProtect((LPVOID)endSceneAddr_, hook_size, PAGE_EXECUTE_READWRITE, &curProtection);
    memcpy(original_bytes, (void*)endSceneAddr_, hook_size);

    uintptr_t relativeAddress = ((uintptr_t)Hooked_EndScene - endSceneAddr_) - hook_size;
    *(BYTE*)endSceneAddr_ = 0xE9; // JMP opcode
    *(uintptr_t*)(endSceneAddr_ + 1) = relativeAddress;

    VirtualProtect((LPVOID)endSceneAddr_, hook_size, curProtection, &curProtection);

    // Create the trampoline
    o_EndScene = (EndScene_t)VirtualAlloc(NULL, sizeof(original_bytes) + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy((LPVOID)o_EndScene, original_bytes, sizeof(original_bytes));

    // Correct jump-back calculation
    uintptr_t jumpBackAddress = endSceneAddr_ + hook_size;
    *(BYTE*)((uintptr_t)o_EndScene + sizeof(original_bytes)) = 0xE9; // JMP
    *(uintptr_t*)((uintptr_t)o_EndScene + sizeof(original_bytes) + 1) = jumpBackAddress - ((uintptr_t)o_EndScene + sizeof(original_bytes) + 5);

    g_hook_installed = true;
}

void RemoveHook() {
    if (!g_hook_installed || !endSceneAddr_) return;
    DWORD curProtection;
    VirtualProtect((LPVOID)endSceneAddr_, sizeof(original_bytes), PAGE_EXECUTE_READWRITE, &curProtection);
    memcpy((void*)endSceneAddr_, original_bytes, sizeof(original_bytes));
    VirtualProtect((LPVOID)endSceneAddr_, sizeof(original_bytes), curProtection, &curProtection);
    if (o_EndScene) VirtualFree((LPVOID)o_EndScene, 0, MEM_RELEASE);
}

// --- Lua & Command Handling ---
void ExecuteLua(const char* code) {
    if (FrameScript_ExecuteBuffer && code && strlen(code) > 0) {
        FrameScript_ExecuteBuffer(code, "JulesAgent", 0);
    }
}

void __cdecl SlashCmdHandler(const char* command, const char* args) {
    if (g_shared_data && !g_shared_data->is_busy) {
        strncpy_s(g_shared_data->lua_code, sizeof(g_shared_data->lua_code), args, _TRUNCATE);
    }
}

void RegisterSlashCommand() {
    if (FrameScript_Register) {
        FrameScript_Register("jules", SlashCmdHandler);
    }
}

// --- DLL Entry Point ---
void StartInjection() {
    g_hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, JULES_SHARED_MEM_NAME);
    if (g_hMapFile == NULL) return;

    g_shared_data = (SharedData*)MapViewOfFile(g_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedData));
    if (g_shared_data == NULL) {
        CloseHandle(g_hMapFile);
        return;
    }

    // Copy addresses from init struct
    FrameScript_ExecuteBuffer = (FrameScript_ExecuteBuffer_t)g_shared_data->init.frameScriptExecuteBufferAddr;
    FrameScript_Register = (FrameScript_Register_t)g_shared_data->init.frameScriptRegisterAddr;
    endSceneAddr_ = g_shared_data->init.endSceneAddr;

    if (FrameScript_ExecuteBuffer && endSceneAddr_) {
        InstallHook();
        RegisterSlashCommand();
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartInjection, NULL, 0, NULL);
    } else if (reason == DLL_PROCESS_DETACH) {
        RemoveHook();
        if (g_shared_data) UnmapViewOfFile(g_shared_data);
        if (g_hMapFile) CloseHandle(g_hMapFile);
    }
    return TRUE;
}
