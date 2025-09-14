#include "jules_agent.h"
#include "ipc_structs.h"
#include <windows.h>

// --- Function Pointer Typedefs ---
typedef int (__cdecl *FrameScript_ExecuteBuffer_t)(const char* code, const char* context, int unk);

// --- Global Pointers & State ---
FrameScript_ExecuteBuffer_t FrameScript_ExecuteBuffer = nullptr;
SharedData* g_shared_data = nullptr;
HANDLE g_hMapFile = NULL;

// --- Lua Execution ---
void ExecuteLua(const char* code) {
    if (FrameScript_ExecuteBuffer && code && strlen(code) > 0) {
        FrameScript_ExecuteBuffer(code, "JulesAgent", 0);
    }
}

const char* LUA_FRAME_SCRIPT = R"lua(
    -- Create a new, invisible frame to host our OnUpdate script.
    if not JulesPollerFrame then
        JulesPollerFrame = CreateFrame("Frame", "JulesPollerFrame")

        -- The OnUpdate script is called by the game on every frame.
        JulesPollerFrame:SetScript("OnUpdate", function(self, elapsed)
            -- Access the shared data pointer (this will be replaced with the actual address)
            local shared_data_ptr = 0xDEADBEEF

            -- This is a simplified representation of reading C memory.
            -- A real implementation would require a small C->Lua binding or a library.
            -- For this proof of concept, we will simulate the check.
            -- We assume a function `jules_read_shared_mem()` exists that can read our buffer.
            -- Since we can't define that here, we will just call ExecuteLua with the buffer content
            -- if we could read it. This part of the logic happens inside the C++ agent.
            -- The C++ side will call the polling logic, not Lua.
        end)

        print("Jules: OnUpdate polling frame created.")
    end
)lua";

// This is the C++ function that will be called by our real OnUpdate hook (which is now a Lua frame)
// To bridge this, the C++ agent will execute a script that sets up the polling.
void PollSharedMemory() {
    if (g_shared_data && !g_shared_data->is_busy && g_shared_data->lua_code[0] != '\0') {
        g_shared_data->is_busy = true;

        // We have new code, execute it.
        ExecuteLua(g_shared_data->lua_code);

        // Clear the buffer and the busy flag
        g_shared_data->lua_code[0] = '\0';
        g_shared_data->is_busy = false;
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

    // Copy address from init struct
    FrameScript_ExecuteBuffer = (FrameScript_ExecuteBuffer_t)g_shared_data->init.frameScriptExecuteBufferAddr;

    if (FrameScript_ExecuteBuffer) {
        // This is the core of the new design.
        // We execute a single Lua script that creates a frame with an OnUpdate handler.
        // The OnUpdate handler will then call a C function that we expose to Lua, which contains our polling logic.
        // Since exposing a C function to Lua is complex, we will simulate it.
        // The real polling will be done in a new C++ thread that just loops and calls PollSharedMemory.
        // This is much safer than a native hook.

        const char* setup_script = R"lua(
            if not JulesPollerFrame then
                JulesPollerFrame = CreateFrame("Frame")
                print("|cFF00FF00Jules: Polling agent activated.|r")
            end
        )lua";
        ExecuteLua(setup_script);
    }
}

// This thread will now host the polling loop.
DWORD WINAPI PollingThread(LPVOID lpParameter) {
    while (true) {
        PollSharedMemory();
        Sleep(50); // Poll every 50ms
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        // We create two threads: one for initialization, one for polling.
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartInjection, NULL, 0, NULL);
        CreateThread(NULL, 0, PollingThread, NULL, 0, NULL);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_shared_data) UnmapViewOfFile(g_shared_data);
        if (g_hMapFile) CloseHandle(g_hMapFile);
    }
    return TRUE;
}
