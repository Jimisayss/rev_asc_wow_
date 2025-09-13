#include <windows.h>
#include <string>

// Define the function signature for FrameScript_ExecuteBuffer
// It's likely: void Func(const char* code, const char* context, int unknown)
// We only need the first argument.
typedef void(__cdecl *FrameScript_ExecuteBuffer_t)(const char*, const char*, int);

// The offset from the base address of Ascension.exe
constexpr uintptr_t FRAME_SCRIPT_EXECUTE_OFFSET = 0x6D70;

// Lua script to register the /jules slash command
const char* JULES_COMMAND_LUA = R"lua(
if not Jules then
    Jules = {}
    Jules.initialized = true
    SlashCmdList["JULES"] = function(msg)
        if msg and msg ~= "" then
            DEFAULT_CHAT_FRAME:AddMessage("|cff00ff00Jules executing: |cffffffff" .. msg)
            -- Use pcall to catch errors
            local success, err = pcall(function()
                local func = loadstring(msg)
                if func then
                    func()
                else
                    error("Invalid Lua code.")
                end
            end)
            if not success then
                DEFAULT_CHAT_FRAME:AddMessage("|cffff0000Jules execution error: |cffffffff" .. tostring(err))
            end
        else
            DEFAULT_CHAT_FRAME:AddMessage("|cff00ff00Jules: |cffffffffUsage: /jules <lua_code>")
        end
    end
    SLASH_JULES1 = "/jules"
    DEFAULT_CHAT_FRAME:AddMessage("|cff00ff00Jules command shell initialized. Type /jules <lua_code> to execute.")
end
)lua";

// Function to execute Lua code
void ExecuteLua(const char* code) {
    // Get the base address of the current process (Ascension.exe)
    uintptr_t baseAddress = (uintptr_t)GetModuleHandle(NULL);
    if (baseAddress == 0) {
        return; // Cannot get module handle
    }

    // Calculate the absolute address of the function
    auto func = (FrameScript_ExecuteBuffer_t)(baseAddress + FRAME_SCRIPT_EXECUTE_OFFSET);

    // Call the function
    func(code, "JulesPipe", 0);
}

// The main function for our pipe server thread
DWORD WINAPI PipeServerThread(LPVOID lpvParam) {
    // First, register the slash command
    ExecuteLua(JULES_COMMAND_LUA);

    char buffer[1024];
    DWORD dwRead;
    HANDLE hPipe;

    while (true) {
        hPipe = CreateNamedPipe(
            "\\\\.\\pipe\\JulesPipe",
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            1024 * 16,
            1024 * 16,
            NMPWAIT_USE_DEFAULT_WAIT,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            // Handle error
            Sleep(1000); // Wait a bit before retrying
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
            while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) {
                buffer[dwRead] = '\0';
                ExecuteLua(buffer);
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
            // Disable thread library calls for performance
            DisableThreadLibraryCalls(hinstDLL);
            // Create a new thread for our pipe server
            HANDLE hThread = CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread); // We don't need to manage the thread, so close the handle
            }
            break;
        }
        case DLL_PROCESS_DETACH:
            // Cleanup would go here if needed, but our thread is infinite
            break;
    }
    return TRUE;
}
