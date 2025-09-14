#pragma once
#include <cstdint>

#define JULES_SHARED_MEM_NAME "JulesSharedMemory"
#define JULES_BUF_SIZE 2048

struct JulesInit {
    uintptr_t frameScriptExecuteBufferAddr;
    uintptr_t frameScriptRegisterAddr;
    uintptr_t endSceneAddr;
};

struct SharedData {
    JulesInit init;
    bool is_busy;
    char lua_code[JULES_BUF_SIZE - sizeof(JulesInit) - sizeof(bool)];
};
