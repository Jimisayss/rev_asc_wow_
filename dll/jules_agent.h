#pragma once
#include <windows.h>

// Main function to be called from the injector
void StartInjection();

// Hooking
void InstallHook();
void RemoveHook();

// Shared Memory
void CheckSharedMemory();

// Lua Execution
void ExecuteLua(const char* code);
