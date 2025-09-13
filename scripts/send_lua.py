#!/usr/bin/env python3
"""
A Python script to send a Lua string to the injected DLL via a named pipe.

This script connects to the named pipe '\\.\pipe\JulesPipe' and sends the
command-line argument to it. The injected DLL will then execute the string.

Requires:
- The target process (Ascension.exe) must be running.
- The dllmain.dll must be injected into the process.

Usage:
    python scripts/send_lua.py 'SendChatMessage("Hello from Python!", "SAY")'
"""
import sys
import ctypes
from ctypes import wintypes

# Named pipe constant
PIPE_NAME = r'\\.\pipe\JulesPipe'

# WinAPI constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

# WinAPI functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
CreateFileW.restype = wintypes.HANDLE

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
WriteFile.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <lua_string_to_execute>")
        print(r'Example: python scripts/send_lua.py "SendChatMessage(\"Hello\", \"SAY\")"')
        return

    lua_code = sys.argv[1]
    print(f"Connecting to pipe '{PIPE_NAME}'...")

    hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0,                      # No sharing
        None,                   # Default security attributes
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None                    # No template file
    )

    if hPipe == wintypes.HANDLE(-1).value:
        print(f"Error: Could not connect to the named pipe.")
        print(f"Is the DLL injected into Ascension.exe?")
        print(f"Win32 Error Code: {ctypes.get_last_error()}")
        return

    print("Connected. Sending Lua code...")

    try:
        # Encode the Lua code to bytes
        lua_bytes = lua_code.encode('utf-8')
        bytes_to_write = len(lua_bytes)
        bytes_written = wintypes.DWORD(0)

        success = WriteFile(
            hPipe,
            ctypes.c_char_p(lua_bytes),
            bytes_to_write,
            ctypes.byref(bytes_written),
            None
        )

        if not success or bytes_written.value != bytes_to_write:
            print(f"Error: Failed to write to pipe.")
            print(f"Win32 Error Code: {ctypes.get_last_error()}")
        else:
            print(f"Successfully sent {bytes_written.value} bytes.")

    finally:
        print("Closing pipe handle.")
        CloseHandle(hPipe)

if __name__ == '__main__':
    main()
