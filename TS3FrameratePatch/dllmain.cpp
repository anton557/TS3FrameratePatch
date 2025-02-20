// Original author: LazyDuchess
//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// Code improvement (Multithreading, updating code and libraries, C++17 Standard, Visual Studio 2022)
// By anton557 (Stone)
// Link: https://vk.com/anton_paskevich
// Link 2: https://modthesims.info/member.php?u=10350339
// Link 3: https://thesims.cc/members/anton557.484107/
//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄

#include "pch.h"  // Precompiled header file for faster compilation
#include <string>  // Standard string library
#include <Psapi.h>  // Windows API for process and memory management
#include <fstream>  // File stream operations
#include <vector>  // Dynamic array container
#include <sstream>  // String stream operations
#include <d3d9.h>  // Direct3D 9 library
#include "D3Dhook.h"  // Custom header for Direct3D hooking
#include <math.h>  // Mathematical functions
#include <chrono>  // Time utilities
#include <iostream>  // Standard input/output stream
#include <algorithm>  // Algorithms like sorting, searching, etc.
#include <thread>  // Multithreading support
#include <atomic>  // Atomic operations for thread-safe variables

#pragma comment(lib, "D3D Hook x86.lib")  // Linker directive to include the D3D Hook library

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              CONSTANTS AND VARIABLES
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
char hookUncapped[] = { 0xC3 };
char hookSystem[] = { 0xB9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x6A, 0x00 };
char hookCapped[] = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x90 };
char lookup[] = { 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x6A, 0x01, 0x51, 0xFF };
char lookup2[] = { 0xC3, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x6A, 0x01, 0x51, 0xFF };

char* modBase;  // Base address of the module
std::atomic<bool> bExit{ false };  // Atomic flag to signal thread exit
std::atomic<long long> FPSTarget{ 0 };  // Target FPS in nanoseconds
std::chrono::steady_clock::time_point lastFrameTime;  // Time point of the last frame
int tps = 0;  // Ticks per second

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              MEMORY MANIPULATION FUNCTIONS
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
void WriteToMemory(DWORD addressToWrite, const char* valueToWrite, int byteNum) {
    DWORD oldProtect;  // Variable to store old memory protection
    VirtualProtect((LPVOID)addressToWrite, byteNum, PAGE_EXECUTE_READWRITE, &oldProtect);  // Change memory protection
    memcpy((LPVOID)addressToWrite, valueToWrite, byteNum);  // Copy data to memory
    VirtualProtect((LPVOID)addressToWrite, byteNum, oldProtect, &oldProtect);  // Restore memory protection
}

void WriteToMemory(DWORD addressToWrite, int* valueToWrite, int byteNum) {
    DWORD oldProtect;  // Variable to store old memory protection
    VirtualProtect((LPVOID)addressToWrite, byteNum, PAGE_EXECUTE_READWRITE, &oldProtect);  // Change memory protection
    memcpy((LPVOID)addressToWrite, valueToWrite, byteNum);  // Copy data to memory
    VirtualProtect((LPVOID)addressToWrite, byteNum, oldProtect, &oldProtect);  // Restore memory protection
}

char* ScanBasic(const char* pattern, int patternLen, const char* begin, intptr_t size) {
    for (int i = 0; i < size; i++) {
        bool found = true;
        for (int j = 0; j < patternLen; j++) {
            if (pattern[j] != *(char*)((intptr_t)begin + i + j)) {
                found = false;
                break;
            }
        }
        if (found) return (char*)(begin + i);  // Return the address if pattern is found
    }
    return nullptr;  // Return null if pattern is not found
}

char* ScanInternal(const char* pattern, int patternLen, const char* begin, intptr_t size) {
    char* match{ nullptr };  // Variable to store the match address
    MEMORY_BASIC_INFORMATION mbi{};  // Structure to store memory information

    for (const char* curr = begin; curr < begin + size; curr += mbi.RegionSize) {
        if (!VirtualQuery(curr, &mbi, sizeof(mbi))) continue;  // Query memory region information
        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;  // Skip non-committed or no-access regions

        match = ScanBasic(pattern, patternLen, curr, mbi.RegionSize);  // Scan the region for the pattern
        if (match) break;  // Break if pattern is found
    }
    return match;  // Return the match address
}

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              D3D HOOK DECLARATIONS
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
typedef long(__stdcall* tPresent)(LPDIRECT3DDEVICE9, RECT*, RECT*, HWND, RGNDATA*);  // Function pointer type for D3D9 Present
tPresent oD3D9Present = nullptr;  // Original D3D9 Present function

long __stdcall hkD3D9Present(LPDIRECT3DDEVICE9 pDevice, RECT* pSourceRect, RECT* pDestRect, HWND hDestWindowOverride, RGNDATA* pDirtyRegion) {
    if (FPSTarget > 0) {
        auto now = std::chrono::steady_clock::now();  // Get current time
        auto frameTime = std::chrono::duration_cast<std::chrono::nanoseconds>(now - lastFrameTime).count();  // Calculate frame time

        // Account for double buffering (divide by 2)
        if (frameTime < FPSTarget * 2) {
            auto targetTime = lastFrameTime + std::chrono::nanoseconds(FPSTarget * 2);  // Calculate target time
            while (std::chrono::steady_clock::now() < targetTime) {
                std::this_thread::yield();  // Yield the thread to wait for the target time
            }
        }
        lastFrameTime = now;  // Update last frame time
    }
    return oD3D9Present(pDevice, pSourceRect, pDestRect, hDestWindowOverride, pDirtyRegion);  // Call original Present function
}

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              BORDERLESS MODE
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
HWND g_HWND = NULL;  // Global variable to store the window handle

BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam) {
    DWORD lpdwProcessId;  // Variable to store process ID
    GetWindowThreadProcessId(hwnd, &lpdwProcessId);  // Get process ID of the window
    if (IsWindowVisible(hwnd) && lpdwProcessId == lParam) {
        g_HWND = hwnd;  // Store the window handle if it matches the process ID
        return FALSE;  // Stop enumeration
    }
    return TRUE;  // Continue enumeration
}

void MakeBorderless() {
    while (g_HWND == NULL && !bExit) {
        EnumWindows(EnumWindowsProcMy, GetCurrentProcessId());  // Find the window handle
        Sleep(100);  // Wait for 100ms
    }

    if (g_HWND) {
        // Remove standard window styles
        LONG lStyle = GetWindowLong(g_HWND, GWL_STYLE);
        lStyle &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZE | WS_MAXIMIZE | WS_SYSMENU);
        SetWindowLong(g_HWND, GWL_STYLE, lStyle);

        // Remove extended window styles
        LONG lExStyle = GetWindowLong(g_HWND, GWL_EXSTYLE);
        lExStyle &= ~(WS_EX_DLGMODALFRAME | WS_EX_CLIENTEDGE | WS_EX_STATICEDGE);
        SetWindowLong(g_HWND, GWL_EXSTYLE, lExStyle);

        // Set the window to full screen
        SetWindowPos(g_HWND, HWND_TOP, 0, 0,
            GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYSCREEN),
            SWP_FRAMECHANGED | SWP_SHOWWINDOW
        );
    }
}

DWORD WINAPI BorderlessThread(LPVOID param) {
    while (!bExit) {
        MakeBorderless();  // Make the window borderless
        Sleep(500);  // Update every 500ms
    }
    return 0;
}

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              MULTITHREADING SYSTEMS
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

void MemoryScanThread() {
    MODULEINFO modInfo;  // Structure to store module information
    GetModuleInformation(GetCurrentProcess(), (HMODULE)modBase, &modInfo, sizeof(MODULEINFO));  // Get module information

    DWORD addr = 0;  // Variable to store the address of the pattern
    while (!bExit && !addr) {
        addr = (DWORD)ScanInternal(lookup, sizeof(lookup), modBase, modInfo.SizeOfImage);  // Scan for the first pattern
        if (!addr) addr = (DWORD)ScanInternal(lookup2, sizeof(lookup2), modBase, modInfo.SizeOfImage);  // Scan for the second pattern

        if (addr) {
            int tickrate = 0;  // Variable to store the tick rate
            if (tps > 0) {
                tickrate = 1000 / tps;  // Calculate tick rate if TPS is positive
            }
            else if (tps < 0) {
                tickrate = (tps == -2) ? -2 : -1;  // Set tick rate based on TPS value
            }

            if (tickrate == -1) {
                WriteToMemory(addr, hookUncapped, sizeof(hookUncapped));  // Write uncapped frame rate hook
            }
            else if (tickrate == 0) {
                WriteToMemory(addr, hookSystem, sizeof(hookSystem));  // Write system frame rate hook
            }
            else if (tickrate != -2) {
                WriteToMemory(addr, hookCapped, sizeof(hookCapped));  // Write capped frame rate hook
                WriteToMemory(addr + 1, &tickrate, 4);  // Write tick rate value
            }
            break;  // Exit the loop if the pattern is found and processed
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));  // Wait for 500ms before retrying
    }
}

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              MAIN CODE
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
DWORD WINAPI MainThread(LPVOID param) {
    // Check if the process is TS3.exe
    wchar_t modName[MAX_PATH];  // Buffer to store module name
    GetModuleFileNameW(NULL, modName, MAX_PATH);  // Get the executable file name
    std::wstring exePath(modName);  // Convert to wide string
    std::transform(exePath.begin(), exePath.end(), exePath.begin(), towlower);  // Convert to lowercase

    if (exePath.find(L"ts3") == std::wstring::npos) {
        FreeLibraryAndExitThread((HMODULE)param, 0);  // Exit if not TS3.exe
        return 0;
    }

    // Load configuration
    std::wstring configPath = exePath.substr(0, exePath.find_last_of(L"\\/")) + L"\\TS3Patch.txt";  // Path to the configuration file

    bool debug = false;  // Debug mode flag
    int delay = 0;  // Delay before applying patches
    bool borderless = false;  // Borderless mode flag

    std::wifstream file(configPath);  // Open the configuration file
    if (file.is_open()) {
        std::wstring line;  // Variable to store each line
        while (std::getline(file, line)) {
            line.erase(std::remove(line.begin(), line.end(), L' '), line.end());  // Remove spaces
            if (line.empty() || line[0] == L'#') continue;  // Skip empty lines and comments

            size_t delim = line.find(L'=');  // Find the delimiter
            if (delim != std::wstring::npos) {
                std::wstring key = line.substr(0, delim);  // Extract the key
                std::wstring valueStr = line.substr(delim + 1);  // Extract the value
                int value = std::stoi(valueStr);  // Convert value to integer

                if (key == L"TPS") tps = value;  // Set TPS
                else if (key == L"Debug") debug = (value > 0);  // Set debug mode
                else if (key == L"Delay") delay = value;  // Set delay
                else if (key == L"FPSLimit") FPSTarget = (value > 0) ? (1'000'000'000LL / value) : 0;  // Set FPS limit
                else if (key == L"Borderless") borderless = (value == 1);  // Set borderless mode
            }
        }
        file.close();  // Close the configuration file
    }

    if (debug) {
        MessageBoxW(NULL, L"Debug mode: Patching Game!", L"TS3Patch", MB_OK | MB_ICONINFORMATION);  // Show debug message
    }

    if (delay > 0) Sleep(delay);  // Apply delay if specified

    // Initialization
    modBase = (char*)GetModuleHandleA(NULL);  // Get the base address of the module

    // Initialize D3D hooks
    if (FPSTarget > 0) {
        if (init_D3D()) {
            methodesHook(17, hkD3D9Present, (LPVOID*)&oD3D9Present);  // Hook the D3D9 Present function
            lastFrameTime = std::chrono::steady_clock::now();  // Initialize last frame time
        }
    }

    std::thread memoryThread(MemoryScanThread);  // Start the memory scanning thread

    // Borderless mode
    if (borderless) {
        CreateThread(0, 0, BorderlessThread, param, 0, 0);  // Start the borderless thread
    }

    // Main loop
    while (!bExit) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Sleep for 100ms
    }

    // Cleanup
    memoryThread.join();  // Wait for the memory thread to finish
    FreeLibraryAndExitThread((HMODULE)param, 0);  // Free the library and exit the thread
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);  // Start the main thread
    }
    return TRUE;  // Return TRUE for successful DLL initialization
}