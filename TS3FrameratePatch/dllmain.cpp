// Original author: LazyDuchess
//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// Code improvement (Multithreading, updating code and libraries, C++17 Standard, Visual Studio 2022)
// By anton557 (Stone)
// Link: https://vk.com/anton_paskevich
// Link 2: https://modthesims.info/member.php?u=10350339
// Link 3: https://thesims.cc/members/anton557.484107/
//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄

#include "pch.h"
#include <string>
#include <Psapi.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <d3d9.h>
#include "D3Dhook.h"
#include <math.h>
#include <chrono>
#include <iostream>
#include <algorithm>
#include <thread>
#include <atomic>

#pragma comment(lib, "D3D Hook x86.lib")

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              КОНСТАНТЫ И ПЕРЕМЕННЫЕ
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
char hookUncapped[] = { 0xC3 };
char hookSystem[] = { 0xB9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x6A, 0x00 };
char hookCapped[] = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x90 };
char lookup[] = { 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x6A, 0x01, 0x51, 0xFF };
char lookup2[] = { 0xC3, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x6A, 0x01, 0x51, 0xFF };

char* modBase;
std::atomic<bool> bExit{ false };
std::atomic<long long> FPSTarget{ 0 }; // Объявлено здесь
std::chrono::steady_clock::time_point lastFrameTime; // Объявлено здесь
int tps = 0;

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              ФУНКЦИИ ДЛЯ РАБОТЫ С ПАМЯТЬЮ
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
void WriteToMemory(DWORD addressToWrite, const char* valueToWrite, int byteNum) {
    DWORD oldProtect;
    VirtualProtect((LPVOID)addressToWrite, byteNum, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((LPVOID)addressToWrite, valueToWrite, byteNum);
    VirtualProtect((LPVOID)addressToWrite, byteNum, oldProtect, &oldProtect);
}

void WriteToMemory(DWORD addressToWrite, int* valueToWrite, int byteNum) {
    DWORD oldProtect;
    VirtualProtect((LPVOID)addressToWrite, byteNum, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((LPVOID)addressToWrite, valueToWrite, byteNum);
    VirtualProtect((LPVOID)addressToWrite, byteNum, oldProtect, &oldProtect);
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
        if (found) return (char*)(begin + i);
    }
    return nullptr;
}

char* ScanInternal(const char* pattern, int patternLen, const char* begin, intptr_t size) {
    char* match{ nullptr };
    MEMORY_BASIC_INFORMATION mbi{};

    for (const char* curr = begin; curr < begin + size; curr += mbi.RegionSize) {
        if (!VirtualQuery(curr, &mbi, sizeof(mbi))) continue;
        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

        match = ScanBasic(pattern, patternLen, curr, mbi.RegionSize);
        if (match) break;
    }
    return match;
}

// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              ОБЪЯВЛЕНИЯ ДЛЯ D3D ХУКОВ
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
typedef long(__stdcall* tPresent)(LPDIRECT3DDEVICE9, RECT*, RECT*, HWND, RGNDATA*);
tPresent oD3D9Present = nullptr;

long __stdcall hkD3D9Present(LPDIRECT3DDEVICE9 pDevice, RECT* pSourceRect, RECT* pDestRect, HWND hDestWindowOverride, RGNDATA* pDirtyRegion) {
    if (FPSTarget > 0) {
        auto now = std::chrono::steady_clock::now();
        auto frameTime = std::chrono::duration_cast<std::chrono::nanoseconds>(now - lastFrameTime).count();

        if (frameTime < FPSTarget) {
            auto targetTime = lastFrameTime + std::chrono::nanoseconds(FPSTarget);
            while (std::chrono::steady_clock::now() < targetTime) {
                std::this_thread::yield();
            }
        }
        lastFrameTime = now;
    }
    return oD3D9Present(pDevice, pSourceRect, pDestRect, hDestWindowOverride, pDirtyRegion);
}

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              МНОГОПОТОЧНЫЕ СИСТЕМЫ
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
void MemoryScanThread() {
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), (HMODULE)modBase, &modInfo, sizeof(MODULEINFO));

    DWORD addr = 0;
    while (!bExit && !addr) {
        addr = (DWORD)ScanInternal(lookup, sizeof(lookup), modBase, modInfo.SizeOfImage);
        if (!addr) addr = (DWORD)ScanInternal(lookup2, sizeof(lookup2), modBase, modInfo.SizeOfImage);

        if (addr) {
            int tickrate = 0;
            if (tps > 0) {
                tickrate = 1000 / tps;
            }
            else if (tps < 0) {
                tickrate = (tps == -2) ? -2 : -1;
            }

            if (tickrate == -1) {
                WriteToMemory(addr, hookUncapped, sizeof(hookUncapped));
            }
            else if (tickrate == 0) {
                WriteToMemory(addr, hookSystem, sizeof(hookSystem));
            }
            else if (tickrate != -2) {
                WriteToMemory(addr, hookCapped, sizeof(hookCapped));
                WriteToMemory(addr + 1, &tickrate, 4);
            }
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

//▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
//                              ОСНОВНОЙ КОД
//▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
DWORD WINAPI MainThread(LPVOID param) {
    // Проверка, что процесс — TS3.exe
    wchar_t modName[MAX_PATH];
    GetModuleFileNameW(NULL, modName, MAX_PATH);
    std::wstring exePath(modName);
    std::transform(exePath.begin(), exePath.end(), exePath.begin(), towlower);

    if (exePath.find(L"ts3") == std::wstring::npos) {
        FreeLibraryAndExitThread((HMODULE)param, 0);
        return 0;
    }

    // Загрузка конфигурации
    std::wstring configPath = exePath.substr(0, exePath.find_last_of(L"\\/")) + L"\\TS3Patch.txt";

    bool debug = false;
    int delay = 0;
    bool borderless = false;

    std::wifstream file(configPath);
    if (file.is_open()) {
        std::wstring line;
        while (std::getline(file, line)) {
            line.erase(std::remove(line.begin(), line.end(), L' '), line.end());
            if (line.empty() || line[0] == L'#') continue;

            size_t delim = line.find(L'=');
            if (delim != std::wstring::npos) {
                std::wstring key = line.substr(0, delim);
                std::wstring valueStr = line.substr(delim + 1);
                int value = std::stoi(valueStr);

                if (key == L"TPS") tps = value;
                else if (key == L"Debug") debug = (value > 0);
                else if (key == L"Delay") delay = value;
                else if (key == L"FPSLimit") FPSTarget = (value > 0) ? (1'000'000'000LL / value) : 0;
                else if (key == L"Borderless") borderless = (value == 1);
            }
        }
        file.close();
    }

    if (debug) {
        MessageBoxW(NULL, L"Debug mode: Patching Game!", L"TS3Patch", MB_OK | MB_ICONINFORMATION);
    }

    if (delay > 0) Sleep(delay);

    // Инициализация
    modBase = (char*)GetModuleHandleA(NULL);

    // Инициализация D3D хуков
    if (FPSTarget > 0) {
        if (init_D3D()) {
            methodesHook(17, hkD3D9Present, (LPVOID*)&oD3D9Present);
            lastFrameTime = std::chrono::steady_clock::now();
        }
    }

    std::thread memoryThread(MemoryScanThread);

    // Borderless режим
    if (borderless) {
        HWND hWnd = nullptr;
        while (!hWnd && !bExit) {
            EnumWindows([](HWND hwnd, LPARAM pid) -> BOOL {
                DWORD windowPid;
                GetWindowThreadProcessId(hwnd, &windowPid);
                if (windowPid == (DWORD)pid && IsWindowVisible(hwnd)) {
                    *(HWND*)&pid = hwnd;
                    return FALSE;
                }
                return TRUE;
                }, (LPARAM)GetCurrentProcessId());
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (hWnd) {
            LONG_PTR style = GetWindowLongPtrW(hWnd, GWL_STYLE);
            style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU);
            SetWindowLongPtrW(hWnd, GWL_STYLE, style);
            SetWindowPos(hWnd, HWND_TOP, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), SWP_FRAMECHANGED);
        }
    }

    // Основной цикл
    while (!bExit) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Очистка
    memoryThread.join();
    FreeLibraryAndExitThread((HMODULE)param, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}