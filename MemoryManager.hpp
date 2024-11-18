#ifndef MEMORY_MANAGER_HPP
#define MEMORY_MANAGER_HPP

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <stdexcept>
#include <iostream>
#include <optional>
#include <vector>

class MemoryManager {
private:
    HANDLE hProcess;
    DWORD processId;

public:
    MemoryManager(const std::wstring& processName) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to create snapshot of processes");
        }

        DWORD pid = 0;
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (processName == pe32.szExeFile) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);

        if (!pid) {
            throw std::runtime_error("Process not found");
        }

        processId = pid;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) {
            throw std::runtime_error("Failed to open process");
        }
    }

    ~MemoryManager() {
        if (hProcess) {
            CloseHandle(hProcess);
        }
    }

    uintptr_t getModuleBaseAddress(const std::wstring& moduleName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to create snapshot of modules");
        }

        MODULEENTRY32W me;
        me.dwSize = sizeof(MODULEENTRY32W);

        uintptr_t baseAddress = 0;

        if (Module32FirstW(hSnapshot, &me)) {
            do {
                if (moduleName == me.szModule) {
                    baseAddress = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    break;
                }
            } while (Module32NextW(hSnapshot, &me));
        }

        CloseHandle(hSnapshot);

        if (!baseAddress) {
            throw std::runtime_error("Module not found");
        }

        return baseAddress;
    }

    template <typename T>
    T readMemory(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets) {
        uintptr_t currentAddress = baseAddress;
        for (size_t i = 0; i < offsets.size(); ++i) {
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(currentAddress), &currentAddress, sizeof(currentAddress), nullptr)) {
                throw std::runtime_error("Memory read error at offset level " + std::to_string(i));
            }
            currentAddress += offsets[i];
        }

        T buffer{};
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(currentAddress), &buffer, sizeof(T), nullptr)) {
            throw std::runtime_error("Error reading final value");
        }
        return buffer;
    }

    std::wstring readMemoryUnicode(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets, size_t maxLength) {
        uintptr_t currentAddress = baseAddress;
        for (size_t i = 0; i < offsets.size(); ++i) {
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(currentAddress), &currentAddress, sizeof(currentAddress), nullptr)) {
                throw std::runtime_error("Memory read error at offset level " + std::to_string(i));
            }
            currentAddress += offsets[i];
        }

        std::vector<wchar_t> buffer(maxLength, L'\0');

        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(currentAddress), buffer.data(), maxLength * sizeof(wchar_t), nullptr)) {
            throw std::runtime_error("Error reading Unicode string");
        }

        return std::wstring(buffer.data());
    }

    template <typename T>
    void writeMemory(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets, const T& value) {
        uintptr_t currentAddress = baseAddress;
        for (size_t i = 0; i < offsets.size(); ++i) {
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(currentAddress), &currentAddress, sizeof(currentAddress), nullptr)) {
                throw std::runtime_error("Memory read error at offset level " + std::to_string(i));
            }
            currentAddress += offsets[i];
        }

        if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(currentAddress), &value, sizeof(T), nullptr)) {
            throw std::runtime_error("Error writing value");
        }
    }

    void call(uintptr_t baseAddress, uintptr_t functionOffset, const std::vector<uintptr_t>& args) {
        
        uintptr_t functionAddress = baseAddress + functionOffset;
        size_t argsSize = args.size() * sizeof(uintptr_t);
        void* remoteArgs = VirtualAllocEx(hProcess, nullptr, argsSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteArgs) {
            throw std::runtime_error("Failed to allocate memory in the target process");
        }

        if (!WriteProcessMemory(hProcess, remoteArgs, args.data(), argsSize, nullptr)) {
            VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
            throw std::runtime_error("Failed to write arguments to the target process");
        }

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(functionAddress), remoteArgs, 0, nullptr);

        if (!hThread) {
            VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
            throw std::runtime_error("Failed to create remote thread");
        }

        WaitForSingleObject(hThread, INFINITE);

        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
    }

};
#endif // !MEMORY_MANAGER_HPP
