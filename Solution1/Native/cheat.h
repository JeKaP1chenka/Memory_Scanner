#pragma once
#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <psapi.h>
#include <thread>
#include <chrono>
//#include <ctime>
#include <future>

namespace ch {

    struct ADDR_INFO {
        DWORD64 addr;
        DWORD64 offset;
        DWORD state;
        DWORD protect;
        DWORD type;
        DWORD64 regionSize;

        ADDR_INFO(DWORD64 addr, DWORD64 offset, DWORD state, DWORD protect, DWORD type, DWORD64 regionSize)  {
            this->addr = addr;
            this->offset = offset;
            this->state = state;
            this->protect = protect;
            this->type = type;
            this->regionSize = regionSize;
        }

        void print() {
            std::cout << std::hex <<
                "addr = " << addr << '\t' <<
                "offset >> " << offset << '\t' << std::dec;
            std::cout << "state = ";
            switch (state)
            {
            case MEM_COMMIT:
                std::cout << "MEM_COMMIT";
                break;
            case MEM_FREE:
                std::cout << "MEM_FREE";
                break;
            case MEM_RESERVE:
                std::cout << "MEM_RESERVE";
                break;
            default:
                std::cout << std::hex << state << std::dec;
                break;
            }
            std::cout << '\t';

            std::cout << "protect = ";
            switch (protect)
            {
            case PAGE_EXECUTE:
                std::cout << "PAGE_EXECUTE";
                break;
            case PAGE_EXECUTE_READ:
                std::cout << "PAGE_EXECUTE_READ";
                break;
            case PAGE_EXECUTE_READWRITE:
                std::cout << "PAGE_EXECUTE_READWRITE";
                break;
            case PAGE_EXECUTE_WRITECOPY:
                std::cout << "PAGE_EXECUTE_WRITECOPY";
                break;
            case PAGE_NOACCESS:
                std::cout << "PAGE_NOACCESS";
                break;
            case PAGE_READONLY:
                std::cout << "PAGE_READONLY";
                break;
            case PAGE_READWRITE:
                std::cout << "PAGE_READWRITE";
                break;
            case PAGE_WRITECOPY:
                std::cout << "PAGE_WRITECOPY";
                break;
            case PAGE_TARGETS_INVALID:
                std::cout << "PAGE_TARGETS_INVALID or PAGE_TARGETS_NO_UPDATE";
                break;

            default:
                std::cout << std::hex << protect << std::dec;
                break;
            }
            std::cout << '\t';

            std::cout << "type = ";
            switch (type)
            {
            case MEM_IMAGE:
                std::cout << "MEM_IMAGE";
                break;
            case MEM_MAPPED:
                std::cout << "MEM_MAPPED";
                break;
            case MEM_PRIVATE:
                std::cout << "MEM_PRIVATE";
                break;
            default:
                std::cout << std::hex << type << std::dec;
                break;
            }
            std::cout << '\t';

            std::cout << "regionSize = " << std::hex << regionSize << std::dec << '\n';

        }
    };

    struct SettingsForSearch {
        DWORD state;
        DWORD protect;
        DWORD type;
        DWORD64 downLimit;
        DWORD64 upLimit;
        DWORD64 downRegionSize;
        DWORD64 upRegionSize;

        SettingsForSearch(
            DWORD state = MEM_COMMIT,
            DWORD protect = PAGE_READWRITE,
            DWORD type = MEM_PRIVATE,
            DWORD64 downLimit = 0x0,
            DWORD64 upLimit = 0x7fffffffffff,
            DWORD64 downRegionSize = 0x0,
            DWORD64 upRegionSize = 0x7fffffffffff
        ) {
            this->state = state;
            this->protect = protect;
            this->type = type;
            this->downLimit = downLimit;
            this->upLimit = upLimit;
            this->downRegionSize = downRegionSize;
            this->upRegionSize = upRegionSize;
        }
    };

    extern "C" __declspec(dllexport) int getPIDFromExe(const char s[]);

    extern "C" __declspec(dllexport) int getPIDFromName(const char* name);

    extern "C" __declspec(dllexport)
    bool WriteProcMem(const int pID, const long long addr, const int buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(int), NULL);
        CloseHandle(handle);
        return r;
    }

    template<typename T>
    bool WriteProcMem(const DWORD& pID, const DWORD64& addr, const T& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(T), NULL);
        CloseHandle(handle);
        return r;
    }

    template<typename T>
    bool WriteProcMem(const HANDLE& handle, const DWORD64& addr, const T& buffer) {
        return WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(T), NULL);
    }

    template<typename T>
    bool ReadProcMem(const DWORD& pID, const DWORD64& addr, T& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPCVOID)addr, &buffer, sizeof(T), NULL);
        CloseHandle(handle);
        return r;
    }

    template<typename T>
    bool ReadProcMem(const HANDLE& handle, const DWORD64& addr, T& buffer) {
        return ReadProcessMemory(handle, (LPCVOID)addr, &buffer, sizeof(T), NULL);
    }
    // Don`t use
    template<typename T>
    void ThrFreeze(const DWORD pID, const DWORD64 addr,const T buffer,const bool& stop, int delay) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        while (stop) {
            WriteProcessMemory(handle, (LPVOID)addr, &buffer, sizeof(T), NULL);
            //std::this_thread::sleep_for(std::chrono::seconds(delay));
            Sleep(delay);
        }
        CloseHandle(handle);

    }
    
    template<typename T>
    void Freeze(const DWORD& pID, const DWORD64& addr, T& buffer,const bool& stop, int delay) {
        std::thread thr(ThrFreeze<T>, pID, addr, buffer, std::ref(stop), delay);
        thr.detach();
    }

    //inline bool CheckSignature(const PBYTE sourse, const PBYTE pattern, const std::string& mask);

    //PBYTE getPatMask(std::string AOB, std::string& mask);

    //std::vector<DWORD64> fut(const HANDLE& handle, MEMORY_BASIC_INFORMATION mbi,
    //    const PBYTE pattern, const std::string& mask, const DWORD64& startAddress, const DWORD64 offset);

    std::vector<DWORD64> AOBscanAsync(DWORD pID, std::string AOB);

    std::vector<DWORD64> AOBscanAsyncSettings(DWORD pID, std::string AOB, SettingsForSearch settings);

    std::vector<ADDR_INFO> AOBscanInfo(DWORD pID, std::string AOB);

    std::vector<MEMORY_BASIC_INFORMATION> regionScan(DWORD pID, std::string AOB);


    std::vector<DWORD64> test2(DWORD pID, std::string AOB, SettingsForSearch settings);
    std::vector<ADDR_INFO> test(DWORD pID, std::string AOB);

    void getNumRegions(DWORD pID);
}