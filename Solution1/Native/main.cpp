#include <iostream>

#pragma once
#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <psapi.h>
#include <thread>
#include <chrono>
#include <future>

#define DLLE extern "C" __declspec(dllexport)

namespace ch {

    typedef long long ADDRESS;

    enum State : DWORD
    {
        _MEM_COMMIT = 0x00001000,
        _MEM_RESERVE = 0x00002000,
        _MEM_REPLACE_PLACEHOLDER = 0x00004000,
        _MEM_RESERVE_PLACEHOLDER = 0x00040000,
        _MEM_RESET = 0x00080000,
        _MEM_TOP_DOWN = 0x00100000,
        _MEM_WRITE_WATCH = 0x00200000,
        _MEM_PHYSICAL = 0x00400000,
        _MEM_ROTATE = 0x00800000,
        _MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000,
        _MEM_RESET_UNDO = 0x01000000,
        _MEM_LARGE_PAGES = 0x20000000,
        _MEM_4MB_PAGES = 0x80000000,
        _MEM_64K_PAGES = (_MEM_LARGE_PAGES | _MEM_PHYSICAL),
        _MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001,
        _MEM_COALESCE_PLACEHOLDERS = 0x00000001,
        _MEM_PRESERVE_PLACEHOLDER = 0x00000002,
        _MEM_DECOMMIT = 0x00004000,
        _MEM_RELEASE = 0x00008000,
        _MEM_FREE = 0x00010000,
    };
    enum Protect : DWORD
    {
        _PAGE_NOACCESS = 0x01,
        _PAGE_READONLY = 0x02,
        _PAGE_READWRITE = 0x04,
        _PAGE_WRITECOPY = 0x08,
        _PAGE_EXECUTE = 0x10,
        _PAGE_EXECUTE_READ = 0x20,
        _PAGE_EXECUTE_READWRITE = 0x40,
        _PAGE_EXECUTE_WRITECOPY = 0x80,
        _PAGE_GUARD = 0x100,
        _PAGE_NOCACHE = 0x200,
        _PAGE_WRITECOMBINE = 0x400,
        _PAGE_GRAPHICS_NOACCESS = 0x0800,
        _PAGE_GRAPHICS_READONLY = 0x1000,
        _PAGE_GRAPHICS_READWRITE = 0x2000,
        _PAGE_GRAPHICS_EXECUTE = 0x4000,
        _PAGE_GRAPHICS_EXECUTE_READ = 0x8000,
        _PAGE_GRAPHICS_EXECUTE_READWRITE = 0x10000,
        _PAGE_GRAPHICS_COHERENT = 0x20000,
        _PAGE_GRAPHICS_NOCACHE = 0x40000,
        _PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
        _PAGE_REVERT_TO_FILE_MAP = 0x80000000,
        _PAGE_TARGETS_NO_UPDATE = 0x40000000,
        _PAGE_TARGETS_INVALID = 0x40000000,
        _PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
        _PAGE_ENCLAVE_MASK = 0x10000000,
        _PAGE_ENCLAVE_DECOMMIT = (_PAGE_ENCLAVE_MASK | 0),
        _PAGE_ENCLAVE_SS_FIRST = (_PAGE_ENCLAVE_MASK | 1),
        _PAGE_ENCLAVE_SS_REST = (_PAGE_ENCLAVE_MASK | 2),
    };
    enum Type : DWORD
    {
        _MEM_PRIVATE = 0x00020000,
        _MEM_MAPPED = 0x00040000,
        _MEM_IMAGE = 0x01000000,
    };

    struct ADDR_INFO {
        DWORD64 addr;
        DWORD64 offset;
        DWORD state;
        DWORD protect;
        DWORD type;
        DWORD64 regionSize;

        ADDR_INFO(DWORD64 addr, DWORD64 offset, DWORD state, DWORD protect, DWORD type, DWORD64 regionSize) {
            this->addr = addr;
            this->offset = offset;
            this->state = state;
            this->protect = protect;
            this->type = type;
            this->regionSize = regionSize;
        }
        ADDR_INFO() {
            this->addr = NULL;
            this->offset = NULL;
            this->state = NULL;
            this->protect = NULL;
            this->type = NULL;
            this->regionSize = NULL;
        }
        ADDR_INFO(const ADDR_INFO& other) {
            this->addr = other.addr;
            this->offset = other.offset;
            this->state = other.state;
            this->protect = other.protect;
            this->type = other.type;
            this->regionSize = other.regionSize;
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
    
    DLLE SettingsForSearch CreateSett(
            DWORD state = MEM_COMMIT,
            DWORD protect = PAGE_READWRITE,
            DWORD type = MEM_PRIVATE,
            DWORD64 downLimit = 0x0,
            DWORD64 upLimit = 0x7fffffffffff,
            DWORD64 downRegionSize = 0x0,
            DWORD64 upRegionSize = 0x7fffffffffff
        ) {
        SettingsForSearch r(state, protect, type, downLimit, upLimit, downRegionSize, upRegionSize);
        return r;
    }

    //struct Processes {
    //    WCHAR name[MAX_PATH];
    //    DWORD pID;
    //    Processes(WCHAR name[MAX_PATH], DWORD pID) {
    //        for (int i = 0; i < MAX_PATH; i++) {
    //            this->name[i] = name[i];
    //        }
    //        this->pID = pID;
    //    }
    //    Processes(const Processes& other) {
    //        for (int i = 0; i < MAX_PATH; i++) {
    //            this->name[i] = other.name[i];
    //        }
    //        this->pID = other.pID;
    //    }
    //    Processes() {
    //    }

    //};

    //bool PrintModuleList(const HANDLE hStdOut, const DWORD dwProcessId) {
    //    MODULEENTRY32 meModuleEntry;
    //    TCHAR szBuff[1024];
    //    DWORD dwTemp;
    //    HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
    //        TH32CS_SNAPMODULE, dwProcessId);
    //    if (INVALID_HANDLE_VALUE == hSnapshot) {
    //        return false;
    //    }

    //    meModuleEntry.dwSize = sizeof(MODULEENTRY32);
    //    Module32First(hSnapshot, &meModuleEntry);
    //    do {
    //        wsprintf(szBuff, L"  ba: %08X, bs: %08X, %s\r\n",
    //            meModuleEntry.modBaseAddr, meModuleEntry.modBaseSize,
    //            meModuleEntry.szModule);
    //        WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
    //    } while (Module32Next(hSnapshot, &meModuleEntry));

    //    CloseHandle(hSnapshot);
    //    return true;
    //}

    DLLE bool getProcessList(int& size, WCHAR**& outNames, DWORD*& outPIDs) {
        PROCESSENTRY32 peProc32;
        //DWORD dwTemp;
        HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hSnapshot) {
            return false;
        }
        peProc32.dwSize = sizeof(PROCESSENTRY32);
        Process32First(hSnapshot, &peProc32);
        std::vector<WCHAR*> names;
        std::vector<DWORD> pIDs;
        do {
            WCHAR* t = new WCHAR[260];
            for (int i = 0; i < 260; i++) {
                t[i] = peProc32.szExeFile[i];
            }
            names.push_back(t);
            pIDs.push_back(peProc32.th32ProcessID);
        } while (Process32Next(hSnapshot, &peProc32));

        if (names.size() != pIDs.size()) {
            for (int i = 0; i < names.size(); i++) {
                delete[] names[i];
            }
            return false;
        }

        size = names.size();

        outNames = new WCHAR * [size];
        for (int i = 0; i < size; i++) {
            outNames[i] = names[i];
        }

        outPIDs = new DWORD[size];
        for (int i = 0; i < size; i++) {
            outPIDs[i] = pIDs[i];
        }

        CloseHandle(hSnapshot);
        return true;
    }
    
    DLLE DWORD getPIDFromExe(const char s[]) {
        DWORD pID = 0;
        PROCESSENTRY32 peProcessEntry;
        HANDLE const hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hSnapshot) {
            std::cout << "ERROR: func->getPID_fromExe; the handler was not created" << '\n';
            return 0;
        }
        peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
        Process32First(hSnapshot, &peProcessEntry);

        auto is1 = [](const char exe[], const char name[]) -> bool {
            if (strlen(exe) == strlen(name)) {
                for (int i = 0; i < strlen(name); i++)
                    if (exe[i] != name[i])
                        return false;
                return true;
            }
            return false;
        };

        do {
            auto g = peProcessEntry.szExeFile;
            int size = wcslen(g);
            char* t = new char(size + 1);
            for (int i = 0; i < size; i++)
                t[i] = (char)g[i];
            t[size] = '\0';
            if (is1(t, s))
                pID = peProcessEntry.th32ProcessID;
            delete[] t;
        } while (Process32Next(hSnapshot, &peProcessEntry) and pID == 0);

        if (pID == 0)
            std::cout << "ERROR: func->getPID_fromExe; process not found" << '\n';

        CloseHandle(hSnapshot);
        return pID;
    }

    extern "C" __declspec(dllexport)  DWORD getPIDFromName(const char name[]) {
        DWORD pID = 0;
        HWND hwnd = FindWindowA(NULL, (LPSTR)name);
        if (hwnd == NULL) {
            std::cout << "ERROR: func->getPID_fromName; HWND not found" << '\n';
            return 0;
        }
        GetWindowThreadProcessId(hwnd, (LPDWORD)&pID);
        if (pID == 0)
            std::cout << "ERROR: func->getPID_fromName; process not found" << '\n';
        return pID;
    }

    // write
    // unsigned
    DLLE bool WriteProcMemBYTE(DWORD pID, const long long addr, const BYTE buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(BYTE), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool WriteProcMemWORD(DWORD pID, const long long addr, const WORD buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(WORD), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool WriteProcMemDWORD(DWORD pID, const long long addr, const DWORD32 buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(DWORD32), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool WriteProcMemQWORD(DWORD pID, const long long addr, const DWORD64 buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(DWORD64), NULL);
        CloseHandle(handle);
        return r;
    }
    // signed
    DLLE bool WriteProcMemChar(DWORD pID, const long long addr, const signed char buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed char), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool WriteProcMemShort(DWORD pID, const long long addr, const signed short buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed short), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool WriteProcMemInt(DWORD pID, const long long addr, const signed int buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed int), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool WriteProcMemLong(DWORD pID, const long long addr, const signed long long buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed long long), NULL);
        CloseHandle(handle);
        return r;
    }
    // real 
    DLLE bool WriteProcMemFloat(DWORD pID, const long long addr, const float buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(float), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool WriteProcMemDouble(DWORD pID, const long long addr, const double buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(double), NULL);
        CloseHandle(handle);
        return r;
    }
    // XOR
    DLLE bool WriteProcMemXOR(int pID, const long long addr, const DWORD32 buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        DWORD32 t = 0;
        bool r = ReadProcessMemory(handle, (LPCVOID)(addr+0x4), &t, sizeof(DWORD32), NULL);
        DWORD32 t1 = t ^ buffer;
        r = WriteProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(DWORD32), NULL);
        CloseHandle(handle);
        return r;
    }
    // ~write

    // -----------------------------------------------

    // -----------------------------------------------

    // -----------------------------------------------
    
    // read
    DLLE bool ReadProcMemBYTE(DWORD pID, const long long addr, BYTE& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(BYTE), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool ReadProcMemWORD(DWORD pID, const long long addr, WORD& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(WORD), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool ReadProcMemDWORD(DWORD pID, const long long addr, DWORD32& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(DWORD32), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool ReadProcMemQWORD(DWORD pID, const long long addr, DWORD64& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(DWORD64), NULL);
        CloseHandle(handle);
        return r;
    }
    // signed
    DLLE bool ReadProcMemChar(DWORD pID, const long long addr, signed char& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed char), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool ReadProcMemShort(DWORD pID, const long long addr, signed short& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed short), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool ReadProcMemInt(DWORD pID, const long long addr, signed int& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed int), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool ReadProcMemLong(DWORD pID, const long long addr, signed long long& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(signed long long), NULL);
        CloseHandle(handle);
        return r;
    }
    // real 
    DLLE bool ReadProcMemFloat(DWORD pID, const long long addr, float& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(float), NULL);
        CloseHandle(handle);
        return r;
    }
    DLLE bool ReadProcMemDouble(DWORD pID, const long long addr, double& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        bool r = ReadProcessMemory(handle, (LPVOID)(addr), &buffer, sizeof(double), NULL);
        CloseHandle(handle);
        return r;
    }
    // XOR
    DLLE bool ReadProcMemXOR(int pID, const long long addr, DWORD32& buffer) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        DWORD32 t;
        DWORD32 t1;
        bool r = ReadProcessMemory(handle, (LPCVOID)(addr), &t, sizeof(DWORD32), NULL);
        r = ReadProcessMemory(handle, (LPCVOID)(addr + 0x4), &t1, sizeof(DWORD32), NULL);
        buffer = t ^ t1;
        CloseHandle(handle);
        return r;
    }
    // ~read

    inline bool CheckSignature(const PBYTE sourse, const PBYTE pattern, const std::string& mask) {
        int size = mask.size();
        if (mask[size - 1] != '?' and sourse[size - 1] != pattern[size - 1])
            return false;
        for (int i = 0; i < size - 1; i++) {
            if (mask[i] == '?' or (sourse[i] == pattern[i]))
                continue;
            else
                return false;
        }
        return true;
    }

    PBYTE GetPatMask(std::string AOB, std::string& mask) {

        auto byteFromStr = [](const char b[3]) -> BYTE {
            std::string t = "0123456789ABCDEF";
            return (t.find(b[0])) * 16 + t.find(b[1]);
        };

        int size =
            AOB[AOB.size() - 1] == ' ' ?
            AOB.size() / 3 :
            (AOB.size() + 1) / 3;

        PBYTE pattern = new BYTE[size];
        char s1[] = "  ";

        for (int i = 0; i < size; i++) {
            s1[0] = AOB[(i * 3) + 0];
            s1[1] = AOB[(i * 3) + 1];
            if ((s1[0] == 'x' and s1[1] == 'x')
                or (s1[0] == '?' and s1[1] == '?')) {
                mask += "?";
                pattern[i] = 0x0;
            }
            else {
                mask += "x";
                pattern[i] = byteFromStr(s1);
            }
        }
        return pattern;
    }

    std::vector<DWORD64> fut(const HANDLE& handle, MEMORY_BASIC_INFORMATION mbi,
        const PBYTE pattern, const std::string& mask, const DWORD64& startAddress, const DWORD64 offset) {

        std::vector<DWORD64> res;
        SIZE_T bytesRead = 0;
        BYTE* buffer = new BYTE[mbi.RegionSize];

        ReadProcessMemory(handle, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
        int size = mask.size();

        if (bytesRead >= 400)
            for (int i = 0; i < (mbi.RegionSize - size); i++)
                if (CheckSignature(buffer + i, pattern, mask))
                    res.push_back(startAddress + offset + i);

        delete[] buffer;
        return res;
    }

    std::vector<DWORD64> AOBscanAsync(DWORD pID, std::string AOB) {

        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        size_t scanSize = 0x7fffffffffff;
        std::string mask;
        PBYTE pattern = GetPatMask(AOB, mask);

        std::vector<DWORD64> res;

        std::vector<std::future<std::vector<DWORD64>>> r;

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        DWORD64 offset = 0;
        DWORD64 save = 0;
        SIZE_T bytesRead = 0;
        DWORD64 startAddress = 0;

        int count;

        while (offset < (scanSize - mask.size()) and offset >= save) {
            count = VirtualQueryEx(handle, (LPVOID)(startAddress + offset), &mbi, sizeof(mbi));
            if (count and mbi.State != MEM_FREE)
                r.push_back(std::async(std::launch::async, fut, std::ref(handle), mbi, pattern, std::ref(mask), std::ref(startAddress), offset));
            save = offset;
            offset += mbi.RegionSize;
        }

        int i, j, rSize = r.size();

        for (i = 0; i < rSize; i++)
            r[i].wait();

        for (i = 0; i < rSize; i++) {
            auto temp = r[i].get();
            for (j = 0; j < temp.size(); j++)
                res.push_back(temp[j]);
        }
        CloseHandle(handle);
        delete[] pattern;

        return res;
    }

    DLLE long long* AOBSA(int* size, DWORD pID, const char* AOB) {
        std::string AOB1 = AOB;
        auto l = ch::AOBscanAsync(pID, AOB1);
        *size = l.size();
        long long* arr = new long long[*size];
        for (int i = 0; i < *size; i++) {
            arr[i] = l[i];
        }
        return arr;
    }

    std::vector<DWORD64> AOBscanAsyncSettings(DWORD pID, std::string AOB, SettingsForSearch settings) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        size_t scanSize = 0x7fffffffffff;
        std::string mask;
        PBYTE pattern = GetPatMask(AOB, mask);

        std::vector<DWORD64> res;

        std::vector<std::future<std::vector<DWORD64>>> r;

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        DWORD64 offset = 0;
        DWORD64 save = 0;
        SIZE_T bytesRead = 0;
        DWORD64 startAddress = 0;

        int count;
        int t = 0;
        while (offset < (scanSize - mask.size()) and offset >= save) {
        //std::cout << ++t << '\n';
            count = VirtualQueryEx(handle, (LPVOID)(startAddress + offset), &mbi, sizeof(mbi));
            if (count and
                ((mbi.State & settings.state) or !settings.state) and (mbi.State != MEM_FREE) and
                ((mbi.Protect & settings.protect) or !settings.protect) and
                ((mbi.Type & settings.type) or !settings.type) and
                (offset >= settings.downLimit) and
                (offset <= settings.upLimit) and
                (mbi.RegionSize >= settings.downRegionSize) and
                (mbi.RegionSize <= settings.upRegionSize)) {
                std::cout << ++t<<'\n';
                r.push_back(std::async(std::launch::async, fut, std::ref(handle), mbi, pattern, std::ref(mask), std::ref(startAddress), offset));
            }
            save = offset;
            offset += mbi.RegionSize;
        }

        int i, j, rSize = r.size();

        for (i = 0; i < rSize; i++)
            r[i].wait();

        for (i = 0; i < rSize; i++) {
            auto temp = r[i].get();
            for (j = 0; j < temp.size(); j++)
                res.push_back(temp[j]);
        }
        CloseHandle(handle);
        delete[] pattern;

        return res;
    }

    DLLE long long* AOBSAS(int* size, DWORD pID, const char* AOB, SettingsForSearch settings) {
        std::string AOB1 = AOB;
        auto l = ch::AOBscanAsyncSettings(pID, AOB1, settings);
        *size = l.size();
        long long* arr = new long long[*size];
        for (int i = 0; i < *size; i++) {
            arr[i] = l[i];
        }
        return arr;
    }

    std::vector<ADDR_INFO> AOBscanInfo(DWORD pID, std::string AOB) {
        std::vector<ADDR_INFO> m;
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        size_t scanSize = 0x7fffffffffff;
        std::string mask;
        PBYTE pattern = GetPatMask(AOB, mask);

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        DWORD64 offset = 0;
        DWORD64 save = 0;
        SIZE_T bytesRead = 0;
        DWORD64 startAddress = 0;

        BYTE* buffer;

        int count;

        while (offset < (scanSize - mask.size()) and offset >= save) {
            count = VirtualQueryEx(handle, (LPVOID)(startAddress + offset), &mbi, sizeof(mbi));
            if (count and mbi.State != MEM_FREE) {
                buffer = new BYTE[mbi.RegionSize];

                ReadProcessMemory(handle, (LPCVOID)mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);

                if (bytesRead >= 400)
                    for (int i = 0; i < (mbi.RegionSize - mask.size()); i++)
                        if (CheckSignature(buffer + i, pattern, mask)) {
                            ADDR_INFO temp(startAddress + offset + i, offset, mbi.State, mbi.Protect, mbi.Type, mbi.RegionSize);
                            m.push_back(temp);
                        }
                delete[] buffer;
                //buffer = nullptr;
            }
            save = offset;
            offset += mbi.RegionSize;
        }
        CloseHandle(handle);
        delete[] pattern;
        return m;

    }

    DLLE
        ADDR_INFO * AOBSI(int* size,DWORD pID, const char* AOB) {
        std::string AOB1 = AOB;
        auto temp = ch::AOBscanInfo(pID, AOB1);
        *size = temp.size();
        ADDR_INFO* res = new ADDR_INFO[*size];
        for (int i = 0; i < *size; i++) {
            res[i] = temp[i];
        }
        return res;
    }

    DLLE
        ADDR_INFO * GetInfoAddress(DWORD pID, DWORD64 address) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        MEMORY_BASIC_INFORMATION mbi1 = { 0 };
        size_t scanSize = 0x7fffffffffff;

        DWORD64 offset = 0;
        DWORD64 save = 0;
        DWORD64 startAddress = 0;

        int count;
        while (offset < scanSize and offset >= save) {
            count = VirtualQueryEx(handle, (LPVOID)(startAddress + offset), &mbi, sizeof(mbi));
            if (address < startAddress + offset) {
                ADDR_INFO* t = new ADDR_INFO;
                *t = ADDR_INFO(address, startAddress + save, mbi1.State, mbi1.Protect, mbi1.Type, mbi1.RegionSize);
                return t;
            }
            mbi1 = mbi;
            save = offset;
            offset += mbi.RegionSize;
        }

        CloseHandle(handle);

    }
    
    // Don`t use
    //template<typename T>
    //void ThrFreeze(const DWORD pID, const DWORD64 addr, const T buffer, const bool& stop, int delay) {
    //    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
    //    while (stop) {
    //        WriteProcessMemory(handle, (LPVOID)addr, &buffer, sizeof(T), NULL);
    //        //std::this_thread::sleep_for(std::chrono::seconds(delay));
    //        Sleep(delay);
    //    }
    //    CloseHandle(handle);

    //}

    //template<typename T>
    //void Freeze(const DWORD& pID, const DWORD64& addr, T& buffer, const bool& stop, int delay) {
    //    std::thread thr(ThrFreeze<T>, pID, addr, buffer, std::ref(stop), delay);
    //    thr.detach();
    //}


    //inline bool CheckSignature(const PBYTE sourse, const PBYTE pattern, const std::string& mask);

    //PBYTE getPatMask(std::string AOB, std::string& mask);

    //std::vector<DWORD64> fut(const HANDLE& handle, MEMORY_BASIC_INFORMATION mbi,
    //    const PBYTE pattern, const std::string& mask, const DWORD64& startAddress, const DWORD64 offset);


    
    //std::vector<MEMORY_BASIC_INFORMATION> regionScan(DWORD pID, std::string AOB);


    //std::vector<DWORD64> test2(DWORD pID, std::string AOB, SettingsForSearch settings);
    //std::vector<ADDR_INFO> test(DWORD pID, std::string AOB);

    //void getNumRegions(DWORD pID);
}