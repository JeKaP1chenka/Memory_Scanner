#include "cheat.h"

namespace ch {


    extern "C" __declspec(dllexport) int getPIDFromExe(const char s[]) {
        int pID = 0;
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
            char* t = new char(size+1);
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

    extern "C" __declspec(dllexport) int getPIDFromName(const char* name) {
        int pID = 0;
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

    inline bool CheckSignature(const PBYTE sourse, const PBYTE pattern, const std::string& mask) {
        int size = mask.size();
        if (mask[size - 1] != '?' and sourse[size - 1] != pattern[size - 1])
            return false;
        for (int i = 0; i < size-1; i++) {
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
        //if (AOB[AOB.size() - 1] == ' ')
        //    size = AOB.size() / 3;
        //else
        //    size = (AOB.size() + 1) / 3;

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
        
        while (offset < (scanSize - mask.size()) and offset >= save) {
            count = VirtualQueryEx(handle, (LPVOID)(startAddress + offset), &mbi, sizeof(mbi));
            if (count and 
                (mbi.State & settings.state) and
                (mbi.Protect & settings.protect) and
                (mbi.Type & settings.type) and
                (offset > settings.downLimit) and
                (offset < settings.upLimit) and
                (mbi.RegionSize > settings.downRegionSize) and
                (mbi.RegionSize < settings.upRegionSize))
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

    std::vector<MEMORY_BASIC_INFORMATION> regionScan(DWORD pID, std::string AOB) {
        std::vector<MEMORY_BASIC_INFORMATION> res;
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        size_t scanSize = 0x7fffffffffff;
        std::string mask;
        PBYTE pattern = GetPatMask(AOB, mask);
        SIZE_T size = mask.size();

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        DWORD64 offset = 0;
        DWORD64 save = 0;
        SIZE_T bytesRead = 0;
        DWORD64 startAddress = 0;

        BYTE* buffer;

        int count;

        while (offset < (scanSize - mask.size()) and offset >= save) {
            count = VirtualQueryEx(handle, (LPVOID)(startAddress + offset), &mbi, sizeof(mbi));
            if (count and mbi.State != MEM_FREE and size > mbi.RegionSize) {
                buffer = new BYTE[size];

                ReadProcessMemory(handle, (LPCVOID)mbi.BaseAddress, buffer, size, &bytesRead);
                if (CheckSignature(buffer, pattern, mask)) {
                    res.push_back(mbi);
                }
                //if (bytesRead >= 400)
                //    for (int i = 0; i < (mbi.RegionSize - mask.size()); i++)
                //        if (CheckSignature(buffer + i, pattern, mask)) {
                //            ADDR_INFO temp(startAddress + offset + i, offset, mbi.State, mbi.Protect, mbi.Type, mbi.RegionSize);
                //            m.push_back(temp);
                //        }
                delete[] buffer;
                //buffer = nullptr;
            }
            save = offset;
            offset += mbi.RegionSize;
        }
        CloseHandle(handle);
        delete[] pattern;
        return res;
    }

    /////////
    std::vector<ADDR_INFO> test(DWORD pID, std::string AOB) {
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
                    for (int i = 0; i < (mbi.RegionSize - mask.size()); i+=0x10)
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

    // 
    std::vector<DWORD64> fut1(const HANDLE& handle, MEMORY_BASIC_INFORMATION mbi,
        const PBYTE pattern, const std::string& mask, const DWORD64& startAddress, const DWORD64 offset) {

        std::vector<DWORD64> res;
        SIZE_T bytesRead = 0;
        BYTE* buffer = new BYTE[mbi.RegionSize];

        ReadProcessMemory(handle, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
        int size = mask.size();

        if (bytesRead >= 400)
            for (int i = 0; i < (mbi.RegionSize - size); i+=0x10)
                if (CheckSignature(buffer + i, pattern, mask))
                    res.push_back(startAddress + offset + i);

        delete[] buffer;
        return res;
    }

    std::vector<DWORD64> test2(DWORD pID, std::string AOB, SettingsForSearch settings) {

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
            if (count and 
                (mbi.State & settings.state) and
                (mbi.Protect & settings.protect) and
                (mbi.Type & settings.type) and
                (offset > settings.downLimit) and
                (offset < settings.upLimit) and
                (mbi.RegionSize > settings.downRegionSize) and
                (mbi.RegionSize < settings.upRegionSize))
                r.push_back(std::async(std::launch::async, fut1, std::ref(handle), mbi, pattern, std::ref(mask), std::ref(startAddress), offset));
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
    /////////



    void getNumRegions(DWORD pID) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
        size_t scanSize = 0x7fffffffffff;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        DWORD64 offset = 0;
        DWORD64 save = 0;
        SIZE_T bytesRead = 0;
        DWORD64 startAddress = 0;
        int count;
        int res = 0;
        int res_all = 0;
        while (offset < (scanSize) and offset >= save) {
            count = VirtualQueryEx(handle, (LPVOID)(startAddress + offset), &mbi, sizeof(mbi));
            res_all++;
            if (count and mbi.State != MEM_FREE) {
                res++;
            }
            save = offset;
            offset += mbi.RegionSize;
        }
        std::cout   << "\n---------------------------\n" 
                    << "res_all -> " << res_all << "\n"
                    << "res -> " << res 
                    << "\n---------------------------\n";
        CloseHandle(handle);
    }

}