using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Address_info
{
    class Cheat
    {
        private const string DllPath = "CheatLib.dll";
        //private const string DllPath = "..\\..\\..\\x64\\Release\\CheatLib.dll";

        public enum State : uint
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_REPLACE_PLACEHOLDER = 0x00004000,
            MEM_RESERVE_PLACEHOLDER = 0x00040000,
            MEM_RESET = 0x00080000,
            MEM_TOP_DOWN = 0x00100000,
            MEM_WRITE_WATCH = 0x00200000,
            MEM_PHYSICAL = 0x00400000,
            MEM_ROTATE = 0x00800000,
            MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000,
            MEM_RESET_UNDO = 0x01000000,
            MEM_LARGE_PAGES = 0x20000000,
            MEM_4MB_PAGES = 0x80000000,
            MEM_64K_PAGES = (MEM_LARGE_PAGES | MEM_PHYSICAL),
            MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001,
            MEM_COALESCE_PLACEHOLDERS = 0x00000001,
            MEM_PRESERVE_PLACEHOLDER = 0x00000002,
            MEM_DECOMMIT = 0x00004000,
            MEM_RELEASE = 0x00008000,
            MEM_FREE = 0x00010000,
        }
        public enum Protect : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            PAGE_GRAPHICS_NOACCESS = 0x0800,
            PAGE_GRAPHICS_READONLY = 0x1000,
            PAGE_GRAPHICS_READWRITE = 0x2000,
            PAGE_GRAPHICS_EXECUTE = 0x4000,
            PAGE_GRAPHICS_EXECUTE_READ = 0x8000,
            PAGE_GRAPHICS_EXECUTE_READWRITE = 0x10000,
            PAGE_GRAPHICS_COHERENT = 0x20000,
            PAGE_GRAPHICS_NOCACHE = 0x40000,
            PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
            PAGE_REVERT_TO_FILE_MAP = 0x80000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
            PAGE_ENCLAVE_MASK = 0x10000000,
            PAGE_ENCLAVE_DECOMMIT = (PAGE_ENCLAVE_MASK | 0),
            PAGE_ENCLAVE_SS_FIRST = (PAGE_ENCLAVE_MASK | 1),
            PAGE_ENCLAVE_SS_REST = (PAGE_ENCLAVE_MASK | 2),
        }
        public enum Type : uint
        {
            MEM_PRIVATE = 0x00020000,
            MEM_MAPPED = 0x00040000,
            MEM_IMAGE = 0x01000000,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ADDR_INFO
        {
            public ulong addr;
            public ulong offset;
            public uint state;
            public uint protect;
            public uint type;
            public ulong regionSize;

            public string getInfo() => 
                "addr = " + addr.ToString("X") + '\t' + 
                "offset = " + offset.ToString("X") + '\t' +
                "state = " + Enum.GetName(typeof(State), state) + '\t' +
                "protect = " + Enum.GetName(typeof(Protect), protect) + '\t' +
                "type = " + Enum.GetName(typeof(Type), type) + '\t' +
                "RG = " + regionSize.ToString("X") + " (16) | " + regionSize + " (10)";
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SettingsForSearh
        {
            public uint state;
            public uint protect;
            public uint type;
            public ulong downLimit;
            public ulong upLimit;
            public ulong downRegionSize;
            public ulong upRegionSize;
        }
        //[DllImport(DllPath, EntryPoint = "CreateSett", CallingConvention = CallingConvention.Cdecl)]
        //public static extern SettingsForSearh CreateSett(
        //    uint state = 0,
        //    uint protect = 0,
        //    uint type = 0,
        //    ulong downLimit = 0x0,
        //    ulong upLimit = 0x7fffffffffff,
        //    ulong downRegionSize = 0x0,
        //    ulong upRegionSize = 0x7fffffffffff
        //    );
        public static SettingsForSearh CreateSett(
            uint state = 0,
            uint protect = 0,
            uint type = 0,
            ulong downLimit = 0x0,
            ulong upLimit = 0x7fffffffffff,
            ulong downRegionSize = 0x0,
            ulong upRegionSize = 0x7fffffffffff
            )
        {
            SettingsForSearh r = new SettingsForSearh();
            r.state = state;
            r.protect = protect;
            r.type = type;
            r.downLimit = downLimit;
            r.upLimit = upLimit;
            r.downRegionSize = downRegionSize;
            r.upRegionSize = upRegionSize;
            return r;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct Processes
        {
            public string name;
            public uint pID;
            public void print()
            {
                Console.WriteLine(name+ " " + pID.ToString("X"));
            }
            public string getStr()
            {
                return "0x" + pID.ToString("X").PadLeft(6, '0') + " - " + name;
            }
        }
        private static Processes createProcesses(string name, uint pID)
        {
            var proc = new Processes();
            proc.name = name;
            proc.pID = pID;
            return proc;
        }

        [DllImport(DllPath, EntryPoint = "getProcessList", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private static extern bool getProcessList(out int size, out IntPtr outNames, out IntPtr outPIDs);
        public static Processes[] getProcessList()
        {
            int size;
            IntPtr outNames;
            IntPtr outPIDs;

            bool state = getProcessList(out size, out outNames, out outPIDs);

            Processes[] res = new Processes[size];
            uint[] pIDs = new uint[size];
            IntPtr[] ptrNames = new IntPtr[size];
            string[] names = new string[size];

            byte[] byteArray = new byte[size * sizeof(uint)];

            Marshal.Copy(outPIDs, byteArray, 0, byteArray.Length);
            Buffer.BlockCopy(byteArray, 0, pIDs, 0, byteArray.Length);
            Marshal.Copy(outNames, ptrNames, 0, size);

            for (int i = 0; i < size; i++)
            {
                names[i] = Marshal.PtrToStringUni(ptrNames[i]);
                Marshal.FreeHGlobal(ptrNames[i]);
            }
            
            Marshal.FreeHGlobal(outNames);
            Marshal.FreeHGlobal(outPIDs);

            for (int i = 0; i < size; i++)
            {
                res[i] = createProcesses(names[i], pIDs[i]);
            }
            return res;
        }


        [DllImport(DllPath, EntryPoint = "getPIDFromExe", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint getPIDFromExe(string name);
        [DllImport(DllPath, EntryPoint = "getPIDFromName", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint getPIDFromName(string name);

        // Write
        // unsigned
        [DllImport(DllPath, EntryPoint = "WriteProcMemBYTE", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, byte buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemWORD", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, ushort buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemDWORD", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, uint buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemQWORD", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, ulong buffer);
        //signed
        [DllImport(DllPath, EntryPoint = "WriteProcMemChar", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, sbyte buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemShort", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, short buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemInt", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, int buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemLong", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, long buffer);
        // real
        [DllImport(DllPath, EntryPoint = "WriteProcMemFloat", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, float buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemDouble", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMem(uint pID, long addr, double buffer);
        [DllImport(DllPath, EntryPoint = "WriteProcMemXOR", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool WriteProcMemXOR(uint pID, long addr, uint buffer);

        // ~Write
        // Read
        // unsigned
        [DllImport(DllPath, EntryPoint = "ReadProcMemBYTE", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out byte buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemWORD", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out ushort buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemDWORD", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out uint buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemQWORD", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out ulong buffer);
        //signed
        [DllImport(DllPath, EntryPoint = "ReadProcMemChar", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out sbyte buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemShort", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out short buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemInt", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out int buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemLong", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out long buffer);
        // real
        [DllImport(DllPath, EntryPoint = "ReadProcMemFloat", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out float buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemDouble", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMem(uint pID, long addr, out double buffer);
        [DllImport(DllPath, EntryPoint = "ReadProcMemXOR", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool ReadProcMemXOR(uint pID, long addr, out uint buffer);
        // ~Read

        [DllImport(DllPath, EntryPoint = "AOBSA", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr AOBS(out int size, uint pID, string AOB);
        public static long[] AOBScan(uint pID, string AOB)
        {
            int size;
            IntPtr ptr = AOBS(out size, pID, AOB);
            long[] arr = new long[size];
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        [DllImport(DllPath, EntryPoint = "AOBSAS", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr AOBSAS(out int size, uint pID, string AOB, SettingsForSearh settings);
        public static long[] AOBScan(uint pID, string AOB, SettingsForSearh settings)
        {
            int size;
            IntPtr ptr = AOBSAS(out size, pID, AOB, settings);
            long[] arr = new long[size];
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        [DllImport(DllPath, EntryPoint = "AOBSI", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr AOBSI(out int size, uint pID, string AOB);

        public static ADDR_INFO[] AOBScanInfo(uint pID, string AOB)
        {
            int size;
            IntPtr ptr = AOBSI(out size, pID, AOB);
            ADDR_INFO[] res = new ADDR_INFO[size];
            int structSize = Marshal.SizeOf<ADDR_INFO>();

            for (int i = 0; i < size; i++)
            {
                IntPtr p = new IntPtr(ptr.ToInt64() + i * structSize);
                res[i] = Marshal.PtrToStructure<ADDR_INFO>(p);
            }
            Marshal.FreeHGlobal(ptr);
            return res;
        }

        [DllImport(DllPath, EntryPoint = "GetInfoAddress", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr GIA(uint pID, ulong address);

        public static ADDR_INFO GetInfoAddress(uint pID, ulong address)
        {
            IntPtr ptr = GIA(pID, address);
            ADDR_INFO res = new ADDR_INFO();
            res = Marshal.PtrToStructure<ADDR_INFO>(ptr);
            Marshal.FreeHGlobal(ptr);
            return res;
        }


    }
}
