using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
//using static ConsoleApp1.Cheat;
//using CheatLib;
using Address_info;


namespace ConsoleApp1
{
    
    class Program
    {
        static void run()
        {
            uint pID = Cheat.getPIDFromExe("LdVBoxHeadless.exe");
            Console.WriteLine(pID);

            string AOB = "00 00 80 3F CD CC CC 3D 8F C2 F5 3C";
            Cheat.SettingsForSearh settingsForAOB = Cheat.CreateSett(
                (uint)Cheat.State.MEM_COMMIT, 
                (uint)Cheat.Protect.PAGE_READWRITE, 
                (uint)Cheat.Type.MEM_PRIVATE, 
                0x20000000
                );
            long[] res = Cheat.AOBScan(pID, AOB, settingsForAOB);
            Console.WriteLine(res.Length);
            Console.WriteLine(Convert.ToString(res[0], 16));
            string AOB1 = "05 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 xx xx xx xx xx xx xx xx xx xx xx xx 01 01 00 00 xx xx xx xx xx xx xx xx xx xx xx xx 01 01 00 00 xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 00 00 00 xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 00 00 00 00 00 00 00 xx 01 00 00 00 00 00 00 xx 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A0 xx xx xx 00 00 00 00 xx xx xx xx xx xx xx xx xx xx xx xx 00 00 00 00 xx 01 00 00 xx 00 00 00 xx 00 00 00 xx 01 xx 00 xx xx xx xx 00 00 00 00 xx xx xx xx xx xx xx xx 00 00 00 00 00 00 00 00 xx xx xx xx xx xx xx xx 00 00 00 00 00 00 xx xx xx xx xx xx xx xx 00 00 00 00 00 00 xx xx xx xx xx xx xx xx xx 00 00 00 xx 01 00 00";

            Cheat.SettingsForSearh settingsForAOB1 = Cheat.CreateSett(
                (uint)Cheat.State.MEM_COMMIT,
                (uint)Cheat.Protect.PAGE_READWRITE,
                (uint)Cheat.Type.MEM_PRIVATE,
                0x20000000, 
                0x7fffffffffff, 
                0x190000, 
                0x210000
                );

            DateTime start;
            DateTime end;

            float s1 = 0.001f;
            float s2 = 1;
            float s3 = 100;

            int state = 0;
            int buf1 = 0, buf2 = 1000;
            while (state != 2)
            {
                Console.Write("1 - poisk\t2 - exit\n>>>");
                state = int.Parse(Console.ReadLine());
                if (state == 1)
                {
                    Cheat.WriteProcMem(pID, res[0], s1);

                    start = DateTime.Now;
                    long[] puk = Cheat.AOBScan(pID, AOB1, settingsForAOB1);
                    end = DateTime.Now;
                    Console.WriteLine("time = " + (end-start).TotalMilliseconds);

                    if (puk.Length == 1)
                    {
                        Cheat.WriteProcMem(pID, (puk[0] + 0x120), buf1);
                        Cheat.WriteProcMem(pID, (puk[0] + 0x124), buf2);
                        Console.Write(Convert.ToString(puk[0] + 0x120, 16));

                    }
                    Console.WriteLine();
                    Cheat.WriteProcMem(pID, res[0], s3);
                }
            }
        }


        static void Main(string[] args)
        {
            
            //run();
            //uint pID = Cheat.getPIDFromExe("Tutorial-x86_64.exe");

            //var sett = Cheat.CreateSett(
            //    0,
            //    0,
            //    0,
            //    0,0x7fffffffffff,0, 0x7fffffffffff

            //    );

            ////MessageBox.Show(Convert.ToUInt64(textBox3.Text, 16).ToString());

            //string AOB = "64 00 00 00";

            //var t = Cheat.AOBScan(pID, AOB, sett);
            //Console.WriteLine(t.Length);
            //Console.WriteLine(pID.ToString("X"));

            //var t = Cheat.AOBScanInfo(pID, "64 00 00 00 00 00 00 00 31 04 43 04 47 04 30 04 20 08 00 00 00 00 00 00");
            //var t1 = Cheat.AOBScan(pID, "64 00 00 00 00 00 00 00 31 04 43 04 47 04 30 04 20 08 00 00 00 00 00 00");
            //Console.WriteLine(t.Length);
            //Console.WriteLine(t1[0].ToString("X"));
            //foreach (var i in t)
            //{
            //    Console.WriteLine(i.getInfo());
            //}
            //Cheat.ADDR_INFO r = Cheat.GetInfoAddress(pID, (ulong)t1[0]);
            //Console.WriteLine(r.getInfo());
            //int g = 0x8;
            //var t = Cheat.getProcessList();
            //foreach (var i in t)
            //{
            //    i.print();
            //}
            //foreach (var i in t)
            //{
            //Console.WriteLine(i.name + " "+ i.pID.ToString("X"));
            //}

            //addr += 0x4;

            //int k1;
            //cheat.ReadProcMem(pID, 0x00157B68, out k1);
            //Console.WriteLine(k1);
        }
    }
}
