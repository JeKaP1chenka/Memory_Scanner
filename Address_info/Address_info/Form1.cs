using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.Odbc;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;


namespace Address_info
{
    public partial class Form1 : Form
    {
        public static uint pID;
        public Form1()
        {
            InitializeComponent();
        }

        List<Cheat.ADDR_INFO> listInfo = new List<Cheat.ADDR_INFO>();
        List<Cheat.ADDR_INFO> listInfo2 = new List<Cheat.ADDR_INFO>();

        private void reload(ref DataGridView d,ref List<Cheat.ADDR_INFO> li)
        {
            d.Rows.Clear();
            foreach (var i in li)
            {
                d.Rows.Add(
                    i.addr.ToString("X"),
                    i.offset.ToString("X"),
                    Enum.GetName(typeof(Cheat.State), i.state),
                    Enum.GetName(typeof(Cheat.Protect), i.protect),
                    Enum.GetName(typeof(Cheat.Type), i.type),
                    i.regionSize.ToString("X")
                    );
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

            //var t = Cheat.AOBScanInfo(pID, "64 00 00 00 00 00 00 00 31 04 43 04 47 04 30 04 20 08 00 00 00 00 00 00");
            //var t1 = Cheat.AOBScan(pID, "64 00 00 00 00 00 00 00 31 04 43 04 47 04 30 04 20 08 00 00 00 00 00 00");
            List<string> state_names = Enum.GetNames(typeof(Cheat.State)).ToList();
            comboBox2.Items.Add(" ");
            comboBox2.Items.AddRange(state_names.ToArray());
            comboBox2.Text = " ";
            List<string> protect_names = Enum.GetNames(typeof(Cheat.Protect)).ToList();
            comboBox3.Items.Add(" ");
            comboBox3.Items.AddRange(protect_names.ToArray());
            comboBox3.Text = " ";
            List<string> type_names = Enum.GetNames(typeof(Cheat.Type)).ToList();
            comboBox4.Items.Add(" ");
            comboBox4.Items.AddRange(type_names.ToArray());
            comboBox4.Text = " ";

        }
        // AOBscan
        private void button1_Click(object sender, EventArgs e)
        {
            //uint pID = Cheat.getPIDFromExe("Tutorial-x86_64.exe");
            if (pID == default)
            {
                MessageBox.Show("говно");
                return;
            }
            string AOB = textBox1.Text;
            if (AOB == "")
            {
                MessageBox.Show("введите AOB");
                return;
            }
            bool cheak = true;
            for (int i = 0; i < AOB.Length; i++)
            {
                if ((i + 1) % 3 == 0 && !(AOB[i] == ' '))
                {
                    cheak = false;
                    break;
                }
                else if (!((i + 1) % 3 == 0) && !Regex.IsMatch(AOB[i].ToString(), @"[0-9]|[A-F]|\?|x"))
                {
                    cheak = false;
                    break;
                }
            }
            if (!cheak) 
            {
                MessageBox.Show("не правильно введен AOB");
                return;
            }

            uint mState = 0;
            uint mProtect = 0;
            uint mType = 0;

            if (comboBox2.Text != " ")
            {
                mState = (uint)Enum.Parse(typeof(Cheat.State), comboBox2.Text);
                //MessageBox.Show(mState.ToString());
            }
            if (comboBox3.Text != " ")
            {
                mProtect = (uint)Enum.Parse(typeof(Cheat.Protect), comboBox3.Text);
                //MessageBox.Show(mProtect.ToString());
            }
            if (comboBox4.Text != " ")
            {
                mType = (uint)Enum.Parse(typeof(Cheat.Type), comboBox4.Text);
                //MessageBox.Show(mType.ToString());
            }
            string sDownLimit = "0";
            if (textBox3.Text.Contains("0x"))
                sDownLimit = textBox3.Text.Replace("0x", "");
            string sUpLimit = "7fffffffffffffff";
            if (textBox4.Text.Contains("0x"))
                sUpLimit = textBox4.Text.Replace("0x", "");
            string sDownRG = "0";
            if (textBox5.Text.Contains("0x"))
                sDownRG = textBox5.Text.Replace("0x", "");
            string sUpRG = "7fffffffffffffff";
            if (textBox6.Text.Contains("0x"))
                sUpRG = textBox6.Text.Replace("0x", "");

            //MessageBox.Show(textBox3.Text);

            ulong DownLimit = 0, UpLimit = 0, DownRG = 0 , UpRG = 0;
            try
            {

                DownLimit = Convert.ToUInt64(sDownLimit, 16);
                UpLimit = Convert.ToUInt64(sUpLimit, 16);
                DownRG = Convert.ToUInt64(sDownRG, 16);
                UpRG = Convert.ToUInt64(sUpRG, 16);
            }
            catch
            {
                MessageBox.Show("параша");
                return;
            }
            var sett = Cheat.CreateSett(
                mState,
                mProtect,
                mType,
                DownLimit,
                UpLimit,
                DownRG,
                UpRG
                );

            var t = Cheat.AOBScan(pID, AOB, sett);
            //var t = Cheat.AOBScan(pID, AOB);
            listInfo.Clear();
            foreach (var i in t)
            {
                Cheat.ADDR_INFO r = Cheat.GetInfoAddress(pID, (ulong)i);
                listInfo.Add(r);
            }
            label8.Text = listInfo.Count.ToString() + " results";

            reload(ref dataGridView1, ref listInfo);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            int selectedRowCount = dataGridView1.Rows.GetRowCount(DataGridViewElementStates.Selected);
            if (selectedRowCount > 0)
            {
                for (int i = 0; i < selectedRowCount; i++)
                {
                    var ind = dataGridView1.SelectedRows[i].Index;
                    listInfo2.Add(listInfo[ind]);
                }
            }
            reload(ref dataGridView2, ref listInfo2);
        }

        private void button6_Click(object sender, EventArgs e)
        {
            getProc win = new getProc();
            win.ShowDialog();
        }
        // del
        private void button5_Click(object sender, EventArgs e)
        {
            int selectedRowCount = dataGridView2.Rows.GetRowCount(DataGridViewElementStates.Selected);
            if (selectedRowCount > 0)
            {
                for (int i = 0; i < selectedRowCount; i++)
                {
                    var ind = dataGridView2.SelectedRows[i].Index;
                    //listInfo2.Add(listInfo[ind]);
                    listInfo2.RemoveAt(ind);
                }
            }
            reload(ref dataGridView2, ref listInfo2);
        }

        private void button4_Click(object sender, EventArgs e)
        {
            string sAddr = textBox7.Text;
            ulong addr = 0;
            try
            {
                addr = Convert.ToUInt64(sAddr, 16);
            }
            catch
            {
                MessageBox.Show("лох");
                return;
            }
            var t = Cheat.GetInfoAddress(pID, addr);
            listInfo2.Add(t);
            reload(ref dataGridView2,ref listInfo2);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (listInfo2.Count == 0)
            {
                MessageBox.Show("нахуй");
                return;
            }
            HashSet<string> sState = new HashSet<string>();
            HashSet<string> sProtect = new HashSet<string>();
            HashSet<string> sType = new HashSet<string>();
            //uint state = 0;
            //uint protect = 0;
            //uint type = 0;
            ulong downLimit = 0x7fffffffffffffff;
            ulong upLimit = 0;
            ulong downRG = 0x7fffffffffffffff;
            ulong upRG = 0;
            for (int i = 0; i < listInfo2.Count;i++)
            {
                sState.Add(Enum.GetName(typeof(Cheat.State), listInfo2[i].state));
                sProtect.Add(Enum.GetName(typeof(Cheat.Protect), listInfo2[i].protect));
                sType.Add(Enum.GetName(typeof(Cheat.Type), listInfo2[i].type));
                //state |= listInfo2[i].state;
                //protect |= listInfo2[i].protect;
                //type |= listInfo2[i].type;
                if (listInfo2[i].offset < downLimit)
                {
                    downLimit = listInfo2[i].offset-0x1000;
                }
                if (listInfo2[i].offset > upLimit)
                {
                    upLimit = listInfo2[i].offset +0x1000;
                }
                if (listInfo2[i].regionSize < downRG)
                {
                    downRG= listInfo2[i].regionSize - 0x1000;
                }
                if (listInfo2[i].regionSize > upRG)
                {
                    upRG = listInfo2[i].regionSize + 0x1000;
                }
            }
            //textBox2.Text = string.Format("(Cheat.State.{0}, Cheat.Protect.{1}, Cheat.Type.{2}, 0x{3}, 0x{4}, 0x{5}, 0x{6})",
            string t1 = "";
            for (int i = 0; i < sState.Count; i++)
            {
                 t1 += "Cheat.State." + sState.ElementAt(i) + " | ";
            }
            t1 = t1.Substring(0,t1.Length-3);
            
            string t2 = "";
            for (int i = 0; i < sProtect.Count; i++)
            {
                 t2 += "Cheat.State." + sProtect.ElementAt(i) + " | ";
            }
            //t2 += "\b\b\b";
            t2 = t2.Substring(0,t2.Length-3);

            string t3 = "";
            for (int i = 0; i < sType.Count; i++)
            {
                 t3 += "Cheat.State." + sType.ElementAt(i) + " | ";
            }
            //t3 += "\b\b\b";
            t3 = t3.Substring(0,t3.Length-3);

            //string t2 = "Cheat.Protect." + Enum.GetName(typeof(Cheat.Protect), protect);
            //string t3 = "Cheat.Type." + Enum.GetName(typeof(Cheat.Type), type);
            string t4 = downLimit.ToString("X");
            string t5 = upLimit.ToString("X");
            string t6 = downRG.ToString("X");
            string t7 = upRG.ToString("X");
            textBox2.Text = "(" + t1 + ", " + t2 + ", " + t3 + ", " + t4 + ", " + t5 + ", " + t6 + ", " + t7 + ")";
        }
    }
}
