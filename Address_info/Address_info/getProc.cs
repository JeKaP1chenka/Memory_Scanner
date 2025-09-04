using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Address_info
{
    public partial class getProc : Form
    {
        Cheat.Processes[] procList;
        public getProc()
        {
            InitializeComponent();
        }

        private void getProc_Load(object sender, EventArgs e)
        {
            procList = Cheat.getProcessList();
            foreach (var i in procList)
            {
                listBox1.Items.Add(i.getStr());
            }
            listBox1.TopIndex = listBox1.Items.Count - 1;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var index = listBox1.SelectedIndex;
            Form1.pID = procList[index].pID;
            Close();
        }
    }
}
