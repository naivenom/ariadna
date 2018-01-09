using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.IO;
using System.Net.Sockets;

namespace ariadna
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void hTTPParametersToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void gETToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _url;
            _url = textBox1.Text;
            int index = _url.IndexOf('?');
            string[] parms = _url.Remove(0, index + 1).Split('&');

            foreach (string parm in parms)
            {
                string xssUrl = _url.Replace(parm, parm + "ra<xss>it");
                string sqlUrl = _url.Replace(parm, parm + "ra'it");

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(sqlUrl);
                request.Method = "GET";
                string _sql = string.Empty;
                using (StreamReader lectura = new
                    StreamReader(request.GetResponse().GetResponseStream()))
                    _sql = lectura.ReadToEnd();

                request = (HttpWebRequest)WebRequest.Create(xssUrl);
                request.Method = "GET";

                string _xss = string.Empty;
                using (StreamReader lectura = new
                    StreamReader(request.GetResponse().GetResponseStream()))
                    _xss = lectura.ReadToEnd();
                if (_xss.Contains("<xss>"))
                    MessageBox.Show("Posible XSS encontrado en el parametro: " + parm);
                if (_sql.Contains("error in your SQL syntax"))
                {
                    MessageBox.Show("Posible SQL encontrado en el parametro: " + parm);
                }

            }
        }

        private void pOSTToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _path;
            int _port;
            _path = textBox1.Text;
            _port = Convert.ToInt32(textBox2.Text);
            string[] requestLines = File.ReadAllLines(_path);
            string[] parms = requestLines[requestLines.Length - 1].Split('&');
            string host = string.Empty;
            StringBuilder requestBuilder = new StringBuilder();

            foreach (string line in requestLines)
            {
                if (line.StartsWith("Host:"))
                {
                    host = line.Split(' ')[1].Replace("\r", string.Empty);
                }
                requestBuilder.Append(line + "\n");
            }
            string request = requestBuilder.ToString() + "\r\n";
            IPEndPoint hostRemoto = new IPEndPoint(IPAddress.Parse(host), _port);
            foreach (string parm in parms)
            {
                using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.Connect(hostRemoto);
                    string valor = parm.Split('=')[1];
                    string peticion = request.Replace("=" + valor, "=" + valor + "'");
                    byte[] BytesPeticion = Encoding.ASCII.GetBytes(peticion);
                    sock.Send(BytesPeticion);
                    byte[] buffer = new byte[sock.ReceiveBufferSize];

                    sock.Receive(buffer);
                    string respuesta = Encoding.ASCII.GetString(buffer);
                    if (respuesta.Contains("error in your SQL syntax"))
                        MessageBox.Show("Parametro " + parm + " parece vulnerable a SQL injection con valor: " + valor + "'");


                }
            }
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void label2_Click(object sender, EventArgs e)
        {

        }

       
    }
}
