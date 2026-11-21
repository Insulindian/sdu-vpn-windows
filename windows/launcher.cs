using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class Launcher
{
    [STAThread]
    private static void Main()
    {
        try
        {
            string root = Path.GetFullPath(
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".."));
            string client = Path.Combine(root, "client");
            var start = new ProcessStartInfo
            {
                FileName = "pythonw.exe",
                Arguments = "-m sdu_connect.app",
                WorkingDirectory = client,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            Process.Start(start);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "无法启动 SDU VPN：\n" + ex.Message,
                "SDU VPN",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}
