using System;
using System.Threading.Tasks;
using System.Management;
using System.IO;

class Program
{
    static StreamWriter? logWriter;

    static void WriteOutput(string message)
    {
        Console.WriteLine(message);
        logWriter?.WriteLine(message);
    }

    static async Task Main(string[] args)
    {
        using (logWriter = new StreamWriter("scan_output.txt", append: false))
        {
            string apiKey = "f303e6f4-69f0-4a8b-9a1f-dbbe0f86f535";
            var checker = new CVEChecker(apiKey);

            WriteOutput("Kurulu yazılımlar taranıyor...\n");

            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Product");

            foreach (ManagementObject obj in searcher.Get())
            {
                string name = obj["Name"]?.ToString() ?? "Bilinmeyen";
                string version = obj["Version"]?.ToString() ?? "N/A";

                string cleanedName = System.Text.RegularExpressions.Regex.Replace(name, @"\([^)]*\)", "").Trim();
                string[] parts = cleanedName.Split(' ');
                if (parts.Length > 2)
                {
                    cleanedName = string.Join(" ", parts[0], parts[1]);
                }

                if (!string.IsNullOrWhiteSpace(name))
                {
                    WriteOutput($"\nUygulama: {name} ({version})");

                    string json = await checker.GetCVEsAsync(cleanedName);

                    if (!string.IsNullOrEmpty(json))
                    {
                        var cveList = CVEParser.ParseCVEInfo(json);

                        if (cveList.Count == 0)
                        {
                            WriteOutput("  → CVE bulunamadı.");
                        }
                        else
                        {
                            foreach (var cve in cveList)
                            {
                                WriteOutput($"  → CVE: {cve.Id}");
                                WriteOutput($"     Açıklama: {cve.Description.Substring(0, Math.Min(80, cve.Description.Length))}...");
                                WriteOutput($"     CVSS Puanı: {cve.CVSS}");
                                WriteOutput($"     Exploit mevcut mu: {(cve.HasExploit ? "VAR" : "YOK")}\n");
                            }
                        }
                    }

                    await Task.Delay(2000);
                }
            }

            WriteOutput("\nTarama tamamlandı!");
            WriteOutput("Çıkmak için bir tuşa basın...");
            Console.ReadKey();
        }
    }
}