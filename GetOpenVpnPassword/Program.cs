using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace GetOpenVpnPassword
{
    class Program
    {
        static void Main(string[] args)
        {
            var configPath = @"Software\OpenVPN-GUI\configs";
            using (var configs = Registry.CurrentUser.OpenSubKey(configPath))
            {
                if (configs != null)
                {
                    foreach (var subKey in configs.GetSubKeyNames())
                    {
                        Console.WriteLine($"Try to get password for {subKey}");
                        GetConfigurationPassword(configs, subKey);
                    }
                }
            }

            Console.WriteLine("Hello World!");
        }

        private static void GetConfigurationPassword(RegistryKey? registryKey, string subKey)
        {
            using RegistryKey key = registryKey?.OpenSubKey(subKey);
            var entropy = (byte[])key.GetValue("entropy");
            var data = (byte[])key.GetValue("key-data");

            if (entropy == null || data == null)
            {
                Console.WriteLine("Could not read the value from registry");
            }

            GetOpenVpnPassword(entropy.Take(entropy.Length - 1).ToArray(), data);
        }

        private static void GetOpenVpnPassword(byte[] entropy, byte[] data)
        {
            var originData = ProtectedData.Unprotect(data, entropy, DataProtectionScope.CurrentUser);
            var outputString = Encoding.Unicode.GetString(originData);
            Console.WriteLine(outputString);
        }
    }
}
