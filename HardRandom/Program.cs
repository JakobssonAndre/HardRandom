using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using HardRandom.Properties;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HardRandom
{
    internal class Program
    {
        private static readonly Pkcs11InteropFactories pkcs11Factories = new Pkcs11InteropFactories();
        private static readonly AppType pkcs11Type = AppType.MultiThreaded;

        static void Main(string[] args)
        {
            // Get requested length of random number
            int RandomLength = Settings.Default.RandomLength;
            if (args != null && args.Length > 0 && args[0].Trim().Length > 0)
            {
                RandomLength = int.Parse(args[0]);
            }

            // Access Smart Card over PKCS#11
            using (IPkcs11Library pkcs11 = new Pkcs11LibraryFactory().LoadPkcs11Library(pkcs11Factories, Settings.Default.Pkcs11LibraryPath, pkcs11Type))
            {
                // Find avilable slot (with Smart Card in it)
                List<ISlot> slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);
                if (slots == null || slots.Count < 1)
                {
                    Console.WriteLine("Error: No slots");
                    return;
                }
                ISlot slot = slots[0];

                // Open a read only session (no PIN) and generate random sequence
                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                {
                    byte[] randomData = session.GenerateRandom(RandomLength);
                    string randomHex = string.Join(" ", randomData.Select(x => x.ToString("X2")));
                    Console.WriteLine("{0} ({1})", randomHex, randomData.Length);
                }
            }
        }
    }
}
