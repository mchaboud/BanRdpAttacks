using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;
using System.Text.RegularExpressions;
using NetFwTypeLib;

namespace BanRdpAttacks
{
    class Program
    {
        static int minEvntIdx = 0;
        static int maxFails = 5;
        static int delay = 5;
        static TimeSpan tdelay = new TimeSpan(0, delay, 0);

        static void Main(string[] args)
        {
            while (true)
            {
                var res = ExtractRDPFails();
                var res2 = DetectIpToBan(res);
                Console.WriteLine($"-{minEvntIdx}-{res.Count}-{res2.Count}-{string.Join(", ", res.Keys.Except(res2).Select(s => $"{s}->{res[s].Count}"))}");
                AddIpToWinFirewall(res2);
                Thread.Sleep(60 * 1000);
            }
        }

        private static Dictionary<string, List<DateTime>> ExtractRDPFails()
        {
            Dictionary<string, List<DateTime>> res = new Dictionary<string, List<DateTime>>();
            Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;
            var eventLogs = EventLog.GetEventLogs().Where(el => el.Log == "Security").FirstOrDefault();
            var lastCheck = DateTime.Now.AddMinutes(delay * -2);
            if (eventLogs == null)
                throw new KeyNotFoundException();
            foreach (EventLogEntry evnt in eventLogs.Entries)
                if (evnt.InstanceId == 4625 && evnt.Index >= minEvntIdx && evnt.EntryType == EventLogEntryType.FailureAudit)//take only failed logon
                {
                    if (evnt.TimeGenerated < lastCheck && minEvntIdx < evnt.Index)
                        minEvntIdx = evnt.Index;
                    if (evnt.ReplacementStrings.Length >= 20 && !string.IsNullOrWhiteSpace(evnt.ReplacementStrings[19]) && evnt.ReplacementStrings[19] != "-")//use the fact messages are formated string, ip is at idx 19
                    {
                        string ip = evnt.ReplacementStrings[19];
                        //Console.WriteLine($"{evnt.TimeGenerated} {evnt.Index} {ip}");
                        if (!res.TryGetValue(ip, out var dates))
                        {
                            dates = new List<DateTime>();
                            res.Add(ip, dates);
                        }
                        dates.Add(evnt.TimeGenerated);
                    }
                }
            foreach (var kvp in res)
                Console.WriteLine($"{kvp.Key}=> {kvp.Value.Count}");
            return res;
        }
        private static List<string> DetectIpToBan(Dictionary<string, List<DateTime>> failures)
        {
            var res = new List<string>();

            foreach (var kvp in failures)
            {
                var failledDates = kvp.Value;
                if (failledDates.Count < maxFails)
                    continue;
                /* var ts = new List<TimeSpan>();//Extract TimeSpan between to failed login
                 for (int i = 1; i < failledDates.Count - 1; i++)
                 {
                     var tsBetween = failledDates[i] - failledDates[i - 1];
                     if (tsBetween < tdelay)//remove any timespan already bigger than the delay where we authorize X failed login
                         ts.Add(tsBetween);
                 }
                 if (ts.Count < maxFails)
                     continue;
                 Console.WriteLine($"{kvp.Key} <> {ts.Count}");*/
                for (int i = 0; i < failledDates.Count - 1; i++)
                    for (int j = i + maxFails; j < failledDates.Count - 1; j++)
                        if (failledDates[j] - failledDates[i] < tdelay)
                        {
                            res.Add(kvp.Key);
                            Console.WriteLine($"BANNED : {kvp.Key} {i} : {j}");
                            i = int.MaxValue - 1;//LOL trapped by this
                            j = int.MaxValue - maxFails - 1;//LOL trapped by this also
                        }
            }
            return res;
        }
        private static void AddIpToWinFirewall(List<string> toBan)
        {
            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            HashSet<string> BlockedBastards = firewallPolicy.Rules
                .Cast<INetFwRule>()
                .Where(r => r.Action == NET_FW_ACTION_.NET_FW_ACTION_BLOCK && r.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN && r.Enabled && r.RemoteAddresses.Contains('/'))
                .Select(r => r.RemoteAddresses.Split('/')[0])
                //.Distinct()
                .ToHashSet();


            foreach (var ip in toBan)
                if (!string.IsNullOrWhiteSpace(ip) && ip.Split(new char[] { '.', ':' }, StringSplitOptions.RemoveEmptyEntries).Length == 4 && !BlockedBastards.Contains($"{ip}"))
                {
                    try
                    {
                        INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                        firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                        firewallRule.Description = $"Unwanted bot or bastard detedted at {ip}";
                        firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN; // inbound
                        firewallRule.Enabled = true;
                        firewallRule.InterfaceTypes = "All";
                        firewallRule.RemoteAddresses = $"{ip}/32"; // add more blocks comma separated
                        firewallRule.Name = $"Bot or bastard at {ip}";

                        firewallPolicy.Rules.Add(firewallRule);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
        }
    }
}
