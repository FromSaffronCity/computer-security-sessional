# reference: https://www.tutorialspoint.com/python/python_command_line_arguments.htm
import sys

from scapy.all import *
from scapy.layers.inet import IP, ICMP

print('\n./{}: OS Fingerprinting ({})...\n'.format(sys.argv[0], sys.argv[1]))

# crafting packet & carrying out passive os fingerprinting via icmp echo/ping messages
packet = IP(dst=sys.argv[1])/ICMP()

# reference: https://stackoverflow.com/questions/22421290/scapy-operation-not-permitted-when-sending-packets
response = sr1(packet, timeout=2, verbose=False)

if response == None:
    print('./{}: No Response from {}.\n'.format(sys.argv[0], sys.argv[1]))
elif IP in response:
    if response.getlayer(IP).ttl <= 64:
        os_guess = 'Linux/ FreeBSD(v5)/ MacOS'
    elif response.getlayer(IP).ttl <= 128:
        os_guess = 'Windows'
    else:
        os_guess = 'Cisco/ Solaris/ SunOS/ FreeBSD(v3.4, v4.0)/ HP-UX(v10.2, v11)'

    print('./{}: TTL = {} -> Guessed OS = {}.\n'.format(sys.argv[0], response.getlayer(IP).ttl, os_guess))

"""
    references: 
        1. OS Fingerprint with Scapy by Melardev (https://www.youtube.com/watch?v=gBvJ29QjO10)
        2. Remote OS Detection (https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/os_detection/index.html)
        3. Default TTL(Time to Live) Values of Different OS (https://subinsb.com/default-device-ttl-values/)
"""
