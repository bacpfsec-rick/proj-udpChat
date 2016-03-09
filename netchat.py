# -*- coding: utf-8 -*-
"""
Created on Tue Dec 08 17:14:44 2015

@author: Rick
"""

import sys
import socket
import threading
import time
import re

# Verify the numbe of inputs
if len(sys.argv) != 4:
    print "Missing arguments"    
    sys.exit(1)
if not re.compile(r'[a-zA-Z0-9_@\-\*&\^%\$!#]+').match(sys.argv[3]):
    print "Invalid username"
    sys.exit(1)
    
# Global variables
# buffer length, KAT, ET
BUFLEN=1000
KAT = 3
ET = 10
# configure of this PC
main_ip = str(sys.argv[1])
main_port = int(sys.argv[2])
main_name = str(sys.argv[3])
# socket used in this program
main_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
main_socket.bind(('',main_port))
main_socket.setblocking(0)
# ip_range of the lab
#ip_range = ['192.168.1.73','192.168.1.75']
ip_range = []
for i in range(226,251):
    ip_range.append('142.66.140.'+str(i))
for i in range(70,99):
    ip_range.append('142.66.140.'+str(i))
# available port numbers
#port_range = range(56000,56003)
port_range = range(56000,56021)
#port_range = range(56000,56012)
# (un)confirmed peer list with format as {ip:{port:[name,last_time]}}
peer_list = {}
# (un)confirmed peer list with format as {ip:{port:[name]}}
un_peer_list = {}     
# basic sockets
hello_socket = "HEL:"+main_name
keep_socket = "KEE:"

# build the IM socket
def im_socket():
    ims = "IAM:" + main_name + ";"
    for ip in peer_list:
        for port in peer_list[ip]:
            ims += (ip + ":" + str(port) + ":" + \
            peer_list[ip][port][0] + ";")
    return ims        
            
# Receiver thread to handle different sockets
class receiver(threading.Thread):   
    def __init__(self):
        super(receiver,self).__init__()
        self.status = True        
        print "--->Receiver is activated"
    def run(self):        
        while self.status == True:
            try:
                data,addr = main_socket.recvfrom(BUFLEN)
#                print "Received: %s from (%s,%s)" % (data,addr[0],addr[1])
                self.handle_packet(data,addr)
            except:
                do_nothing = True	            
    def finish(self):
        print "--->Receiver is shutdown"
        self.status = False
    def handle_packet(self,data,addr):       
        # handle Hello with correct format
        if re.compile(r'^HEL:[a-zA-Z0-9_@\s\-\*&\^%\$!#]+').match(data):
#            name = re.compile(r'^HEL:[a-zA-Z0-9_@\-\*&\^%\$!#]+')\
#            .match(data).group()[4:]
            name = data.split(":")[1]
            ip = addr[0]
            port = int(addr[1])
#            if ip in peer_list:
#            	if port in peer_list[ip]:
#                        if name == peer_list[ip][port][0]:
#            			return
            print "--->%s has joined the Netchat" % name
            if not (ip in peer_list):
                peer_list[ip]= {}  
            peer_list[ip][port] = [name,time.time()]
            ims = im_socket()
#            print ims
            main_socket.sendto(ims,addr) 
#            print "%s sent to (%s,%s)" % (ims,ip,port)    
        # handle IM with correct format
        elif re.compile(r'^IAM:[a-zA-Z0-9_@\s\-\*&\^%\$!#]+').match(data):
#            name = re.compile(r'^IAM:[a-zA-Z0-9_@\-\*&\^%\$!#]+')\
#            .match(data).group()[4:];
            name = data.split(":")[1].split(";")[0]
            ip = addr[0]
            port = int(addr[1])
#            if ip in peer_list:
#            	if port in peer_list[ip]:
#                        if name == peer_list[ip][port][0]:
#            			return
            print "--->%s has joined the Netchat" % name
            # add the peer to confirmed peer_list
            if not (ip in peer_list):
                peer_list[ip] = {}
            peer_list[ip][port] = [name,time.time()]            
            # add the unconfirmed peer list to un_peer_list
            pattern=\
            r'(\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}):(\d{,6}):[a-zA-Z0-9_@\-\*&\^%\$!#]+'
            valid_un_peers=re.compile(pattern).findall(data)
            for un_peer in valid_un_peers:
                up_ip = un_peer[0]
                up_port = un_peer[1]
                up_name = un_peer[2]
                # skip the case when some peer is already confirmed before
                if up_ip in peer_list:
                    if up_port in peer_list[up_ip]:
                        if peer_list[up_ip][up_port][0] == up_name:
                            continue
                if not (up_ip in un_peer_list):
                    un_peer_list[up_ip] = {}
                un_peer_list[up_ip][up_port] = up_name
        # handle Keep with correct format      
        elif 'KEE:' == data:
            ip = addr[0]
            port = int(addr[1])
            if ip in peer_list:
                if port in peer_list[ip]:
#                    print "--->%s is kept alive" % peer_list[ip][port][0]
                    peer_list[ip][port][1] = time.time()
        # handle Message with correct format                  
        elif re.compile(r'^MSG:.+').match(data):
            ip = addr[0]
            port = int(addr[1])
            if ip in peer_list:
                if port in peer_list[ip]:
                    print "--->MSG received from %s: %s" \
                    % (peer_list[ip][port][0],data[4:])
                    peer_list[ip][port][1] = time.time()
        

# Sender thread to send different content
class sender(threading.Thread):
    def __init__(self,ip,port,content):
        super(sender,self).__init__()
        self.ip = ip
        self.port = port
        self.content = content
    def run(self):  
        main_socket.sendto(self.content,(self.ip,self.port))  
#        print "'%s' sent to (%s,%s)" % (self.content,self.ip,self.port)

# Peer discovery process with sending hello
def peer_discovery():
    global ip_range
    global port_range
    global main_socket
    global hello_socket
    print "--->Peer discovering"
    for ip in ip_range:
        for port in port_range:
            if (port == main_port) and (ip==main_ip):
                continue            
            else: # unconfirmend
		print "HELLO sent to:\tip: " + ip + "\tport: " + str(port)
		main_socket.sendto(hello_socket,(ip,port))
#                print "%s sent to (%s,%s)" % (hello_socket,ip,port)

# Keep alive timer thread
class kat(threading.Thread):
    def __init__(self):
        super(kat,self).__init__()
        self.time = time.time()
        self.status = True
    def run(self):
        global un_peer_list
        while self.status:
            current_time = time.time()
            if (current_time-self.time) < KAT:
                continue
            else:
                self.time = current_time
                for ip in peer_list.keys():
                    for port in peer_list[ip].keys():
                        la_time = peer_list[ip][port][1]
                        if (current_time-la_time) < ET:
                            main_socket.sendto(keep_socket,(ip,port))   
#                            print "%s sent to (%s,%s)" % (keep_socket,ip,port)
                        else: # kill the peer      
                            print "--->%s has quit" % peer_list[ip][port][0]
                            peer_list[ip].pop(port)                            
                for ip in un_peer_list:
                    for port in un_peer_list[ip]:
                        main_socket.sendto(hello_socket,(ip,port))
#                        print "%s sent to (%s,%s)" \
#                        % (im_socket,ip,port)
                un_peer_list = {}        
    def finish(self):
        self.status = False
        
# Message sending thread
class msg(threading.Thread):
    def __init__(self,message):
        super(msg,self).__init__()
        self.message = message
    def run(self):
        for ip in peer_list:
            for port in peer_list[ip]:
                main_socket.sendto(self.message,(ip,port))
    
# Netchat main
def netchat():
    # load global variables
    global ip_range
    global main_ip
    global main_name
    global main_port
    print "--->Netchat is started"
    # peer discovery
    peer_discovery()        
    # start the receiver thread
    receiveThread = receiver()
    receiveThread.start()
    # start the KAT thread
    katThread = kat()
    katThread.start()
    # get the MSG to send
    while True:
        text = raw_input('\n(Type quit to quit)\n')
        if 'quit' == text:
            receiveThread.finish()
            katThread.finish()
            break      
        elif '' == text:
            continue
        else:
            msgThread = msg("MSG:"+text)
            msgThread.start()
    print "--->Netchat is closed"          
    
# Run the Netchat program
netchat()    
