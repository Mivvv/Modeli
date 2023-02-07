from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import argparse
import scapy
import pickle
import sys
import os


def init_args():
    parser = argparse.ArgumentParser(description='Ping a network')
    parser.add_argument("-f", "--file", help="File that has the packets", required=True)
    parser.add_argument("-i", "--interface", help="Interface to send packets")
    #parser.add_argument("-s", "--src", help="Source IP address",required=True)
    return parser

def write_log(content): # write to log file
    try:
        if(type(content) == Exception):
            content = str(content)

        with open("log.txt", "a") as f:
            f.write(str(content))
            f.write("\n")
    except Exception as e:
        write_log(e)
        print(e)


def sniff_callback(pkt):
    # check if src is from 240.0.0.0/24
    write_log("now here")
    try:
        if(pkt.haslayer("IP") == True and pkt["IP"].src.startswith("240.0.0.") == False):
            #write to log
            write_log("Not from server")
            return
        if(pkt.haslayer("Raw") == False):
            #write to log
            write_log("No raw layer")
            return
        num = int(pkt.getlayer("Raw").load.decode("utf-8"))
        # with open("log.txt", "a") as f:
        #     f.write(str(num))
        #     f.write("\n")
        # #wrpcap("test.pcap", pkt_to_send)
        #os.system("tcpreplay -i eth1 test.pcap")
        sendp(packets[num], iface="eth0")
        write_log("Sent :" + packets[num].summary())
        
      
    except Exception as e:
        write_log(e)


# main but not in main func to make global variable access easier
try:
    os.system("touch log.txt")
    parser = init_args()
    results = parser.parse_args()
    if(results.interface == None):
        results.interface = "eth1"
    write_log("I get here")
    packets = pickle.load(open(results.file, "rb"))
    write_log(packets[0].summary())
    srcPort = 1000
    portFilter = "dst port " + str(srcPort)
    sniff(prn=sniff_callback, iface="eth1")
except Exception as e:
    write_log(e)





