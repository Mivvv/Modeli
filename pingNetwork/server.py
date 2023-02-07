from scapy.all import *
import sys
import pickle
import argparse
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP
from time import sleep
import os
import json

def main():
    args = init_args()
    os.system("touch log.txt")
    os.system("touch jsonLog.json")
    # os.environ["PYTHONUNBUFFERED"] = "1"
    # with open("log.txt", "w") as f:
    #     f.write("I SET THE FUCKING ENV VARIABLE")
    results = args.parse_args()
    if(results.src == None):
        results.src = "240.0.0.100"
    if(results.interface == None):
        results.interface = "eth0"
    portFrom = 2000
    portTo = 1000
    src_ip = results.src
    interface = results.interface


    packets = pickle.load(open(results.file, "rb"))
    sleep(20)
    json_file_master = dict()
    json_file_master["Packets"] = dict()
    relativeTime = time.time()
    baseTime = time.time()
    try:
        for i in range(int(results.count)):
            pack = packets[i]
            json_file = dict()
            json_file["Source"] = pack["IP"].src
            json_file["Destination"] = pack["IP"].dst
            json_file["Time"] = time.time() - baseTime
            json_file["Length"] = len(pack)
            json_file["Summary"] = pack.summary()

            dst_ip = "240.0.0." + pack["IP"].src.split(".")[-1]
            ping = Ether()/IP(src=src_ip,dst=dst_ip)/TCP(sport = portFrom,dport=portTo)/str(i)
            sendp(ping, iface=interface)
            json_file["Exec Time"] = time.time() - relativeTime
            json_file["Datarate"] = len(pack)/(time.time() - relativeTime)
            relativeTime = time.time()
            json_file_master["Packets"][str(i)] = json_file
            with open("jsonLog.json", "w") as f:
                f.write(json.dumps(json_file_master))
                f.write("\n")
    except Exception as e:
        with open("log.txt", "a") as f:
            f.write(str(e))
            f.write("\n")
        
        
    

def init_args():
    parser = argparse.ArgumentParser(description='Ping a network')
    parser.add_argument("-f", "--file", help="File that has the packets", required=True)
    parser.add_argument("-i", "--interface", help="Interface to send packets")
    parser.add_argument("-c", "--count", help="Number of packets to send", required=True)
    parser.add_argument("-s", "--src", help="Source IP address")
    return parser

if __name__ == "__main__":
    main()
