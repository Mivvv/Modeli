from scapy.all import *
import pickle
import argparse
import time

def main():
    args = init_args().parse_args()
    # start time
    start = 0
    diff = 0
    if(args.verbose == 1):
        start = time.time()
    with open(args.file, 'rb') as f:
        data = pickle.load(f)
    sendp(data, iface=args.interface, verbose = 0)
    if(args.verbose == 1):
        diff = time.time() - start

    if (args.verbose == 1):
        if(type(data) == list):
            for i in range(len(data)):
                print("No. " + str(i) + ": " + str(data[i].summary()))
                print("Time needed to send: " + str(diff) + " seconds")
                print("Length of packages: " + str(len(bytes(data[i]))) + " bytes")
                print("Datarate: " + str(len(bytes(data[i]))/diff) + " bytes/s")
        else:
            print("No. X: " + str(data.summary()))
            print("Time needed to send: " + str(diff) + " seconds")
            print("Length of packages: " + str(len(bytes(data))) + " bytes")
            print("Datarate: " + str(len(bytes(data))/diff) + " bytes/s")
    else:
        if(type(data) == list):
            for i in range(len(data)):
                print("No. " + str(i) + ": " + str(data[i].summary()))
        else:
            print("No. X: " + str(data.summary()))


def init_args():
    parser = argparse.ArgumentParser(description='ScapySend')
    parser.add_argument('-i', '--interface', help='Interface to send packets on', required=True)
    parser.add_argument('-f', '--file', help='File to send', required=True)
    parser.add_argument('-v', '--verbose',type = int, help='Verbose output', default = False)
    return parser



if __name__ == "__main__":
    main()