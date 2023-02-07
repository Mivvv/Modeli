# General

This program takes a PCAP file and generates a network in docker and simulates the traffic.
You can customize the program with the following arguments.

# Arguments

- p (pcap) -> path to tcpfile
- d (docker) -> only make the network but nothing else
- sp (savepath) -> path to savefile
- f (filter) -> filter the pcap for a certain protocol
- g (gui) -> give a GUI where you make the window with the information
- m (mode) -> lets have only "tcpreplay","scapySend","ping network"
- og (onlygui) -> only gui, no actual docker network
- td (dump) -> create a tcpdump
- c (count) -> how many packages to send
- l (listOfLists) -> optimised list of list way, mode has to be tcpreplay or scapy
- ip (ip) -> range of the network, if left empty we take the first IP and make the assumption of a /24 network