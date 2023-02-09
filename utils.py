from scapy.all import *
from datetime import timezone
from time import sleep
import time
import docker
import pickle
import tarfile
import datetime
import os
import platform
import argparse
import network_gui
import sys
from PySide2.QtWidgets import QApplication
from PySide2.QtGui import QPalette, QColor
from PySide2.QtCore import Qt, QSize

#region util
# get unique id for secondary network
def get_unique_ip(dict_source):
    containerID = "240.0.0."
    for i in range(99,255):
        if(containerID + str(i) not in dict_source):
            return containerID + str(i)
    
    return "-1"

def read_pcap(pcap_file:str):
    # Read in the pcap file and return a list of packets
    # Also return a dictionary with the source IP as key and the packets as value
    packets = rdpcap(pcap_file)
    dict_source = dict_of_sourceIP_packets(packets)
    return packets, dict_source

def dict_of_sourceIP_packets(packets):
    # Create a dictionary with the source IP as key and the packets as value
    dict_of_sourceIP_packets = {}

    for packet in packets:
        if packet["IP"].src not in dict_of_sourceIP_packets:
            dict_of_sourceIP_packets[packet["IP"].src] = [packet]
        else:
            dict_of_sourceIP_packets[packet["IP"].src].append(packet)

    return dict_of_sourceIP_packets

def kill_containers(client):
    # Kill and remove all containers
    # if i say ALL I mean ALL
    containers = client.containers.list()
    for container in containers:
        container.kill()
        container.remove()

    client.networks.prune()

def get_path():
    path = __file__
    path = path.replace("\\","/")
    path = path.split("/")[:-1]
    path = "/".join(path)
    return path

#copy to and from container
def copy_to(src, dst, client):
    name, dst = dst.split(':')
    container = client.containers.get(name)

    os.chdir(os.path.dirname(src))
    srcname = os.path.basename(src)
    tar = tarfile.open(src + '.tar', mode='w')
    try:
        tar.add(srcname)
    finally:
        tar.close()

    data = open(src + '.tar', 'rb').read()
    container.put_archive(os.path.dirname(dst), data)

def copy_from(save,savepath,location,client,firstKey):
    if(save):
        trycount = 0
        return_value = 1
        while(return_value != 0 and trycount < 3):
            return_value = get_tcpdump(savepath,location,client,firstKey)
            trycount += 1
            if(return_value != 0):
                # only log if "json" is not in savepath
                if("json" not in savepath):
                    log("Error while trying to get the tcpdump file, retrying in 5 seconds")
                time.sleep(5)
        if(return_value != 0):
            if("json" not in savepath):
                log("Failed to get the tcpdump file, please check the container logs")
        else:
            if("json" not in savepath):
                log("Successfully got the tcpdump file")
                log("File can be found at:" + location + "/" + savepath)
# test function to get any file from the container
def copy_any_from(savename:str,save_path:str,filename:str,client:docker.DockerClient,container:str):
    trycount = 0
    return_value = 1
    while(return_value != 0 and trycount < 3):
        return_value = get_any_file(savename,save_path,filename,client,container)
        trycount += 1
        if(return_value != 0):
            if("json" not in filename):
                log("Error while trying to get the file, retrying in 5 seconds")
        time.sleep(5)
    if(return_value != 0):
        log("Failed to get the file, please check the container logs")
    else:
        log("Successfully got the file")
        log("File can be found at:" + save_path + "/" + savename)
        
def get_subnet(packs):
    for pack in packs:
        if(pack.haslayer("IP")):
            ip = (pack["IP"].src).split(".")[:3]
            return ".".join(ip) + ".0/24"
    return 0

# test function to get any file from the container
def get_any_file(savename:str,save_path:str,filename:str,client:docker.DockerClient,container:str):
    #get archive attempt
    try:
        path = "/usr/src/app" + filename
        stream,stats =  client.containers.get(container).get_archive(path)
        with open(save_path + "/" + filename.split(".")[0]+".tar", 'wb') as f:
            for chunk in stream:
                f.write(chunk)
        with tarfile.open(save_path + "/" + filename.split(".")[0] + ".tar") as tar:
            tar.extractall(path=save_path)
        # delete tar file
        os.remove(save_path + "/" + filename.split(".")[0] + ".tar")
        # rename to savename
        os.rename(save_path + "/" + filename,save_path + "/" + savename)
        return 0
    except Exception as e:
        return 1

def get_tcpdump(savepath,location,client,container):
    #get archive attempt
    try:

        stream,stats =  client.containers.get(container).get_archive("usr/src/app/" + savepath)
        with open(location + "/" + savepath.split(".")[0] + ".tar", 'wb') as f:
            for chunk in stream:
                f.write(chunk)
        with tarfile.open(location + "/" + savepath.split(".")[0] + ".tar") as tar:
            tar.extractall(path=location)
        # delete tar file
        os.remove(location + "/" + savepath.split(".")[0] + ".tar")

        return 0
    except Exception as e:
        
        return 1

def filter_packets(packets,filter):
    # Filter the packets based on the filter
    # Only tcp and udp are supported
    packets_filltered = list()
    for packet in packets:
        if(filter == "TCP"):
            if(packet.haslayer("TCP")):
                packets_filltered.append(packet)
        elif(filter == "UDP"):
            if(packet.haslayer("UDP")):
                packets_filltered.append(packet)

    return packets_filltered

def SplitIntoMultipleList(packets):
    list_of_lists = []
    current_list = []
    currentSrcIP = ""
    for packet in packets:
        if packet.haslayer("IP"):
            if currentSrcIP == "":
                currentSrcIP = packet["IP"].src
                current_list.append(packet)
            elif currentSrcIP == packet["IP"].src:
                current_list.append(packet)
            else:
                list_of_lists.append(current_list)
                current_list = []
                currentSrcIP = packet["IP"].src
                current_list.append(packet)
    return list_of_lists

def log(message):
    print(message)
#endregion
def create_second_network(client, ping_location,secondary_network,dict_source,packets,max_range):
    # hard coded path names
    client_py = "/client.py"
    server_py = "server.py"
    server_dockerfile = "server.Dockerfile"
    server_tag = "server"
    server_subnet = "240.0.0.0/24" # subnet that SHOULD NEVER appear in a pcap file...officially...
    server_name = get_unique_ip(dict_source)
    packets_filename = "packets.p"
    with open(ping_location + "/"+ packets_filename, 'wb') as f:
        pickle.dump(packets, f)
    # build image
    client.images.build(path=ping_location, dockerfile=server_dockerfile, tag=server_tag)
    # create network (fake object called server_network, as it does not actually work)
    server_network = create_Network(secondary_network,server_subnet,client)
    container = client.containers.run(server_tag, detach=True, network=secondary_network, name=server_name, tty=True, stdin_open=True, privileged  = True,command="tail -f /dev/null")
    container.exec_run("ip addr add " + server_name + "/24 dev eth0")
    container.exec_run("ip link set dev eth0 up")
    for key in dict_source:
        client_container = client.containers.get(key)
        client_ip = server_name.split(".")[0:3]
        client_ip.append(str(key).split(".")[-1])
        client_ip = ".".join(client_ip)
        log("Client IP : " + client_ip)
        client.networks.get(secondary_network).connect(client_container,ipv4_address=client_ip)
        copy_to(ping_location + client_py, key + ":/usr/src/app/client.py", client)
        copy_to(ping_location + "/"+packets_filename, key + ":/usr/src/app/"+packets_filename, client)
    # now we have to wait for the network to be created
    sleep(1)
    for key in dict_source:
        client_container = client.containers.get(key)
        client_container.exec_run("python3 client.py "+"-f " + packets_filename,detach=True)

  
    copy_to(ping_location + "/"+packets_filename, server_name + ":/usr/src/app/"+packets_filename, client)
    container.exec_run("python3 -u server.py -i eth0 -f "+packets_filename + " -c " + str(max_range) + " -s "+server_name,detach=True)

def create_Network(netname, sub, client):
    # gateway should be 254 in the network
    gate = sub.split(".")[0:3] + ["254"]
    ipam_pool = docker.types.IPAMPool(
        subnet=sub,
        gateway=".".join(gate)
    )
    ipam_config = docker.types.IPAMConfig(
        pool_configs=[ipam_pool]
    )
    return client.networks.create(netname, ipam=ipam_config, driver="bridge")

def create_containers(dict_source, client, netname,image_name,location):
    # Create a container for each source IP in the dictionary
    # The container will be named after the source IP
    # The container will have the same IP as the source IP

    # first build the image
    client.images.build(path=location, dockerfile=image_name, tag="one")
    for key in dict_source:
        container = client.containers.run("one", name=key, network=netname, detach=True, tty=True, stdin_open=True, privileged  = True,command="tail -f /dev/null")
        container.exec_run("ip addr add " + key + "/24 dev eth0")
        container.exec_run("ip link set dev eth0 up")
        log("Created Container: "+ str(key))
        #print(container.exec_run("ip route add default via 10.13.152.254 dev eth0"))
        # start container


