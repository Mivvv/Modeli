from scapy.all import *
from time import sleep
import time
import json
import docker
import pickle
import tarfile
import os
import argparse
import network_gui
import OnlyGui
import sys
import utils
from PySide2.QtWidgets import QApplication
from PySide2.QtGui import QPalette, QColor
from PySide2.QtCore import Qt



#region init region
def main():

    arg_parser = init_sys_args()
    args = arg_parser.parse_args()

    args = clean_args(args)


    location = get_path()
   
        

    if(args.onlygui == 1):
        init_only_gui(location,args)
    packets, dict_source = utils.read_pcap(args.pcap) # args.pcap,default = "fullTCP.pcap"
    client = docker.from_env()
    subnet = args.ip
    if(subnet == None):
        subnet = utils.get_subnet(packets)
    netname = "primary"
    create_Network(netname, subnet, client)
    image_name = "one.Dockerfile"
    utils.create_containers(dict_source, client, netname,image_name,location)
    if(args.docker == 1):
        return
    if(args.gui == 1):
        
        init_GUI(packets,dict_source,client,netname,location,args)
        
    
    else:
        send_packets_args(packets,dict_source,client,netname,location,args)


def send_packets(packets, dict_source, client, netname,location):
    for pack in packets:
        wrpcap(filename="pack.pcap",pkt=pack)
        utils.copy_to(location+"/pack.pcap", str(pack["IP"].src)+":/usr/src/app/packets.p", client)
        cont = client.containers.get(pack["IP"].src)
        print(cont.exec_run("tcpreplay -i eth0 pack.pcap"))

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
    utils.log("Created Network: "+netname)
    return client.networks.create(netname, ipam=ipam_config, driver="bridge")

#endregion

#region gui
def init_only_gui(location,args):
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # Create a palette with dark colors
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    ex = OnlyGui.GUI(location,args)
    ex.setStyleSheet('background-color: #2b2b2b;')
    errorCode = app.exec_()
    sys.exit(errorCode)

def init_GUI(packets,dict_source,client,netname,location,args):
    app = QApplication(sys.argv)

    app.setStyle('Fusion')

    # Create a palette with dark colors
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)

    # Create the main window and set its properties
    ex = network_gui.MyWidget(packets,dict_source,client,location,args)
    ex.setStyleSheet('background-color: #2b2b2b;')
    errorCode = app.exec_()
    utils.kill_containers(client)
    sys.exit(errorCode)
#endregion



#region send functions
def send_packets_args(packets, dict_source, client, netname,location,args):
    #vars
    savename = args.savepath if args.savepath != "" else "/save.pcap"
    savename = args.savepath if args.savepath != "" else "save.pcap"
    save = True if args.dump == 1 else False
    args.listoflists = True if args.listoflists == 1 else False
   
    verbose = True if args.verbose == 1 else False
    mode = args.mode
    packetsFiltered = packets if args.filter == "" else utils.filter_packets(packets,args.filter)
    maxRange = args.count if args.count > 0 else len(packetsFiltered)


    utils.log("Sending packages with mode: " +mode)


    if(mode == "tcpreplay"):
        send_packets_tcpreplay(packetsFiltered,dict_source,client,location,savename,save,maxRange,verbose,args.listoflists)
    elif(mode == "scapy"):
        send_packets_scapy(packetsFiltered,dict_source,client,location,savename,save,maxRange,verbose,args.listoflists)
    elif(mode == "pingnetwork"):
        send_packets_scapy_ping(packetsFiltered,dict_source,client,location,savename,save,maxRange,verbose)

    utils.kill_containers(client)


def send_packets_tcpreplay(packets, dict_source:dict, client,location,savename,save,maxRange,verbose,optimized=False):
    firstKey = str(list(dict_source.keys())[0])
    if(save):
        client.containers.get(firstKey).exec_run("tcpdump -i eth0 -c " + str(maxRange)+" -w "+savename,detach=True)

    if(optimized):
        baseTime = time.time()
        inumerator = 0
        list_of_lists = utils.SplitIntoMultipleList(packets)
        for packs in list_of_lists:
            if(len(packs) <1):
                continue
            cont = client.containers.get(packs[0]["IP"].src)
            wrpcap(filename="packets.pcap",pkt=packs)
            utils.copy_to(location+"/packets.pcap", str(packs[0]["IP"].src)+":/usr/src/app/packets.pcap", client)
            answer = cont.exec_run("tcpreplay -i eth0 /usr/src/app/packets.pcap")
            if(verbose):
                answer = answer.output.decode("utf-8")
                inumerator += len(packs)
            else:
                for pack in packs:
                    answer = "No. " + str(inumerator) + ": " + str(pack.summary())
                    inumerator += 1
            utils.log(answer)
            if(inumerator >= maxRange):
                break
        endTime = time.time()
        utils.log("Time: " + str(endTime-baseTime))
        utils.log("Packets: " + str(maxRange))
        utils.log("Optimized :" + str(optimized))
        utils.log("Method: tcpreplay")
    else:
        baseTime = time.time()
        for i in range(maxRange):
            pack = packets[i]
            cont = client.containers.get(pack["IP"].src)
            wrpcap(filename="packets.pcap",pkt=pack)
            utils.copy_to(location+"/packets.pcap", str(pack["IP"].src)+":/usr/src/app/packets.pcap", client)
            answer = cont.exec_run("tcpreplay -i eth0 /usr/src/app/packets.pcap")
            if(verbose):
                answer = answer.output.decode("utf-8")
            else:
                answer = "No. " + str(i) + ": " + str(pack.summary())
            utils.log(answer)
        endTime = time.time()
        utils.log("Time: " + str(endTime-baseTime))
        utils.log("Packets: " + str(maxRange))
        utils.log("Optimized :" + str(optimized))
        utils.log("GUI: " +str(False))
        utils.log("Method: tcpreplay")
    utils.copy_from(save,savename,location,client,firstKey)



def send_packets_scapy(packets, dict_source, client,location,savepath,save,maxRange,verbose,optimized=False):
    firstKey = str(list(dict_source.keys())[0])
    if(save):
        client.containers.get(firstKey).exec_run("tcpdump -i eth0 -c " + str(maxRange)+" -w "+savepath,detach=True)

    for key in dict_source:
        cont = client.containers.get(key)
        utils.copy_to(location+"/scapySend.py", str(key)+":/usr/src/app/scapySend.py", client)

    if(optimized):
        baseTime = time.time()
        inumerator = 0
        list_of_lists = utils.SplitIntoMultipleList(packets)
        for packs in list_of_lists:
            if(len(packs) <1):
                continue
            cont = client.containers.get(packs[0]["IP"].src)
            with open(location+"/packets.p", 'wb') as f:
                pickle.dump(packs, f)
            utils.copy_to(location+"/packets.p", str(packs[0]["IP"].src)+":/usr/src/app/packets.p", client)
            answer = cont.exec_run("python3 scapySend.py -i eth0 -v " + str(int(verbose)) +  " -f packets.p")
            for i in range(len(packs)):
                utils.log(answer.output.decode("utf-8").replace("No. "+str(i), "No. " + str(inumerator)))
                inumerator += 1
            if(inumerator >= maxRange):
                break
        endTime = time.time()
        utils.log("Time: " + str(endTime-baseTime))
        utils.log("Packets: " + str(maxRange))
        utils.log("Optimized :" + str(optimized))
        utils.log("Method: scapy")
            
    else:
        baseTime = time.time()
        for i in range(maxRange):
            pack = packets[i]
            cont = client.containers.get(pack["IP"].src)
            with open(location+"/packets.p", 'wb') as f:
                pickle.dump(pack, f)
            utils.copy_to(location+"/packets.p", str(pack["IP"].src)+":/usr/src/app/packets.p", client)
            answer = cont.exec_run("python3 scapySend.py -i eth0 -v " + str(int(verbose)) +  " -f packets.p")
            utils.log(answer.output.decode("utf-8").replace("No. X", "No. " + str(i)))
        endTime = time.time()
        utils.log("Time: " + str(endTime-baseTime))
        utils.log("Packets: " + str(maxRange))
        utils.log("Optimized :" + str(optimized))
        utils.log("GUI: " +str(False))
        utils.log("Method: scapy")
    utils.copy_from(save,savepath,location,client,firstKey)

#endregion 

#region ping functions
def send_packets_scapy_ping(packets, dict_source, client,location,savepath,save,maxRange,verbose):
    # general idea:
    # 1. create a second network, one more container and connect every container to the second network
    # 2. start client.py in every container but the server
    # 3. start server.py in the server container with the right args
    

    if(save):
        client.containers.get(str(list(dict_source.keys())[0])).exec_run("tcpdump -i eth0 -c " + str(maxRange)+" -w "+savepath,detach=True)
    ping_location = location + "/pingNetwork"
    second_network_name = "secondary"
    create_second_network(client, ping_location,second_network_name,dict_source,packets,maxRange,location)

    utils.copy_from(save,savepath,location,client,str(list(dict_source.keys())[0]))


def create_second_network(client, ping_location,secondary_network,dict_source,packets,max_range,location):
    # hard coded path names
    client_py = "/client.py"
    server_py = "server.py"
    server_dockerfile = "server.Dockerfile"
    server_tag = "server"
    server_subnet = "240.0.0.0/24" # subnet that SHOULD NEVER appear in a pcap file...officially...
    server_name = utils.get_unique_ip(dict_source)
    if(server_name == "-1" or server_name == None or server_name == ""):
        raise Exception("No valid IP found for second network")
    packets_filename = "packets.p"
    with open(ping_location + "/"+ packets_filename, 'wb') as f:
        pickle.dump(packets, f)
    # build image
    client.images.build(path=ping_location, dockerfile=server_dockerfile, tag=server_tag)
    # create network (fake object called server_network, as it does not actually work)
    server_network = create_Network(secondary_network,server_subnet,client)
    container = client.containers.run(server_tag, detach=True, network=secondary_network, name=server_name, tty=True, stdout = sys.stdout, stdin_open=True, privileged  = True,command="tail -f /dev/null")
    container.exec_run("ip addr add " + server_name + "/24 dev eth0")
    container.exec_run("ip link set dev eth0 up")
    for key in dict_source:
        client_container = client.containers.get(key)
        client_ip = server_name.split(".")[0:3]
        client_ip.append(str(key).split(".")[-1])
        client_ip = ".".join(client_ip)
        utils.log("Client IP : " + client_ip)
        client.networks.get(secondary_network).connect(client_container,ipv4_address=client_ip)
        # client_container.exec_run("ip addr add " + client_ip + "/24 dev eth1")
        # client_container.exec_run("ip link set dev eth1 up")
        utils.copy_to(ping_location + client_py, key + ":/usr/src/app/client.py", client)
        utils.copy_to(ping_location + "/"+packets_filename, key + ":/usr/src/app/"+packets_filename, client)
    # now we have to wait for the network to be created
    sleep(1)
    for key in dict_source:
        client_container = client.containers.get(key)
        client_container.exec_run("python3 client.py "+"-f " + packets_filename,detach=True)

  
    utils.copy_to(ping_location + "/"+packets_filename, server_name + ":/usr/src/app/"+packets_filename, client)
    answer = container.exec_run("python3 -u server.py -i eth0 -f "+packets_filename + " -c " + str(max_range) + " -s "+ server_name,stream = True,detach=True)

    print_container_logs(container,client,location,max_range)

def print_container_logs(container,client,location,max_range):
    baseTime = time.time()
    reference = dict()
    indexer = 0 
    sleep(20)  
    while(True):
        utils.copy_from(True,"jsonLog.json",location,client,container.name)
        # check if jsonLog.tar exists
        if(not os.path.exists(location + "/jsonLog.json")):
            sleep(1)
            continue
        with open(location + "/jsonLog.json") as json_file:
            # check if file is empty
            if(os.stat(location + "/jsonLog.json").st_size == 0):
                sleep(1)
                json_file.close()
                continue
                
            data = json.load(json_file)
            json_file.close()
        # go through the keys of data starting from indexer
        data = data["Packets"]
        keys = list(data.keys())
        counter = 0
        for i in range(indexer,len(keys)):
            key = keys[i]
            print("No. " + str(key) + ": " + str(data[str(i)]["Summary"]))
            print("Time needed to send: " + str(data[str(i)]["Exec Time"]) + " seconds")
            print("Length of packet: " + str(data[str(i)]["Length"]) + " bytes")
            print("Datarate: " + str(data[str(i)]["Datarate"]) + " bytes/s")
            counter += 1
        indexer += counter
        if(indexer >= max_range):
            break
    endTime = time.time()
    utils.log("Time: " + str(endTime-baseTime))
    utils.log("Packets: " + str(max_range))
    utils.log("GUI: " +str(False))
    utils.log("Method: pingNetwork")       


#endregion 


#region util
def get_tcpdump(savepath,location,client,container):
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
        print(e)
        return 1






def get_path():
    path = __file__
    path = path.replace("\\","/")
    path = path.split("/")[:-1]
    path = "/".join(path)
    return path





def clean_args(args):
    #pcap
    if(args.pcap == None):
        args.pcap = "fullTCP.pcap"
    #docker
    if(args.docker == None):
        args.docker = 0
    if(args.docker > 1 or args.docker < 0):
        args.docker = 1
    #savepath
    if(args.savepath == None):
        args.savepath = "tcpdump.pcap"
    #filter
    if(args.filter == None): # currently default to tcp
        args.filter = "TCP"
    if(args.filter.lower() != "tcp" or args.filter.lower() != "udp"):
        args.filter = "TCP"
    else:
        args.filter = args.filter.upper()
    #gui
    if(args.gui == None):
        args.gui = 0
    if(args.gui > 1 or args.gui < 0):
        args.gui = 1
    #mode
    if(args.mode == None):
        args.mode = "tcpreplay"
    elif(args.mode.lower() != "tcpreplay" and args.mode.lower() != "scapy" and args.mode.lower() != "pingnetwork"):
        args.mode = "tcpreplay"
    else:
        args.mode = args.mode.lower()
    #onlygui
    if(args.onlygui == None):
        args.onlygui = 0
    if(args.onlygui > 1 or args.onlygui < 0):
        args.onlygui = 1
    if(args.verbose < 0 or args.verbose > 1):
        args.verbose = 1
    #dump
    if(args.dump == None):
        args.dump = 0
    if(args.dump > 1 or args.dump < 0):
        args.dump = 1
    #count
    if(args.count == None):
        args.count = -1

    if(args.count < 1):
        args.count = -1

    # listoflists (optimization)
    if(args.listoflists == None):
        args.listoflists = 0
    elif((args.listoflists > 1 or args.listoflists < 0) and (args.mode == "scapy" or args.mode == "tcpreplay")):
        args.listoflists = 1
    elif(args.listoflists == 1 and (args.mode == "tcpreplay" or args.mode == "scapy")):
        args.listoflists = 1
    else:
        args.listoflists = 0

    return args

    
def init_sys_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap",type=str, help="pcap file to read")
    parser.add_argument("-d","--docker",type = int,help = "only generate the docker network without sending packets")
    parser.add_argument("-sp","--savepath",type = str,help = "name to save the tcpdump as")
    parser.add_argument("-f","--filter",type = str,help = "filter for the original pcap file (only tcp and udp)")
    parser.add_argument("-g", "--gui",type = int, help="show the gui (currently not supported)")
    parser.add_argument("-m", "--mode",type = str, help="mode of the program (tcpreplay,scapy,pingNetwork)")
    parser.add_argument("-og","--onlygui",type = int,help = "only show the gui")
    parser.add_argument("-td","--dump",type = int,help = "record with tcpdump (saved in the same folder if -sp not used, only saves the first containers pcap)")
    parser.add_argument("-c","--count",type = int,help = "number of packets to send") 
    parser.add_argument("-v","--verbose",type=int,help="verbose mode (0 = off, 1 = on)",default=0)
    parser.add_argument("-l","--listoflists",type=int,help="list of lists to use for the scapy/tcpmode mode, better performance")
    parser.add_argument("-ip","--ip",type=str,help="ip address of the docker network")
    return parser


#endregion



























if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            utils.kill_containers()
            sys.exit(130)
        except SystemExit:
            os._exit(130)











    # try:
    #     plat = platform.system()
    #     path = location + "/" +  savepath
    #     cmd = ""
    #     print(savepath)
    #     print(path)
    #     if(plat == "Windows"):
    #         cmd = "cmd /c docker cp " + container + ":/usr/src/app/"+savepath +" " + path
    #         print(cmd)
    #     elif(plat == "Linux"):
    #         cmd = "docker cp " + container + ":/usr/src/app/"+savepath +" " + path
    #     elif(plat == "Darwin"):
    #         cmd = "docker cp " + container + ":/usr/src/app/"+savepath +" " + path
    #     else:
    #         print("Platform not supported")
    #         return
        
    #     if(cmd != ""):
    #         error_code = os.system(cmd)
    #         if(error_code != 0):
    #             # Throw exception
    #             return 1
    #         else:
    #             return 0
    # except Exception as e:
    #     #print(e)
    #     return 1