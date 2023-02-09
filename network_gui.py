import sys
from PySide2.QtWidgets import QShortcut,QGraphicsEllipseItem,QGraphicsLineItem,QAbstractItemView, QApplication, QWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QHBoxLayout, QGraphicsView, QGraphicsScene, QSizePolicy
from PySide2.QtGui import QPainter,QKeySequence
from PySide2.QtCore import Qt, QSize,QTimer,QPointF,QPoint

from PySide2.QtWidgets import QHeaderView
from PySide2.QtGui import QPalette, QColor,QPen,QBrush,QFont,QPainter,QPixmap
import argparse
import os
import random
import math
from scapy.all import *
import utils
from time import sleep
import pickle
import json

# # CLI Arguments
# - p (pcap) -> path to tcpfile
# - d (docker) -> only make the network but nothing else
# - sp (savepath) -> path to savefile
# - f (filter) -> filter the pcap for a certain protocol
# - g (gui) -> give a GUI where you make the window with the information
# - m (mode) -> lets have only "tcpreplay","scapySend","ping network"
# - og (onlygui) -> only gui, no actual docker network
# - td (dump) -> create a tcpdump
# - c (count) -> how many packages to send


class MyWidget(QWidget):
    def __init__(self,packets,dict_source,client,location,args):
        super().__init__()
        self.packets = packets
        self.dict_source = dict_source
        self.client = client
        self.location = location
        self.args = args
        self.keylist = list(self.dict_source.keys())
        self.iniated_network = False
        self.edge_to_redraw = None
        self.indexer = 0 # index to keep track of the packets
        self.initUI()
        self.basetime = time.time()
        self.optimized = True if (args.listoflists == 1 and (self.args.mode == "tcpreplay" or self.args.mode == "scapy")) else False
        self.listoflists = [] if self.optimized == False else utils.SplitIntoMultipleList(self.packets)
        self.rownumber = 0
        self.lastNumber = 0
        self.startTimining:float = 0
        self.listIndexer = 0
        stopShortcut = QShortcut(QKeySequence("S"), self)
        stopShortcut.activated.connect(self.stop_clicked)
        startShortcut = QShortcut(QKeySequence("R"), self)
        startShortcut.activated.connect(self.start_clicked)

    def initUI(self):
        self.drawing_area = QGraphicsView(self)
        self.drawing_area.setRenderHint(QPainter.Antialiasing)
        self.drawing_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.drawing_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.drawing_area.setScene(QGraphicsScene(self))
        self.drawing_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.drawing_area.setMinimumSize(QSize(800, 0))



        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(['No.','Time', 'Source', 'Destination', 'Length', 'Exec Time'])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.table.setMinimumSize(QSize(480, 0))

        

        random.seed(13091998)
        layout = QHBoxLayout(self)
        layout.addWidget(self.drawing_area)
        layout.addWidget(self.table)

        self.setLayout(layout)
        self.draw_network()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.updateNetwork)
        self.limiter = 100
        self.timer.start(self.limiter)

        self.setGeometry(200, 200, 1280, 720)
        self.setWindowTitle('Modeli')
        self.show()


    def stop_clicked(self):
        self.timer.stop()
        

    def start_clicked(self):
        self.timer.start(self.limiter)

    def draw_network(self):
        # actual height of 800x720 was not working so i made it smaller
        width = 700
        height = 600
        

        self.nodes = dict()
        for node in self.keylist:
            print("Key: " + str(node))
            self.nodes[str(node)] = Node(label=str(node))

        self.edgelist = set()
        for packet in self.packets:
            str_tuple = (str(packet["IP"].src), str(packet["IP"].dst))
            str2_tuple = (str(packet["IP"].dst), str(packet["IP"].src))
            if(str2_tuple in self.edgelist or str_tuple in self.edgelist):
                continue
            self.edgelist.add(str_tuple)
        self.edgelist = list(self.edgelist)
        
        
        

        

        
        
        print(len(self.edgelist))
        self.fruchterman_reingold(width, height)

        self.edge_to_line = dict()

        self.radius = 20
        for edge in self.edgelist:
            line = self.drawing_area.scene().addLine(self.nodes[edge[0]].x, self.nodes[edge[0]].y, self.nodes[edge[1]].x, self.nodes[edge[1]].y,pen=QPen(QColor(255, 255, 255),2))
            # self.nodes[edge[0]].setItem(line)
            self.edge_to_line[edge] = line

        for node in self.nodes.values():
            ellipse = self.drawing_area.scene().addEllipse(node.x - self.radius, node.y - self.radius, self.radius*2, self.radius*2,brush=QBrush(QColor(0, 0, 255)))
            text = self.drawing_area.scene().addSimpleText(node.label,font=QFont("Times", 10, QFont.Bold))
            # set text under the ellipse
            text.setPos(node.x - self.radius*2, node.y + self.radius)
            self.nodes[node.label].setItem(ellipse)
        

    def fruchterman_reingold(self, width, height):
        random.seed(1309)
        for node in self.nodes.values():

            node.x = random.randint(0, width)
            node.y = random.randint(0, height)

        temperature = width / 10

        num_iterations = 1000

        attractive_mult = 2
        repulsive_mult = 1

        repulsive_force = lambda distance: width**2 / (distance/repulsive_mult) if distance > 0 else 0
        attractive_force = lambda distance: distance**2 / (width/attractive_mult) if distance > 0 else 0
        

        for i in range(num_iterations):
            # Calculate the forces acting on each node
            for node in self.nodes.values():
                node.dx = 0
                node.dy = 0
                for other in self.nodes.values():
                    if node != other:
                        # Calculate the distance between the nodes
                        dx = node.x - other.x
                        dy = node.y - other.y
                        distance = math.sqrt(dx**2 + dy**2) if math.sqrt(dx**2 + dy**2) > 0 else 0.01
                        # Calculate the repulsive force between the nodes
                        force = repulsive_force(distance)
                        node.dx += dx / distance * force
                        node.dy += dy / distance * force

            for edge in self.edgelist:
                # Calculate the attractive force between the nodes connected by the edge
                node1 = self.nodes[edge[0]]
                node2 = self.nodes[edge[1]]
                dx = node1.x - node2.x
                dy = node1.y - node2.y
                distance = math.sqrt(dx**2 + dy**2) if math.sqrt(dx**2 + dy**2) > 0 else 0.01
                force = attractive_force(distance)
                node1.dx -= dx / distance * force 
                node1.dy -= dy / distance * force
                node2.dx += dx / distance * force
                node2.dy += dy / distance * force

            for node in self.nodes.values():
                temperature *= 0.99
                # Calculate the displacement of the node
                dx = math.sqrt(node.dx**2 + node.dy**2) / temperature
                # Update the position of the node
                node.x += node.dx / dx if dx > 0 else 0
                node.y += node.dy / dx if dx > 0 else 0
                # Keep the node within the bounds of the graphics scene
                node.x = max(0, min(node.x, width))
                node.y = max(0, min(node.y, height))

    # call every n-th millisecond
    def updateNetwork(self):
        if(self.startTimining == 0):
            self.startTimining = time.time()
        self.savename = self.args.savepath if self.args.savepath != "" else "save.pcap"
        self.packets = self.packets if self.args.filter == "" else utils.filter_packets(self.packets,self.args.filter)
        self.args.count = self.args.count if self.args.count > 0 else len(self.packets)


        if(self.args.onlygui):
            self.onlygui()
        elif(self.args.mode == "tcpreplay"):
            self.tcpreplay()
        elif(self.args.mode == "scapy"):
            self.scapy()
        elif(self.args.mode == "pingnetwork"):
            self.pingnetwork()


    def tcpreplay(self):
        if(self.edge_to_redraw != None):
            delLine = self.edge_to_redraw
            line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 255, 255),2))
            self.edge_to_redraw = line
            self.drawing_area.scene().removeItem(delLine)
            rect = line.boundingRect().toRect()
            line.setZValue(-1)
            self.update(rect)



        save = True if self.args.dump == 1 else False
        firstKey = list(self.nodes.keys())[0]
        if(save == True and self.iniated_network == False):
            self.iniated_network = True
            self.client.containers.get(firstKey).exec_run("tcpdump -i eth0 -c " + str(self.args.count)+" -w "+str(self.savename),detach=True)
        starttime = time.time() - self.basetime 

        if(self.indexer >= self.args.count or self.listIndexer >= self.args.count):
            utils.copy_from(save,self.savename,self.location,self.client,firstKey)
            endTime = time.time()
            utils.log("Time: " + str(time.time()-self.startTimining))
            utils.log("Packets: " + str(self.args.count))
            utils.log("Optimized: " + str(self.optimized))
            utils.log("GUI: " + str(self.args.gui))
            utils.log("Method: tcpreplay")
            self.timer.stop()
            return
        
        if(self.optimized == True):
            packs = self.listoflists[self.indexer]
            if(len(packs) < 1):
                self.indexer += 1
                return
                
            cont = self.client.containers.get(packs[0]["IP"].src)
            wrpcap(filename="packets.pcap",pkt=packs)
            utils.copy_to(self.location + "/packets.pcap",str(packs[0]["IP"].src)+":/usr/src/app/packets.pcap",self.client)
            cont.exec_run("tcpreplay -i eth0 /usr/src/app/packets.pcap")
            self.listIndexer += len(packs)

        pack = self.packets[self.indexer] if self.optimized == False else self.listoflists[self.indexer][0]
        if(self.optimized == False):
            cont = self.client.containers.get(pack["IP"].src)
            wrpcap(filename="packets.pcap",pkt=pack)
            utils.copy_to(self.location + "/packets.pcap",str(pack["IP"].src)+":/usr/src/app/packets.pcap",self.client)
            cont.exec_run("tcpreplay -i eth0 /usr/src/app/packets.pcap")
        # find the right edge where it connects src and dst, and make it red

        edge = (pack["IP"].src,pack["IP"].dst) if (pack["IP"].src,pack["IP"].dst) in self.edge_to_line else (pack["IP"].dst,pack["IP"].src)
        delLine = self.edge_to_line[edge]
        line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 0, 0),2))
        self.edge_to_line[edge] = line
        self.drawing_area.scene().removeItem(delLine)
        rect = line.boundingRect().toRect()
        line.setZValue(-1)
        

        self.update(rect)
        self.edge_to_redraw = self.edge_to_line[edge]

        
        
       
        toSend = pack if self.optimized == False else self.listoflists[self.indexer]
        self.populate_table(starttime,toSend)
        self.indexer = self.indexer + 1
        # self.edge_to_line[edge].setPen(QPen(Qt.white, 2, Qt.SolidLine))
        # self.repaint(self.edge_to_line[edge].boundingRect().toRect())
    
    

    def scapy(self):
        if(self.edge_to_redraw != None):
            delLine = self.edge_to_redraw
            line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 255, 255),2))
            self.edge_to_redraw = line
            self.drawing_area.scene().removeItem(delLine)
            rect = line.boundingRect().toRect()
            line.setZValue(-1)
            self.update(rect)



        save = True if self.args.dump == 1 else False
        firstKey = list(self.nodes.keys())[0]
        if(self.iniated_network == False):
            for key in self.dict_source:
                utils.copy_to(self.location + "/scapySend.py",str(key)+":/usr/src/app/scapySend.py",self.client)
            if(save is False):
                self.iniated_network = True

        if(save == True and self.iniated_network == False):
            self.iniated_network = True
            self.client.containers.get(firstKey).exec_run("tcpdump -i eth0 -c " + str(self.args.count)+" -w "+str(self.savename),detach=True)

        starttime = time.time() - self.basetime 

        if(self.indexer >= self.args.count or self.listIndexer >= self.args.count):
            utils.copy_from(save,self.savename,self.location,self.client,firstKey)
            endTime = time.time()
            utils.log("Time: " + str(time.time()-self.startTimining))
            utils.log("Packets: " + str(self.args.count))
            utils.log("Optimized: " + str(self.optimized))
            utils.log("GUI: " + str(self.args.gui))
            utils.log("Method: scapy")
            self.timer.stop()
            return
        
        if(self.optimized == True):
            packs = self.listoflists[self.indexer]
            if(len(packs) < 1):
                self.indexer += 1
                return


            cont = self.client.containers.get(packs[0]["IP"].src)
            with open(self.location+"/packets.p", 'wb') as f:
                pickle.dump(packs, f)
            utils.copy_to(self.location + "/packets.p",str(packs[0]["IP"].src)+":/usr/src/app/packets.p",self.client)
            cont.exec_run("python3 scapySend.py -i eth0 -v " + str(int(False)) +  " -f packets.p")
            self.listIndexer += len(packs)

        pack = self.packets[self.indexer] if self.optimized == False else self.listoflists[self.indexer][0]
        if(self.optimized == False):
            cont = self.client.containers.get(pack["IP"].src)
            with open(self.location+"/packets.p", 'wb') as f:
                pickle.dump(pack, f)
            utils.copy_to(self.location + "/packets.p",str(pack["IP"].src)+":/usr/src/app/packets.p",self.client)
            cont.exec_run("python3 scapySend.py -i eth0 -v " + str(int(False)) +  " -f packets.p")
        # find the right edge where it connects src and dst, and make it red

        edge = (pack["IP"].src,pack["IP"].dst) if (pack["IP"].src,pack["IP"].dst) in self.edge_to_line else (pack["IP"].dst,pack["IP"].src)
        delLine = self.edge_to_line[edge]
        line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 0, 0),2))
        self.edge_to_line[edge] = line
        self.drawing_area.scene().removeItem(delLine)
        rect = line.boundingRect().toRect()
        line.setZValue(-1)
        

        self.update(rect)
        self.edge_to_redraw = self.edge_to_line[edge]

        
        
       
        toSend = pack if self.optimized == False else self.listoflists[self.indexer]
        self.populate_table(starttime,toSend)
        self.indexer = self.indexer + 1
    
    def pingnetwork(self):
        save = True if self.args.dump == 1 else False
        if(self.iniated_network == False):
            self.create_second_net()
        
        pingContainer = utils.get_unique_ip(self.dict_source)
        firstKey = list(self.nodes.keys())[0]
        # now we read the logs from the ping container and get the information from there
        # we also have to somehow keep track of how many packets have been sent
        # cont = self.client.containers.get(pingContainer)
        try:
            utils.copy_from(True,"jsonLog.json",self.location,self.client,pingContainer)
        except Exception as e:
            return
        data = dict()
        if(not os.path.exists(self.location + "/jsonLog.json")):
            sleep(1)
            return
        try:
            with open(self.location+"/jsonLog.json", 'rb') as f:
                if(os.stat(self.location + "/jsonLog.json").st_size == 0):
                    sleep(1)
                    f.close()
                    return
                data = json.load(f)
                f.close()
        except Exception as e:
            return
        
        data = data["Packets"]
        keys = list(data.keys())
        
        for i in range(self.indexer,len(keys)):
            key = keys[i]
            jsonPacket = data[key]
            if(self.edge_to_redraw != None):
                delLine = self.edge_to_redraw
                line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 255, 255),2))
                self.edge_to_redraw = line
                self.drawing_area.scene().removeItem(delLine)
                rect = line.boundingRect().toRect()
                line.setZValue(-1)
                self.update(rect)
            pack = self.packets[i]
            edge = (pack["IP"].src,pack["IP"].dst) if (pack["IP"].src,pack["IP"].dst) in self.edge_to_line else (pack["IP"].dst,pack["IP"].src)
            delLine = self.edge_to_line[edge]
            line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 0, 0),2))
            self.edge_to_line[edge] = line
            self.drawing_area.scene().removeItem(delLine)
            rect = line.boundingRect().toRect()
            line.setZValue(-1)
            self.update(rect)
            self.edge_to_redraw = self.edge_to_line[edge]
            self.populate_table_ping(jsonPacket)
        self.indexer = self.indexer + (len(keys) - self.indexer)
        if(self.indexer >= self.args.count):
            self.timer.stop()
            utils.copy_from(save,self.savename,self.location,self.client,firstKey)
            endTime = time.time()
            utils.log("Time: " + str(time.time()-self.startTimining))
            utils.log("Packets: " + str(self.args.count))
            utils.log("Optimized: " + str(self.optimized))
            utils.log("GUI: " + str(self.args.gui))
            utils.log("Method: pingNetwork")
            return
        

            


    
    def populate_table_ping(self,jsonPacket):
        numString = str(self.rownumber)
        timeString = str(round(float(jsonPacket["Time"]),3))
        timeNeededString = str(round(float(jsonPacket["Exec Time"]),3))
        lengthString = str(jsonPacket["Length"])
        srcString = str(jsonPacket["Source"])
        dstString = str(jsonPacket["Destination"])
        self.table.insertRow(self.rownumber)
        self.table.setItem(self.rownumber,0,QTableWidgetItem(numString))
        self.table.setItem(self.rownumber,1,QTableWidgetItem(timeString))
        self.table.setItem(self.rownumber,2,QTableWidgetItem(srcString))
        self.table.setItem(self.rownumber,3,QTableWidgetItem(dstString))
        self.table.setItem(self.rownumber,4,QTableWidgetItem(lengthString))
        self.table.setItem(self.rownumber,5,QTableWidgetItem(timeNeededString))
        self.rownumber = self.rownumber + 1
        self.table.scrollToBottom()

    def populate_table(self,starttime,pack):
        if(type(pack) == list):
            for p in pack:
                self.populate_table(starttime,p)
            return
        numString = str(self.rownumber)
        # round all times to 3 decimal places
        timeString = str(round(starttime,3))
        timeNeededString = str(round((time.time()-self.basetime)- starttime,3))
        lengthString  = str(len(bytes(pack)))
        srcString = str(pack["IP"].src)
        dstString = str(pack["IP"].dst)
        self.table.insertRow(self.rownumber)
        self.table.setItem(self.rownumber,0,QTableWidgetItem(numString))
        self.table.setItem(self.rownumber,1,QTableWidgetItem(timeString))
        self.table.setItem(self.rownumber,2,QTableWidgetItem(srcString))
        self.table.setItem(self.rownumber,3,QTableWidgetItem(dstString))
        self.table.setItem(self.rownumber,4,QTableWidgetItem(lengthString))
        self.table.setItem(self.rownumber,5,QTableWidgetItem(timeNeededString))
        self.rownumber += 1
        self.table.scrollToBottom()
        

    def create_second_net(self):
        save = True if self.args.dump == 1 else False
        if(self.iniated_network == False):
            ping_location = self.location + "/pingNetwork"
            second_network_name = "secondary"
            utils.create_second_network(self.client,ping_location,second_network_name,self.dict_source,self.packets,len(self.packets))
            self.iniated_network = True
            if(save):
                self.client.containers.get(str(list(self.dict_source.keys())[0])).exec_run("tcpdump -i eth0 -c " + str(self.args.count)+" -w "+str(self.savename),detach=True)
        
        
            
    def onlygui(self):
        print("Hi")
        
class Node:
    def __init__(self, label, x=0, y=0, dx=0, dy=0, item = object):
        self.label = label
        self.x = x
        self.y = y
        self.dx = dx
        self.dy = dy
        self.item = item
    
    def setItem(self, item):
        self.item = item
    
    def getItem(self): # just to be save
        return self.item
    

    

