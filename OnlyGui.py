#region processminingstuff
import csv

from datetime import date, datetime
import pm4py


import pandas as pd
#endregion
import sys
from PySide2.QtWidgets import QComboBox,QMessageBox,QShortcut,QFileDialog,QDialog,QProgressDialog,QAbstractItemView,QSplitter, QApplication, QWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QGraphicsView, QGraphicsScene, QSizePolicy,QPushButton,QGridLayout
from PySide2.QtGui import QPainter,QKeySequence
from PySide2.QtCore import Qt, QSize,QTimer

from PySide2.QtWidgets import QHeaderView
from PySide2.QtGui import QPalette, QColor,QPen,QBrush,QFont,QPainter,QCloseEvent

import random
import math
from scapy.all import *
import utils
import utils
import docker
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


class GUI(QWidget):
    def __init__(self,location,args,packets = None,dict_source = None):
        super().__init__()
        self.packets = packets
        self.dict_source = dict_source
        self.location = location
        self.args = args
        self.keylist = list(self.dict_source.keys()) if self.dict_source != None else None
        self.network_drawn = False
        self.initUI()
        self.import_button.clicked.connect(self.import_clicked)
        self.traffic_button.clicked.connect(self.traffic_clicked)
        self.simulation_button.clicked.connect(self.simulation_clicked)
        self.process_button.clicked.connect(self.process_clicked)
        self.docker_button.clicked.connect(self.docker_clicked)
        self.limiter = -1
        self.timer = QTimer()
        stopShortcut = QShortcut(QKeySequence("S"), self)
        stopShortcut.activated.connect(self.stop_clicked)
        startShortcut = QShortcut(QKeySequence("R"), self)
        startShortcut.activated.connect(self.start_clicked)





    def closeEvent(self,event: QCloseEvent):
        try:
            client = docker.from_env()
            utils.kill_containers(client)
        except:
            pass
        event.accept()

    def initUI(self):

        self.import_button = QPushButton('Import pcap', self)
        self.traffic_button = QPushButton('Analyze Traffic', self)
        self.simulation_button = QPushButton('Start Simulation', self)
        self.process_button = QPushButton('Mine Processes', self)
        self.docker_button = QPushButton('Create Docker', self)

        self.drawing_area = QGraphicsView(self)
        self.drawing_area.setRenderHint(QPainter.Antialiasing)
        self.drawing_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.drawing_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.drawing_area.setScene(QGraphicsScene(self))
        self.drawing_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.drawing_area.setMinimumSize(QSize(800, 100))  # modified height

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
        self.table.setMinimumSize(QSize(480, 100))  # modified height
        self.combo_box_1 = QComboBox(self)
        self.combo_box_2 = QComboBox(self)
        self.combo_box_1.addItems(["Process Tree","BPMN","Petri Net (Alpha)","Petri Net (Alpha Plus)","Petri Net (Heuristics)","Petri Net (Inductive)","Dfg","Heuristic Net"])
        self.combo_box_2.addItems(["TCP","UDP"])

        layout = QGridLayout(self)
        layout.addWidget(self.import_button, 0, 0)
        layout.addWidget(self.traffic_button, 0, 1)
        layout.addWidget(self.simulation_button, 0, 2)
        layout.addWidget(self.process_button, 0, 3)
        layout.addWidget(self.docker_button, 0, 6)
        layout.addWidget(self.combo_box_1, 0, 4)
        layout.addWidget(self.combo_box_2, 0, 5)

        splitter = QSplitter(self)
        splitter.addWidget(self.drawing_area)
        splitter.addWidget(self.table)
        splitter.setSizes([700, 300])  

        # Add the splitter widget to the layout
        layout.addWidget(splitter, 1, 0, 1, 7)  # span over 7 columns

        self.setLayout(layout)
        if(self.packets != None):
            self.draw_network()

        self.update_buttons()
        self.setGeometry(200, 200, 1280, 720)
        self.setWindowTitle('Modeli')
        self.show()
    #region buttons
    def stop_clicked(self):
        if(self.limiter < 0 ):
            return
        self.timer.stop()
        self.update_buttons()

    def start_clicked(self):
        if(self.limiter < 0 ):
            return
        self.timer.start(self.limiter)
        self.update_buttons()

    def import_clicked(self):
        # open a file dialog
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.ExistingFile)
        dialog.setNameFilter("Pcap (*.pcap)")
        file_name = ""
        if dialog.exec_():
            file_name = dialog.selectedFiles()[0]
        if(file_name != ""):
            packets,dict_source = utils.read_pcap(file_name)
            self.packets = packets
            self.dict_source = dict_source
            self.keylist = list(self.dict_source.keys())
            self.draw_network()
            self.update_buttons()
            self.indexer = 0
            self.rownumber = 0
            # remove all rows from table
            self.table.setRowCount(0)
            

    def docker_clicked(self):
        client = None
        try:
            client = docker.from_env()
        except:
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Error")
            msg_box.setText("Docker is not installed or not running")
            msg_box.exec_()
            return
        sources = list(self.dict_source.keys()) if self.dict_source != None else []
        if(len(sources) == 0):
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Error")
            msg_box.setText("No Pcap file imported")
            msg_box.exec_()
            return
        try:
            netname = "OnlyGUINetwork"
            sub = self.args.ip
            if(sub == None):
                sub = utils.get_subnet(self.packets)
            utils.create_Network(netname,sub,client)
            image_name = "one.Dockerfile"
            utils.create_containers(self.dict_source,client,netname,image_name,self.location)
        except:
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Error")
            msg_box.setText("Error creating docker containers")
            msg_box.exec_()
            return

    def update_buttons(self):
        #get all buttons
        buttons = self.findChildren(QPushButton)
        for button in buttons:
            button.setEnabled(self.network_drawn)
        self.import_button.setEnabled(True)

    def traffic_clicked(self):
        data = dict()
        #protocols

        # get the gaps between the packets
        timestamps = [pkt.time for pkt in self.packets]
        timestamps.sort()
        gaps = [t2-t1 for t1,t2 in zip(timestamps[:-1],timestamps[1:])]

        min_gap = min(gaps)
        max_gap = max(gaps)
        avg_gap = sum(gaps)/len(gaps)
        data["Minimum Gap"] = min_gap
        data["Maximum Gap"] = max_gap
        data["Average Gap"] = avg_gap

        # size of the packets
        num_packets = len(self.packets)
        num_bytes = sum([len(pkt) for pkt in self.packets])

        min_size = min([len(pkt) for pkt in self.packets])
        max_size = max([len(pkt) for pkt in self.packets])
        avg_size = sum([len(pkt) for pkt in self.packets])/len(self.packets)
        data["Number of packets"] = num_packets
        data["Number of bytes"] = num_bytes
        data["Minimum Size"] = min_size
        data["Maximum Size"] = max_size
        data["Average Size"] = avg_size

        # throughput and the expected number of packets
        start_time = self.packets[0].time   # val
        end_time = self.packets[-1].time    # val
        duration = end_time - start_time    # val

        throughput = num_bytes/duration
        expected_packets = int((timestamps[-1]-timestamps[0])/avg_gap)
        packet_loss = round((expected_packets - len(self.packets))/expected_packets,0)
        data["Throughput"] = throughput
        data["Expected Packets"] = expected_packets
        data["Packet Loss"] = packet_loss



        devices = {}
        for pkt in self.packets:
            if(pkt.haslayer("Ether") and pkt.haslayer("IP")):
                src_mac = pkt["Ether"].src
                src_ip = pkt["IP"].src
                dst_mac = pkt["Ether"].dst
                dst_ip = pkt["IP"].dst
                devices[src_mac] = (src_ip,pkt.time)
                devices[dst_mac] = (dst_ip,pkt.time)

        counter = 0
        for mac,(ip,time) in devices.items():
            data["MAC Adress (IP Adress) No. " + str(counter)] = mac + " (" + ip + ")"
            counter += 1


        dialog = PerformanceMetricsDialog(data)
        dialog.exec_()

    def simulation_clicked(self):

        self.edge_to_redraw = None
        self.basetime = time.time()
        self.indexer = 0
        self.rownumber = 0
        self.limiter = 50
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.updateNetwork)
        self.timer.start(self.limiter)






    def updateNetwork(self):
        if(self.edge_to_redraw != None):
            delLine = self.edge_to_redraw
            line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 255, 255),2))
            self.edge_to_redraw = line
            self.drawing_area.scene().removeItem(delLine)
            rect = line.boundingRect().toRect()
            line.setZValue(-1)
            self.update(rect)

        timer = time.time()-self.basetime
        pack = self.packets[self.indexer]
        edge = (pack["IP"].src,pack["IP"].dst) if (pack["IP"].src,pack["IP"].dst) in self.edge_to_line else (pack["IP"].dst,pack["IP"].src)
        delLine = self.edge_to_line[edge]
        line = self.drawing_area.scene().addLine(delLine.line(),QPen(QColor(255, 0, 0),2))
        self.edge_to_line[edge] = line
        self.drawing_area.scene().removeItem(delLine)
        rect = line.boundingRect().toRect()
        line.setZValue(-1)


        self.update(rect)
        self.edge_to_redraw = self.edge_to_line[edge]
        self.indexer += 1
        self.populate_table(timer,pack)
        if(self.indexer == len(self.packets)):
            self.timer.stop()
            self.indexer = 0
            

    # mine processes if possible
    def process_clicked(self):
        #combobox



        event_log = []
        #value fo combo_box_1
        proc_min = self.combo_box_1.currentText()
        #value fo combo_box_2
        proto = self.combo_box_2.currentText()
        for packet in self.packets:
            if(packet.haslayer(proto) == False):
                pass
            # Extract the relevant information from the packet
            today =  date.today().strftime("%Y-%m-%d %H:%M:%S")
            utcTime = datetime.utcfromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
            event = {
                "case ID" : "1",
                "timestamp": utcTime,
                "source": packet["IP"].src,
                "destination": packet["IP"].dst,
                "action": "Send packet from " + packet["IP"].src + " to " + packet["IP"].dst,
                "date": today
            }
            # Add the event to the event log
            event_log.append(event)





        if(event_log == []):
            return
       # write eventlog to csv
        with open("eventlog.csv", "w") as f:
            writer = csv.DictWriter(f, fieldnames=event_log[0].keys())
            writer.writeheader()
            writer.writerows(event_log)
        dateparse = lambda dates: [datetime.strptime(d, '%Y-%m-%d %H:%M:%S').date() for d in dates]
        df = pd.read_csv("eventlog.csv",parse_dates = ["date","timestamp"],date_parser = dateparse,dtype={"case ID":str})
        # print all column types of df
        print(df.dtypes)
        if(proc_min == "BPMN"):
            processTree = pm4py.discover_process_tree_inductive(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            bpmn_model = pm4py.convert_to_bpmn(processTree)
            pm4py.view_bpmn(bpmn_model)
        elif(proc_min == "Process Tree"):
            processTree = pm4py.discover_process_tree_inductive(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            pm4py.view_process_tree(processTree)
        elif(proc_min == "Petri Net (Alpha)"):
            net,im,fm = pm4py.discover_petri_net_alpha(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            pm4py.view_petri_net(net,im,fm)
        elif(proc_min == "Petri Net (Alpha Plus)"):
            net,im,fm = pm4py.discover_petri_net_alpha_plus(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            pm4py.view_petri_net(net,im,fm)
        elif(proc_min == "Petri Net (Heuristics)"):
            net,im,fm = pm4py.discover_petri_net_heuristics(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            pm4py.view_petri_net(net,im,fm)
        elif(proc_min == "Petri Net (Inductive)"):
            net,im,fm = pm4py.discover_petri_net_inductive(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            pm4py.view_petri_net(net,im,fm)
        elif(proc_min == "Dfg"):
            dfg, start_activities, end_activities = pm4py.discover_dfg_typed(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            pm4py.view_dfg(dfg, start_activities, end_activities)
        elif(proc_min == "Heuristic Net"):
            map = pm4py.discover_heuristics_net(df,activity_key="action",timestamp_key="timestamp",case_id_key = "case ID")
            pm4py.view_heuristics_net(map)

      
    #endregion

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
        # scroll to bottom of table
        self.table.scrollToBottom()


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









        self.fruchterman_reingold(width, height)
        #clear scene
        self.drawing_area.scene().clear()
        self.edge_to_line = dict()

        self.radius = 20
        for edge in self.edgelist:
            line = self.drawing_area.scene().addLine(self.nodes[edge[0]].x, self.nodes[edge[0]].y, self.nodes[edge[1]].x, self.nodes[edge[1]].y,pen=QPen(QColor(255, 255, 255),2))
            self.edge_to_line[edge] = line

        for node in self.nodes.values():
            ellipse = self.drawing_area.scene().addEllipse(node.x - self.radius, node.y - self.radius, self.radius*2, self.radius*2,brush=QBrush(QColor(0, 0, 255)))
            text = self.drawing_area.scene().addSimpleText(node.label,font=QFont("Times", 10, QFont.Bold))
            # set text under the ellipse
            text.setPos(node.x - self.radius*2, node.y + self.radius)
            self.nodes[node.label].setItem(ellipse)

        self.network_drawn = True


    # find positions of the nodes that are the best
    def fruchterman_reingold(self, width, height):
        for node in self.nodes.values():

            node.x = random.randint(0, width)
            node.y = random.randint(0, height)

        temperature = width / 10

        num_iterations = 1000

        attractive_mult = 2
        repulsive_mult = 1

        repulsive_force = lambda distance: width**2 / (distance/repulsive_mult) if distance > 0 else 0
        attractive_force = lambda distance: distance**2 / (width/attractive_mult) if distance > 0 else 0
        progress_dialog = QProgressDialog("Processing...", "Cancel", 0, num_iterations, self)
        progress_dialog.setWindowModality(Qt.WindowModal)  # makes the dialog modal
        progress_dialog.setMinimumDuration(0)

        for i in range(num_iterations):
            progress_dialog.setValue(i)  # sets the progress value (0-100)
            progress_dialog.setLabelText(f'Processing {i}/100')  # sets the text shown
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
                dx = math.sqrt(node.dx**2 + node.dy**2) / temperature
                node.x += node.dx / dx if dx > 0 else 0
                node.y += node.dy / dx if dx > 0 else 0
                node.x = max(0, min(node.x, width))
                node.y = max(0, min(node.y, height))
            if progress_dialog.wasCanceled():
                break

        progress_dialog.close()

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



class PerformanceMetricsDialog(QDialog):


    def __init__(self,data:dict):
        super().__init__()
        self.data = data
        self.initUI()

    def initUI(self):
        self.table = QTableWidget(self)
        self.table.setRowCount(len(self.data))
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Metric","Value"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)

        for i, (key, value) in enumerate(self.data.items()):
            self.table.setItem(i, 0, QTableWidgetItem(key))
            self.table.setItem(i, 1, QTableWidgetItem(str(value)))


        layout = QVBoxLayout()
        layout.addWidget(self.table)
        self.setLayout(layout)
        self.setWindowTitle("Performance Metrics")

        height = len(list(self.data.keys())) * 40
        if(height > 600):
            height = 600
        self.setGeometry(300, 300, 500, height)
        self.show()

def main():
    packets,dict_source = utils.read_pcap("fullTCP.pcap")
    location = utils.get_path()
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

    ex = GUI(location)
    ex.setStyleSheet('background-color: #2b2b2b;')
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()