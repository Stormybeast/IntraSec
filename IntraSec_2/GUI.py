from PyQt4 import QtGui,QtCore
import sys,time,multiprocessing, socket, os
from ARP_Thread import ARP_Thread
from Analyzing_Thread import Analyzing_Thread
import NetworkParameters
import Constant

my_array = [['a','b']]


class App(QtGui.QMainWindow):

    def __init__(self, title):
        super(App, self).__init__()
        qss_file = open('style.qss').read()
        self.workingThread = None
        self.arpingThread = None
        self.setStyleSheet(qss_file)
        self.initUI(title)
        self.show()

    def initUI(self, title):
        self.statusBar()
        self.setWindowTitle(title)
        self.setFixedSize(640, 480)

        # set layout of outer frame
        mainWidget = QtGui.QWidget(self)
        self.setCentralWidget(mainWidget)

        outerLayout = QtGui.QHBoxLayout()
        mainWidget.setLayout(outerLayout)
        mainWidget.setObjectName("outer")
        # set layout of left part of the main frame
        leftWidget = QtGui.QWidget(mainWidget)
        leftLayout = QtGui.QVBoxLayout()
        leftWidget.setLayout(leftLayout)

        # set layout of left part of the main frame
        rightWidget = QtGui.QWidget(mainWidget)
        rightLayout = QtGui.QVBoxLayout()
        rightWidget.setLayout(rightLayout)
        rightWidget.setStyleSheet("border-left: 1px solid black;")

        # set layout of the leftTop of the main frame
        leftTopWidget = QtGui.QWidget(leftWidget)
        leftTopLayout = QtGui.QVBoxLayout()
        leftTopWidget.setLayout(leftTopLayout)
        leftTopWidget.setStyleSheet("border-bottom: 1px solid black;")

        # set layout of the leftBottom of the main frame
        leftBottompWidget = QtGui.QWidget(leftWidget)
        leftBottompLayout = QtGui.QVBoxLayout()
        leftBottompWidget.setLayout(leftBottompLayout)

        leftLayout.addWidget(leftTopWidget)
        leftLayout.addWidget(leftBottompWidget)

        # Menu
        mainMenu = self.menuBar()
        mainMenu.setNativeMenuBar(False)
        fileMenu = mainMenu.addMenu('&File')

        aboutButton = QtGui.QAction(QtGui.QIcon('about.png'), '&About', self)
        aboutButton.setShortcut("Ctrl+A")
        aboutButton.setStatusTip("About Information")
        aboutButton.triggered.connect(self.onAbout)
        fileMenu.addAction(aboutButton)

        exitButton = QtGui.QAction(QtGui.QIcon('exit24.png'), '&Exit', self)
        exitButton.setShortcut("Ctrl+Q")
        exitButton.setStatusTip("Exit Application")
        exitButton.triggered.connect(self.close)
        fileMenu.addAction(exitButton)

        # add buttons
        self.btn_start = QtGui.QPushButton("Start")
        self.btn_clear = QtGui.QPushButton("Clear")
        self.btn_stop = QtGui.QPushButton("Stop")

        # bind events to buttons
        self.btn_start.clicked.connect(self.start_arp)
        self.btn_clear.clicked.connect(self.clear_arp)
        self.btn_stop.clicked.connect(self.stop_arp)

        leftTopLayout.addWidget(self.btn_start)
        leftTopLayout.addWidget(self.btn_clear)
        leftTopLayout.addWidget(self.btn_stop)

        # add potential attacker
        label_attacker = QtGui.QLabel("Attacker")
        self.table_attacker = QtGui.QListView(leftBottompWidget)
        self.table_attacker.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        leftBottompLayout.addWidget(label_attacker)
        leftBottompLayout.addWidget(self.table_attacker)
        self.attacker_model = QtGui.QStandardItemModel(self.table_attacker)

        # add ARP Table
        label_arp = QtGui.QLabel("ARP Table")
        # table model used to configure content of the table
        self.arp_table_model = myTableModel(my_array, ['MAC', 'IP'], rightWidget)
        self.table_arp = myArpTable(rightWidget, self.arp_table_model)

        rightLayout.addWidget(label_arp)
        rightLayout.addWidget(self.table_arp)

        outerLayout.addWidget(leftWidget)
        outerLayout.addWidget(rightWidget)

    def onAbout(self):
        w = QtGui.QWidget()
        QtGui.QMessageBox.about(w, "About", "Laveen Vasinani\nPravina Bhatt\nYixian Hao")

    # update the ARP table of the UI
    def update_arp(self):
        # address of my_array cannot be changed otherwise the UI doesn't refresh
        global my_array
        my_array.clear()
        Constant.MAC_LIST = NetworkParameters.getMAC()
        Constant.IP_LIST = NetworkParameters.getIP()
        for (k, v) in list(zip(Constant.MAC_LIST, Constant.IP_LIST)):
            my_array.append([k, v])
        self.arp_table_model.layoutChanged.emit()
        self.table_arp.resize()

    def update_attacker(self, label):
        item = QtGui.QStandardItem(label)
        self.attacker_model.appendRow(item)
        self.table_attacker.setModel(self.attacker_model)

    # scan the LAN and create ARP tables
    def start_arp(self):
        # disable the "start" button after clicking
        self.btn_start.setEnabled(False)
        # create a thread for the work otherwise the UI will stuck
        self.workingThread = Analyzing_Thread(self)
        # create a thread for the work of ARP table
        self.arpingThread = ARP_Thread(self)
        # update the UI when ARP table has been created
        self.arpingThread.trigger.connect(self.update_arp)
        # update the UI when attacker has been found
        self.workingThread.trigger.connect(lambda: self.update_attacker("Found Attacker"))

        self.arpingThread.start()
        time.sleep(Constant.WAITING_INTERVAL)
        self.workingThread.start()
        self.update_attacker("Start analyzing...")

    def clear_arp(self, ll):
        my_array.clear()
        self.arp_table_model.layoutChanged.emit()

    def stop_arp(self):
        if self.workingThread is not None:
            self.update_attacker("Stoping...")
            self.workingThread.stop()
            self.workingThread = None
            self.btn_start.setEnabled(True)

            self.arpingThread.stop()
            self.arpingThread = None


class myArpTable(QtGui.QTableView):
    def __init__(self, parent, model, *args):
        super(QtGui.QTableView, self).__init__(parent, *args)
        self.model = model
        self.setModel(self.model)
        self.parent = parent
        self.resize()
        # hide verticalHeaders of the table
        self.verticalHeader().setVisible(False)
        # only one row can be selected at one time
        # table_arp.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
        self.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)
        # the whole row will be selected
        self.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)

    def resize(self):
        # resize table columns
        for i in range(self.model.columnCount(self.parent)):
            self.setColumnWidth(i, 140)


class myTableModel(QtCore.QAbstractTableModel):
    def __init__(self, datain,header,parent=None,*args):
        QtCore.QAbstractTableModel.__init__(self,parent,*args)
        self.arraydata = datain
        self.headerdata = header

    def rowCount(self,parent):
        return len(self.arraydata)

    def columnCount(self,parent):
        if len(self.arraydata):
            return len(self.arraydata[0])
        else:
            return 0

    def data(self,index,role):
        if not index.isValid():
            return None
        elif role != QtCore.Qt.DisplayRole:
            return None
        else:
            return self.arraydata[index.row()][index.column()]

    def headerData(self,col,orientation,role):
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.headerdata[col]
        else:
            return None


def main():
    window = QtGui.QApplication(sys.argv)
    app = App("Title")
    sys.exit(window.exec_())


if __name__ == "__main__":
    main()

