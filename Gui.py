#! /usr/bin/env python

from PyQt4 import QtGui,QtCore
import sys
import time

my_array = [['mac1','ip1'],
            ['mac2','ip2'],
            ['mac3','ip3']]
            
class App(QtGui.QMainWindow):

    def __init__(self,title):
        super(App, self).__init__()
        qss_file = open('style.qss').read()
        self.setStyleSheet(qss_file)
        self.initUI(title)
        self.show()

    def initUI(self,title):
        self.statusBar()
        self.setWindowTitle(title)
        self.setFixedSize(640,960)

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

        aboutButton = QtGui.QAction(QtGui.QIcon('about.png'),'&About',self)
        aboutButton.setShortcut("Ctrl+A")
        aboutButton.setStatusTip("About Information")
        aboutButton.triggered.connect(self.onAbout)
        fileMenu.addAction(aboutButton)

        exitButton = QtGui.QAction(QtGui.QIcon('exit24.png'),'&Exit',self)
        exitButton.setShortcut("Ctrl+Q")
        exitButton.setStatusTip("Exit Application")
        exitButton.triggered.connect(self.close)
        fileMenu.addAction(exitButton)


        # add buttons
        btn_start = QtGui.QPushButton("Start")
        btn_clear = QtGui.QPushButton("Clear")
        btn_stop = QtGui.QPushButton("Stop")

        # bind events to buttons
        btn_start.clicked.connect(self.update_arp)
        btn_clear.clicked.connect(self.clear_arp)
     
        leftTopLayout.addWidget(btn_start)
        leftTopLayout.addWidget(btn_clear)
        leftTopLayout.addWidget(btn_stop)

        # add potential attacker
        label_attacker = QtGui.QLabel("Attacker")
        table_attacker = QtGui.QTableView(leftBottompWidget)
        leftBottompLayout.addWidget(label_attacker)
        leftBottompLayout.addWidget(table_attacker)

        # add ARP Table
        label_arp = QtGui.QLabel("ARP Table")
        # table model used to configure content of the table
        self.arp_table_model = myTableModel(my_array,['MAC','IP'],rightWidget)
        self.table_arp = myArpTable(rightWidget,self.arp_table_model)
        
        rightLayout.addWidget(label_arp)
        rightLayout.addWidget(self.table_arp)

        outerLayout.addWidget(leftWidget)
        outerLayout.addWidget(rightWidget)

    def _handle_combo_index_changed(self,idx):
        self.centralWidget().children()[1].children()[1].setText(str(idx))

    def onAbout(self):
        w = QtGui.QWidget()
        QtGui.QMessageBox.about(w,"About","Laveen Vasinani\nPravina Bhatt\nYixian Hao")

    def update_arp(self):
        my_array.append(["NEWMAC","IP"])
        self.arp_table_model.layoutChanged.emit()
        self.table_arp.resize()
        
    def clear_arp(self):
        my_array.clear()
        self.arp_table_model.layoutChanged.emit()

class myArpTable(QtGui.QTableView):
    def __init__(self,parent,model,*args):
        QtGui.QTableView.__init__(self,parent,*args)
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
            self.setColumnWidth(i,140)


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
