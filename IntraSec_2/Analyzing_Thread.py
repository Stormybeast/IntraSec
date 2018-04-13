from PyQt4.QtCore import QThread, pyqtSignal
import socket, multiprocessing, json
from struct import *
from NetworkParameters import getMacFromPack,getIP,getMAC
from pyttsx3 import engine
import Preventor
BLACK_LIST = dict()

class Analyzing_Thread(QThread):
    trigger = pyqtSignal()

    def __init__(self, app):
        super(QThread, self).__init__()
        self.stopFlag = False
        self.app = app

    def stop(self):
        self.stopFlag = True

    # def __del__(self):
    #     self.quit()
        # self.wait()

    def run(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        pool1 = multiprocessing.Pool(processes=50)

        while not self.stopFlag:
            # find the attacker
            pack = s.recvfrom(65565)
            pool1.apply_async(analyze, args=(pack, getMAC(), getIP(), self.trigger),callback=check)

        pool1.close()


def check(x):
    if x is not None:
        BLACK_LIST[x] = BLACK_LIST.setdefault(x, 0) + 1
        with open('BLACK_LIST.json', 'w') as fp:
            json.dump(BLACK_LIST, fp)


def analyze(pack,ip_list,mac_list,thread):
    pack = pack[0]
    e_length = 14
    e_header = pack[:e_length]
    e = unpack('!6s6sH', e_header)
    e_protocol = socket.ntohs(e[2])
    if e_protocol == 8 and getMacFromPack(pack[0:6]) != "ff:ff:ff:ff:ff:ff" and getMacFromPack(pack[6:12]) != "00:00:00:00:00:00":
        e_addr = getMacFromPack(pack[6:12])
        i_head = pack[e_length:20 + e_length]
        iph = unpack('!BBHHHBBH4s4s', i_head)
        s_ip = socket.inet_ntoa(iph[8])
        d_ip = socket.inet_ntoa(iph[9])
        print('Source MAC : ' + e_addr)
        print('Source IP: ' + str(s_ip))
        # print('Dest MAC : ' + get_e_addr(pack[0:6]))
        # print('Dest IP: '+str(d_ip))

        if mac_list.count(e_addr) > 1:
            print("Mac Address of Attacker: " + e_addr + " IP: " + s_ip)
            engine.say('Possible Intrusion Alert! Network may have been breached! Run preventive maneuvers!')
            engine.runAndWait()
            thread.emit()
            return e_addr

    return None