import socket, os, threading, multiprocessing
from struct import *
import get_ip,pyttsx3

arp = {}


# class scan_thread(threading.Thread):
#     def __init__(self, pack):
#         super(scan_thread, self).__init__()
#         self.pack = pack
#
#     def run(self):
#         self.analyze()

def analyze(pack):
    pack = pack[0]
    e_length = 14
    e_header = pack[:e_length]
    e = unpack('!6s6sH', e_header)
    e_protocol = socket.ntohs(e[2])
    if e_protocol == 8 and get_e_addr(pack[0:6]) != "ff:ff:ff:ff:ff:ff" and get_e_addr(pack[6:12]) != "00:00:00:00:00:00":
        e_addr = get_e_addr(pack[6:12])
        i_head = pack[e_length:20+e_length]
        iph = unpack('!BBHHHBBH4s4s', i_head)
        s_ip = socket.inet_ntoa(iph[8])
        d_ip = socket.inet_ntoa(iph[9])
        print('Source MAC : '+e_addr)
        print('Source IP: '+str(s_ip))
        print('Dest MAC : ' + get_e_addr(pack[0:6]))
        print('Dest IP: '+str(d_ip))
        #print(arp)
        # if e_addr in arp and s_ip != arp[e_addr]:
        #
        #     print("Mac Address of Attacker: "+e_addr+" IP Spoofed: "+s_ip+" Actual IP:"+arp[e_addr])
        #     engine.say('Intrusion Alert! Intrusion Alert! The Network has been breached! Run preventive maneuvers now!')
        #     engine.runAndWait()


def get_e_addr(a):
    e_addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return e_addr


if __name__ == "__main__":
    engine = pyttsx3.init()
    rate = engine.getProperty('rate')
    engine.setProperty('rate', rate - 50)
    pool = multiprocessing.Pool(processes=1)
    pool.apply_async(get_ip.caller, [])
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    pool1 = multiprocessing.Pool(processes=50)
    while True:
        pack = s.recvfrom(65565)
        pool1.apply_async(analyze, [pack])