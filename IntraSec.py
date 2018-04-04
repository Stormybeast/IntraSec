import socket, multiprocessing,os, time
from struct import *
import get_ip,pyttsx3

interface = "wlp8s0"

class arp_table:
    arp = {}


# class scan_thread(threading.Thread):
#     def __init__(self, pack):
#         super(scan_thread, self).__init__()
#         self.pack = pack
#
#     def run(self):
#         self.analyze()

def analyze(pack,):
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

        if e_addr in arp_table.arp and s_ip != arp_table.arp[e_addr]:
             c=1
             i=0
             while i < len(arp_table.arp):
                 if s_ip == arp_table.arp[i]:
                     c+=1
                     break
                 i+=1
             if c > 1:
                 print("Mac Address of Attacker: " + e_addr + " IP Spoofed: " + s_ip + " Actual IP:" + arp_table.arp[e_addr])
                 engine.say('Intrusion Alert! Intrusion Alert! The Network has been breached! Run preventive maneuvers now!')
                 engine.runAndWait()


def get_e_addr(a):
    e_addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return e_addr


def caller():
    while True:
        get_arp()
        time.sleep(60)


def get_sys_ip():
    ip = os.popen("ifconfig wlp8s0 | grep \"inet addr\" | cut -d ':' -f 2 | cut -d ' ' -f 1")
    ip = str(ip.read())
    print("The system ip is: "+ip)
    return ip


def get_ip_list():
    os.system("arp -i "+interface+" -n | grep -oE \"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\" > /media/codemaster94sb/0800FF7600FF6958/MyPlayground/\"Python Projects\"/IntraSec/ips.txt")
    ips = open("/media/codemaster94sb/0800FF7600FF6958/MyPlayground/Python Projects/IntraSec/ips.txt")
    ip_list = ips.readlines()
    ip_list = [x.strip() for x in ip_list]
    return ip_list


def get_mac_list():
    os.system("arp -i wlp8s0 -n | grep -oE \"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\" > /media/codemaster94sb/0800FF7600FF6958/MyPlayground/\"Python Projects\"/IntraSec/macs.txt")
    macs = open("/media/codemaster94sb/0800FF7600FF6958/MyPlayground/Python Projects/IntraSec/macs.txt")
    mac_list = macs.readlines()
    mac_list = [x.strip() for x in mac_list]
    return mac_list


def get_arp():
    sys_ip = get_sys_ip().strip()
    print("fping -g "+sys_ip+"/24")
    os.system("fping -g "+sys_ip+"/24 -q")
    time.sleep(15)
    ip_list = get_ip_list()
    mac_list = get_mac_list()
    for i in range(len(ip_list)):
        arp_table.arp[mac_list[i]] = ip_list[i]

    return 1


def caller():
    while True:
        get_arp()
        time.sleep(60)


if __name__ == "__main__":
    engine = pyttsx3.init()
    rate = engine.getProperty('rate')
    engine.setProperty('rate', rate - 50)
    engine.say('The IntraSec Module has been started')
    engine.runAndWait()
    pool = multiprocessing.Pool(processes=1)
    pool.apply_async(caller, [])
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    pool1 = multiprocessing.Pool(processes=50)
    while True:
        pack = s.recvfrom(65565)
        pool1.apply_async(analyze, [pack])