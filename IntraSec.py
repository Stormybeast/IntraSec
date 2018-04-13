import socket, multiprocessing, os, time, pyttsx3
from struct import *

<<<<<<< HEAD
interface = "wlp8s0"
#project_path = "/media/codemaster94sb/0800FF7600FF6958/MyPlayground/\"Python Projects\"/IntraSec/"
=======
interface = "wlp4s0"
# project_path = "/media/codemaster94sb/0800FF7600FF6958/MyPlayground/Python\ Projects/IntraSec/"
>>>>>>> fa73ed3c94fd94da0e384ebfc8a7ed09f0cb61fd
project_path = ""

def analyze(pack,ip_list,mac_list,thread=None):
    arp = build_arp(ip_list,mac_list)
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
       # print('Dest MAC : ' + get_e_addr(pack[0:6]))
       # print('Dest IP: '+str(d_ip))
      #  count = mac_list.count(e_addr)
      #  print("Count: "+str(count))
        if mac_list.count(e_addr) > 1:
            print("Mac Address of Attacker: " + e_addr + " IP: " + s_ip)
            engine.say('Possible Intrusion Alert! Network may have been breached! Run preventive maneuvers!')
            engine.runAndWait()
            if thread is not None:
                thread.emit()


def build_arp(ip_list,mac_list):
    arp = {}
    for i in range(len(ip_list)):
        arp[mac_list[i]] = ip_list[i]
    return arp


def get_e_addr(a):
    e_addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return e_addr


def caller():
    while True:
        get_arp()
        time.sleep(60)


def get_sys_ip():
    ip = os.popen("ifconfig "+interface+" | grep \"inet 地址\" | cut -d ':' -f 2 | cut -d ' ' -f 1")
    ip = str(ip.read())
    print("The system ip is: "+ip)
    return ip


def get_ip_list():
    os.system("arp -i "+interface+" -n | grep -oE \"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\" > "+project_path+"ips.txt")
    ips = open(project_path+"ips.txt")
    ip_list = ips.readlines()
    ip_list = [x.strip() for x in ip_list]
    return ip_list


def get_mac_list():
    os.system("arp -i "+interface+" -n | grep -oE \"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\" > "+project_path+"macs.txt")
    macs = open(project_path+"macs.txt")
    mac_list = macs.readlines()
    mac_list = [x.strip() for x in mac_list]
    return mac_list


def get_arp():
    sys_ip = get_sys_ip().strip()
    print("fping -g "+sys_ip+"/24")
    os.system("fping -g "+sys_ip+"/24 -q")
    return 1


def caller():
    while True:
        get_arp()
        time.sleep(60)


if __name__ == "__main__":
    engine = pyttsx3.init()
    rate = engine.getProperty('rate')
    engine.setProperty('rate', rate - 50)
    engine.say('The IntraSec Module has been initialised!')
    engine.runAndWait()
    pool = multiprocessing.Pool(processes=1)
    pool.apply_async(caller, [])
    time.sleep(45)
    engine.say('The module, will now start scanning the network!')
    engine.runAndWait()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    pool1 = multiprocessing.Pool(processes=50)
    while True:
        pack = s.recvfrom(65565)
        ip_list = get_ip_list()
        mac_list = get_mac_list()
        pool1.apply_async(analyze, [pack, ip_list, mac_list])
