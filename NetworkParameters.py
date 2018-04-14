import socket, multiprocessing, os, time, pyttsx3
import Constant


def getLocalIp():
    ip = os.popen("ifconfig " + Constant.INTERFACE + " | grep \"inet addr\" | cut -d ':' -f 2 | cut -d ' ' -f 1")
    ip = str(ip.read())
    print("The system ip is: " + ip)
    return ip


def getMAC():
    os.system("arp -i " + Constant.INTERFACE + " -n | grep -oE \"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\" > " + Constant.PROJECT_PATH + "macs.txt")
    macs = open(Constant.PROJECT_PATH + "macs.txt")
    mac_list = macs.readlines()
    mac_list = [x.strip() for x in mac_list]
    return mac_list


def getIP():
    os.system("arp -i " + Constant.INTERFACE + " -n | grep -oE \"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\" > " + Constant.PROJECT_PATH + "ips.txt")
    ips = open(Constant.PROJECT_PATH + "ips.txt")
    ip_list = ips.readlines()
    ip_list = [x.strip() for x in ip_list]
    return ip_list


def getMacFromPack(a):
    e_addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return e_addr

