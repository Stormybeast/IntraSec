import os, time,threading
import IntraSec


interface = "wlp8s0"
def get_sys_ip():
    ip = os.popen("ifconfig wlp8s0 | grep \"inet addr\" | cut -d ':' -f 2 | cut -d ' ' -f 1")
    ip = str(ip.read())
    print("The system ip is: "+ip)
    return ip


def get_ip_list():
    os.system("arp -i "+interface+" -n | grep -oE \"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\" > /media/codemaster_sb94/0800FF7600FF6958/MyPlayground/\"Python Projects\"/IntraSec/ips.txt")
    ips = open("/media/codemaster_sb94/0800FF7600FF6958/MyPlayground/Python Projects/IntraSec/ips.txt")
    ip_list = ips.readlines()
    ip_list = [x.strip() for x in ip_list]
    return ip_list


def get_mac_list():
    os.system("arp -i wlp8s0 -n | grep -oE \"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\" > /media/codemaster_sb94/0800FF7600FF6958/MyPlayground/\"Python Projects\"/IntraSec/macs.txt")
    macs = open("/media/codemaster_sb94/0800FF7600FF6958/MyPlayground/Python Projects/IntraSec/macs.txt")
    mac_list = macs.readlines()
    mac_list = [x.strip() for x in mac_list]
    return mac_list


def get_arp():
    sys_ip = get_sys_ip().strip()
    print("fping -g "+sys_ip+"/24")
    os.system("fping -r 1 -g "+sys_ip+"/24 -q")
    time.sleep(10)
    ip_list = get_ip_list()
    mac_list = get_mac_list()
    for i in range(len(ip_list)):
        IntraSec.arp[mac_list[i]] = ip_list[i]


def caller():
    while True:
        get_arp()
        time.sleep(60)

