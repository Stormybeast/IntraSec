import os
import re

def get_ip():
    ip = os.system("ifconfig wlp8s0 | grep \"inet addr\" | cut -d ':' -f 2 | cut -d ' ' -f 1")
    return ip


if __name__ == "__main__":
    ip = get_ip()
    print(ip)
    os.system("arp -i wlp8s0 -n | grep -oE \"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\" > /media/codemaster_sb94/0800FF7600FF6958/MyPlayground/\"Python Projects\"/IntraSec/ips.txt")

    arp = open("/media/codemaster_sb94/0800FF7600FF6958/MyPlayground/Python Projects/IntraSec/ips.txt")
    arp_list = arp.readlines()
    arp_list = [x.strip() for x in arp_list]
    print(arp_list)
    print(len(arp_list))
