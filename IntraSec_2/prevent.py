import os
from NetworkParameters import getIP,getMAC
import Constant
import iptc


def block(mac):
    rule = iptc.Rule()
    match = iptc.Match(rule, "mac")
    match.mac_source = mac
    rule.add_match(match)
    rule.target = iptc.Target(rule, "DROP")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
    chain.insert_rule(rule)
    # chain.delete_rule(rule)

def getVictim(mac):
    ips = getIP()
    macs = getMAC()
    ip_a = []
    mac_s=[]
    mac_v = 0
    for i in range(len(macs)):
        if mac == macs[i]:
            ip_a.append(ips[i])

    print(ip_a)
    for i in range(len(ip_a)):
        print("Printing outcomes for ip: "+ip_a[i])
        for j in range(1, 10):
            os.system("arp-scan "+str(ip_a[i])+" -I "+Constant.INTERFACE+" | grep -oE \"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\" > scan.txt")
            ms = open("scan.txt")
            mac_s = ms.readlines()
            for k in range(len(mac_s)):
                if mac != mac_s[k]:
                    mac_v = mac_s[k]
    print("Mac address of the victim is: "+mac_v)




if __name__ == "__main__":
    mac = "b0:35:9f:c3:af:e1"
    getVictim(mac)
    block(mac)
