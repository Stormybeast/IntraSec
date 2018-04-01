import socket,sys
from struct import *


def eth_addr(a):
    b= "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0],a[1],a[2],a[3],a[4],a[5])
    return b


if __name__ == "__main__":

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        packet = s.recvfrom(65565)

        packet = packet[0]
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        if eth_protocol == 8 and eth_addr(packet[0:6]) != "ff:ff:ff:ff:ff:ff":
            print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))