import socket,sys
from struct import *


def get_e_addr(a):
    e_addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0],a[1],a[2],a[3],a[4],a[5])
    return e_addr


if __name__ == "__main__":

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        pack = s.recvfrom(65565)
        print(pack)
        pack = pack[0]
        e_length = 14

        e_header = pack[:e_length]
        e = unpack('!6s6sH', e_header)
        e_protocol = socket.ntohs(e[2])
        if e_protocol == 8 and get_e_addr(pack[0:6]) != "ff:ff:ff:ff:ff:ff":
            print('Destination MAC : ' + get_e_addr(pack[0:6]) + ' Source MAC : ' + get_e_addr(pack[6:12]) + ' Protocol : ' + str(e_protocol))
