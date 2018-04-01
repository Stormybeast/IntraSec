import os

def get_ip():
    ip = os.system("ifconfig wlp8s0 | grep \"inet addr\" | cut -d ':' -f 2 | cut -d ' ' -f 1")
    return ip
if __name__== "__main__":
    ip = get_ip()
    print(ip)