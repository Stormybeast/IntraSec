from PyQt4.QtCore import QThread, pyqtSignal
import Constant
import NetworkParameters
import os, time


class ARP_Thread(QThread):
    trigger = pyqtSignal()

    def __init__(self, app):
        super(QThread, self).__init__()
        self.stopFlag = False
        self.app = app

    # def __del__(self):
    #     self.wait()

    def run(self):
        while not self.stopFlag:
            self.app.update_attacker("Refreshing ARP...")
            self.arpSpoof()
            time.sleep(Constant.WAITING_INTERVAL)
            self.trigger.emit()
            time.sleep(Constant.REFRESHING_INTERVAL - Constant.WAITING_INTERVAL)

    def stop(self):
        self.stopFlag = True

    def arpSpoof(self):
        sys_ip = NetworkParameters.getLocalIp().strip()
        print("fping -r 0 -g " + sys_ip + "/24")
        os.system("fping -r 0 -g " + sys_ip + "/24 -q")
        return 1

