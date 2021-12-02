import os
from scapy.all import sniff

class PacketScan:
    def __init__(self):
        self.ipMacMap = {}
        sniff(count=0, filter="arp", store=0, prn=self.scan)

    def scan(self, packet):
        os.system("clear")
        print("started scanning for ARP spoofing - press ctrl+c to stop")
        ip = packet['ARP'].psrc
        macAdress = packet['Ether'].src
        print(ip, macAdress)
        if macAdress in self.ipMacMap.keys():
            if self.ipMacMap[macAdress] != ip:
                try:
                    formerIp = self.ipMacMap[macAdress]
                except:
                    formerIp = "unknown"
                msg = f"possible ARP atack detected, device {str(formerIp)} is acting as {str(ip)}"

                return msg
            else:
                self.ipMacMap[macAdress] = ip
     
if __name__== "__main__":
    initialization = PacketScan()