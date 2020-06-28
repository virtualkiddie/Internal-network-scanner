#!/usr/bin/python3

from scapy.all import Ether, ARP, conf, srp
import ipaddress
import time


def arp_scan(iface, ip):
    print("[*]Scaning.....", ip)
    conf.verb = 0
    broadcast = "ff:ff:ff:ff:ff:ff"
    ether_layer = Ether(dst=broadcast)
    apr_layer = ARP(pdst=ip)

    packet = ether_layer / apr_layer

    ans, unans = srp(packet, iface=iface, timeout=2, inter=0.1)

    for snd, rcv in ans:
        ip = rcv[ARP].psrc
        mac = rcv[Ether].src
        print("IP-Address :", ip, '  MAC-Address :', mac)


sip = str(input("Starting ip :"))
eip = str(input("Ending ip :"))

cur_time = time.time()

print("[*]scan starts at :", time.ctime(cur_time))

start_ip = ipaddress.IPv4Address(sip)
end_ip = ipaddress.IPv4Address(eip)
for ip_int in range(int(start_ip), int(end_ip)):
    ipp = ipaddress.IPv4Address(ip_int)

    if __name__ == "__main__":
        iface = "wlan0"
        ip = str(ipp)
        arp_scan(iface, ip)

duration = time.time()
print("[*]Scaning finished at :", time.ctime(duration))
