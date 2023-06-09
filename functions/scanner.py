import re
from scapy.all import ARP, Ether, srp
import click
import nmap
from .arp import poison
from .general import get_interface

def scan_network(interface):
    '''
    Main function used to scan ips anc mac addresses on subnet
    '''

    interface = get_interface(interface)

    ip = get_requested_ip_blocks()

    if ip == 'stop':
        return

    device_details = get_devices(ip, interface)

    # No followup or print possible if no devices were found
    if len(device_details) == 0:
        return click.echo("No devices found")

    print_devices(device_details)

    handle_followup(device_details, interface)


def get_requested_ip_blocks():
    '''
    Gets ip subnet requested by user
    '''

    ip = click.prompt("first 3 blocks of ipv4 like. 1.1.1")

    while ip != 'stop' and not validate_ipv4_blocks(ip):
        ip = click.prompt("Invalid IP. Please enter the first 3 block of the ip like 1.1.1")

    return ip


def get_devices(target_ip, interface):
    '''
    Sends ARP request to every possible ip on subnet
    '''

    # Create ARP packet
    # 1/24 is the range 0-255
    range = f'{target_ip}.1/24'
    arp = ARP(pdst=range)

    # Create the Ether broadcast packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Make packet
    packet = ether/arp

    click.echo("Sending out ARP flood. Please wait...")

    # Check which
    result = srp(packet, timeout=3, verbose=0, iface=interface)[0]

    # List of all devices in the network
    devices = []

    for sent, received in result:
        # For each response, get ip and mac of device and put it in the list
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def print_devices(devices):
    '''
    Prints IP and MAC of every device found on the subnetwork
    '''

    click.echo("Available devices in the network:")
    click.echo("IP" + " "*18+"MAC")
    for device in devices:
        # Use format to make 2 nicely formatted columns
        click.echo("{:16}    {}".format(device['ip'], device['mac']))


def handle_followup(devices, interface):
    '''
    Handles followup action of user after scanning network
    '''

    click.echo("What would you like to do?")
    click.echo("1) Scan ports of a specific IP.")
    click.echo("2) ARP spoof a specific IP.")

    followup = click.prompt("Please enter 1 (port scan), or 2 (ARP spoofing). Enter any other key to stop")

    if followup == '1':
        handle_port_scan(devices)
        return

    if followup == '2':
        handle_arp_spoof(devices, interface)
        return

    return


def handle_port_scan(devices):
    '''
    Handles port scan followup
    '''

    ip = get_specific_ip(devices)

    scan_ports(ip)


def handle_arp_spoof(devices, interface):
    '''
    Handles followup to ARP spoofing
    '''

    victim_ip = get_specific_ip(devices)

    spoof_ip = click.prompt("Which IP do you want to impersonate?")

    while spoof_ip != 'stop' and not validate_ip(spoof_ip):
        spoof_ip = click.prompt("Invalid IP. Please enter the IP in the form 1.1.1.1, or type 'stop'")

    poison(victim_ip, spoof_ip, interface=interface)


def get_specific_ip(devices):
    '''
    Gets a specific IP from list of devices chosen by user
    '''

    # Print all devices
    for index, device in enumerate(devices):
        click.echo(f'{index}) {device["ip"]}')

    input = click.prompt("Please select the index of the IP that you want to choose")

    # Repeat question until input is valid
    while input != 'stop' and not validate_index(input, devices):
        input = click.prompt("Please select the index of the IP that you want to choose, or type 'stop'")

    return devices[index]['ip']


def scan_ports(target_ip):
    '''
    Scans all open ports of chosen IP
    '''

    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-p 1-65535')
    for host in scanner.all_hosts():
        click.echo("Open ports for", host, ":")
        for port in scanner[host].all_tcp():
            if scanner[host]['tcp'][port]['state'] == 'open':
                click.echo('Port:', port, 'is open')


def validate_index(input, devices):
    '''
    Checks whether input is integer, and that it is between 0 and len(devices)
    '''

    try:
        index = int(input)
        if 0 <= index < len(devices):
            return True

        return False
    except ValueError:
        return False


def validate_ipv4_blocks(ip_blocks):
    '''
    Validates IP blocks entered by user
    '''

    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}$'
    match = re.match(pattern, ip_blocks)

    return match is not None


def validate_ip(ip):
    '''
    Validates IP entered by user
    '''

    # Regular expression pattern for IP validation
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

    if re.match(pattern, ip):
        return True

    return False
