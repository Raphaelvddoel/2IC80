import click
import nmap
from scapy.all import sniff, ARP
import re
import sys

networkAddress = ""
unique_ips = []

#
def scan_ports(target_ip):
    scanner = nmap.PortScanner()
    #I can only check open ports for my own ip adress, the router makes it run forever
    #Is there some mechanism blocking me from checking the ports on the router or smth>?
    scanner.scan(target_ip, arguments='-p 1-65535') 
    for host in scanner.all_hosts():
        print("Open ports for", host, ":")
        for port in scanner[host].all_tcp():
            if scanner[host]['tcp'][port]['state'] == 'open':
                print('Port:', port, 'is open')

def sniffing():
    sniff(prn=find_ips, timeout=16)

def find_ips(packet):
    #print(networkAddress)
    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst  

        if src_ip[0:len(networkAddress)] == networkAddress:
            if src_ip not in unique_ips:
                unique_ips.append(src_ip)
        if dst_ip[0:len(networkAddress)] == networkAddress:
            if dst_ip not in unique_ips:
                unique_ips.append(dst_ip)

def validate_ipv4_blocks(ip_blocks):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}$'
    match = re.match(pattern, ip_blocks)

    return match is not None



#networkAddress = ""
# lines to actually run it:
@click.command()
def main():

    #have to put global here since otherwise it acts as if networkAddress remains unchanged
    global networkAddress
    networkAddress = click.prompt("first 3 blocks of ipv4 like. 1.1.1 \n")

    #check if the input was a proper first 3 blocks of an actual ip address, if not do again untill it is
    while True:
        if validate_ipv4_blocks(networkAddress):
            break
        else:
            networkAddress = click.prompt("Invalid try another one")
    
    
    #start sniffing (filtered on the partial ip address from earlier)
    print("start sniffing")
    sniffing()
    #print all caught ip addresses
    for n in unique_ips:
        print(n)
    # wait for an ip adress as input
    input_value = click.prompt("Pick the number corresponding to the IP you want")
    #put this in a loop untill proper input is given
    while True:
        try: 
            input_value = int(input_value)
            input_value = input_value - 1
        except ValueError:
            input_value = click.prompt('invalid input please enter an integer')
            continue

        if (input_value < 0) or (input_value >= len(unique_ips)):
            #print('please give an integer between 1 and' len(unique_ips))
            input_value = click.prompt("please enter an integer between 1 and " + str(len(unique_ips)))
            continue
        break
    click.echo('We will now print all open ports for ' + str(unique_ips[input_value]))
    #call a function to get all open ports for given ip
    scan_ports(unique_ips[input_value])




if __name__ == '__main__':
    main()
