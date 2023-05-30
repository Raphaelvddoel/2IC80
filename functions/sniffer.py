import click
import nmap
from scapy.all import sniff, ARP
from scapy.all import *
import ipaddress

#sniffer runs for 20 seconds; count is in seconds
def sniffer(count=20):
    #this only catches it if i do arp -d in admin cmd, why?
    #this might not catch all ip adresses on local network
    print('start sniffing')
    packets = sniff(timeout=count, filter="arp")
    #packets = sniff(count=count, filter="arp")
    print('ended sniffing')
    print('printing all ips now')
    #this function only gives the ports of the ip adress if you do: arp -d, others like ping will keep running inf??????
    process_packet(packets)

unique_ips = []

def process_packet(packets):
    #all ips we are going to print at the end 
    #unique_ips = []
    for n in packets:
        #add all unique ip adresses to unique adress
        #ip_address = n.psrc
        ip_address = n.pdst
        if ip_address not in unique_ips:
            unique_ips.append(ip_address)
    #print all ips found
    for n in unique_ips:
        print(n)

#fucntion to check if something is an actual ip adress
def validate_ip_address(ip_string):
   try:
       ip_object = ipaddress.ip_address(ip_string)
   except ValueError:
       print(ip_object)
       print('is not an ip adress')

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
                



# lines to actually run it:
@click.command()
def main():
    sniffer()
    #input integer works?
    # wait for an ip adress as input
    input_value = click.prompt("Enter an ip adress you want to ....")
    #put this in a loop continue makes it 
    while True:
        try: 
            input_value = int(input_value)
            input_value = input_value - 1
        except ValueError:
            input_value = click.prompt('invalid input please enter an integer')
            continue

        #if not isinstance(input_value, int):
        #    #print('please give an integer')
        #    input_value = click.prompt("please enter an integer ")
        #    continue
        #input_value = int(input_value)
        #input_value = input_value - 1

        if (input_value < 0) or (input_value >= len(unique_ips)):
            #print('please give an integer between 1 and' len(unique_ips))
            input_value = click.prompt("please enter an integer between 1 and " + str(len(unique_ips)))
            continue

        if validate_ip_address(unique_ips[input_value]):
            input_value = click.prompt("The chosen ip adress is not valid")
            continue
        break
    click.echo('We will now print all open ports for the chosen ip adress')
    print(unique_ips[input_value])
    scan_ports(unique_ips[input_value])




if __name__ == '__main__':
    main()
