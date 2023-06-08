'''This package is for general functions'''

from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, ARP, Ether, srp, conf

def list_interfaces():
    return get_if_list()

def get_my_ip(interface):
    if interface == "":
        interface = conf.iface
    return get_if_addr(interface)

def get_my_mac(interface):
    if interface == "":
        interface = conf.iface
    return get_if_hwaddr(interface)

def get_my_ip_mac(interface):
    if interface == "":
        interface = conf.iface
    return {'ip': get_if_addr(interface), 'mac': get_if_hwaddr(interface)}

def get_target_mac(ip, interface):
    if interface == "":
        interface = conf.iface
    # Create arp packet object. pdst - destination host ip address
    arp_request = ARP(pdst=ip)
    # Create ether packet object. dst - broadcast mac address. 
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    # Combine two packets in two one
    arp_request_broadcast = broadcast/arp_request
    # Get list with answered hosts
    answered_list = srp(arp_request_broadcast, timeout=1,
                              verbose=False, iface=interface)[0]
    
    return answered_list[0][1].hwsrc