'''This package is for general functions'''

from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, ARP, Ether, srp, conf

def get_interface(interface):
    '''
    Get network interface
    '''
    
    if interface == "":
        return conf.iface
    
    return interface


def list_interfaces():
    '''
    Returns all interfaces of attacker
    '''

    return get_if_list()


def get_my_ip(interface):
    '''
    Returns the IP of the attacker
    '''

    interface = get_interface(interface)
    
    return get_if_addr(interface)


def get_my_mac(interface):
    '''
    Returns the MAC address of the attacker
    '''

    interface = get_interface(interface)

    return get_if_hwaddr(interface)


def get_my_ip_mac(interface):
    '''
    Returns the IP and MAC address of the attacker
    '''

    interface = get_interface(interface)

    return {'ip': get_if_addr(interface), 'mac': get_if_hwaddr(interface)}


def get_target_mac(ip, interface):
    '''
    Returns the MAC addres of parameter 'ip'
    '''

    interface = get_interface(interface)

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
