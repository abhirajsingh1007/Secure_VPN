#!/usr/bin/python3
import fcntl
import struct
import os
import time
from Crypto.Cipher import AES
from scapy.all import *
import socket
import select
import secrets
import hashlib

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Diffie-Hellman parameters
# Note: these are not cryptographically secure parameters and are only used for illustration purposes
p = 37
g = 5

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.2/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("server_ip_address", 5555))

# Perform Diffie-Hellman key exchange
print("Performing Diffie-Hellman key exchange...")
# Generate random private key
client_private_key = secrets.randbelow(p-2) + 2
client_public_key = pow(g, client_private_key, p)
sock.sendall(client_public_key.to_bytes(128, byteorder='big'))
server_public_key_bytes = sock.recv(128)
server_public_key = int.from_bytes(server_public_key_bytes, byteorder='big')
shared_secret = pow(server_public_key, client_private_key, p)
print("Shared secret:", shared_secret)
# Derive encryption key from shared secret using SHA-256 hash function
key = hashlib.sha256(str(shared_secret).encode()).digest()

# Create AES cipher object
iv = b'1234567890123456'
cipher = AES.new(key, AES.MODE_CBC, iv)

ip="zero"
port=0
while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data = sock.recv(2048)
            packet = cipher.decrypt(data)
            pkt = IP(packet)
            print("From inside packet <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, bytes(pkt))
        if fd is tun:
            packet = os.read(tun, 2048)
            encrypted_packet = cipher.encrypt(packet)
            sock.sendall(encrypted_packet)