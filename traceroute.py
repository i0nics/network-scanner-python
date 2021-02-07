#!/usr/bin/env python3
# Programmer: Bikram Chatterjee
# Traceroute
# Description: This traceroute program accepts either the destination IP address or hostname from the user and
# identifies the IP addresses or possible hostnames of all intermediary machines in between the source and destination.
# First, this tool identifies if the user has entered an IP address or hostname and finds the respective hostname or IP
# address accordingly. Next, it creates an IP datagram encapsulating a UDP packet with random destination ports in the
# range of 33434 - 33464 along with random high number source ports. The IP destination address is either directly
# provided by the user or is obtained using hostname provided by the user via Scapy. The max hop is set to 20 and the
# TTL increases in accordance with the current hop number so that all intermediary machines in the path with the
# distance less that or equal to 20 hops can be discovered. Finally it sends and receives the packets from one hop
# to the next and reports the hostname and IP address present in the response packet. If a packet is not acknowledged
# within the expected timeout of 3 seconds, the packet is sent one more time. Otherwise a '*' is printed. The program
# stops as soon as it receives an ICMP Port Unreachable message (type 3) from the target which signifies that the packet
# has reached the destination and the destination port is no longer open.
from scapy.all import *
import argparse


def main():
    # Add command line arguments
    parser = argparse.ArgumentParser(description='Traceroute')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0', help='Show Program\'s Version Number and Exit')
    parser.add_argument('--target', help='Hostname or IP')
    args = parser.parse_args()

    user_input = args.target
    if user_input is None:
        print('Missing hostname or IP Address Input Argument')
        quit()

    # If The User Inputs IP Address, hostname is Identified Otherwise IP Address is Identified
    try:
        if user_input[0].isdigit():
            destination = socket.gethostbyaddr(user_input)[0]
            print(f'traceroute to {destination} ({user_input}), 20 hops max, 60 byte packets')

        else:
            destination = socket.gethostbyname(user_input)
            print(f'traceroute to {user_input} ({destination}), 20 hops max, 60 byte packets')

    except (socket.gaierror, socket.herror) as e:
        print('Error: Invalid hostname or IP address')
        quit()
    print(destination)
    # Max Hops Set To 20
    for hop in range(1, 21):

        # IP Datagram Encapsulating an UDP Packet With Random Source Ports and Destination Ports Between 33434 - 33464
        pkt = IP(dst=destination, ttl=hop) / UDP(sport=random.randint(22434, 22464), dport=random.randint(33434, 33464))

        # Send and Receive Network Layer Packets
        # Timeout to Receive Packets Set to 3 seconds and Unanswered Packets Are Sent One More Time via Retry
        reply = sr1(pkt, timeout=3, retry=1, verbose=0)

        # Print '*' if a Packet is Not Acknowledged Within The Expected Timeout
        if reply is None:
            print(f'{hop}.  *') if hop < 10 else print(f'{hop}. *')

        # Report hostname and IP Address of The Discovered Intermediary Machine
        else:
            print(f'{hop}.  ', end='') if hop < 10 else print(f'{hop}. ', end='')
            try:
                print(socket.gethostbyaddr(reply.src)[0], f'({reply.src})')
            except socket.herror:
                print(reply.src, f'({reply.src})')

            # Break When The Tool Receives an ICMP Port Unreachable Message From The Target
            if reply.type == 3:
                break


if __name__ == "__main__":
    sys.exit(main())
