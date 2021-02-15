#!/usr/bin/env python3
# Programmer: Bikram Chatterjee
# Network Discovery
'''
This program lists all available interfaces present in the host’s LAN and uses Scapy to identify all
online machines accessible through each of the host’s non-virtual interfaces. To achieve this, this program
creates an ethernet frame which encapsulates an ARP packet. The ethernet frame has its destination address set to the
broadcast address while the ARP packet has the host's subnet address along with the CIDR notation. Finally,
Scapy creates a list of ARP packets which are then broadcasted to every IP address in the subnet and prints the MAC
and IP addresses of the online machines which send a reply back to the host.
'''
from scapy.all import *
import argparse
import netifaces


def main():
    interfaces, non_virt_ifaces, max_space, s = get_if_list(), list(), 0, ' '
    conf.verb = 0  # Reduce Verbosity of Output

    # Add command line arguments
    parser = argparse.ArgumentParser(description='Network Discovery')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0', help='Show Program\'s Version Number and Exit')
    parser.parse_args()

    print('Interfaces: ', *get_if_list(), sep='\n* ')
    print('----\nInterface Details:', end='')

    # Calculating Length of Interface Name for Aligning Purposes
    for i in interfaces:
        max_space = len(i) if len(i) > max_space else max_space

    for i in interfaces:
        try:
            # Get The Size of The Interface's Subnet in CIDR Notation via Netifaces
            cidr = sum(bin(int(x)).count('1') for x in
                       netifaces.ifaddresses(i)[netifaces.AF_INET][0].get('netmask').split('.'))
            print(f'\n* {i}:' + ' ' * (max_space - len(i)), f'{get_if_hwaddr(i)}   IP = {get_if_addr(i)}/{cidr}',
                  end='')
           
            # Filter Non-Virtual Interfaces
            non_virt_ifaces.append(i) if get_if_hwaddr(i) != '00:00:00:00:00:00' else 0  
            
        except (KeyError, Scapy_Exception) as e:
            print(f'\n* {i}:' + ' ' * (max_space - len(i)), f'00:00:00:00:00:00   IP = {get_if_addr(i)} ', end='')

    # Identify All Online Interfaces Accessible Through The Non-Virtual Interfaces of Local Machine
    for i in non_virt_ifaces:
        print(f'\n----\nScanning on Interface {i}\n----\nResults:')
       
        # Get The Subnet Size of The Interface Used to Probe The Network in CIDR notation via Netifaces
        cidr = sum(bin(int(x)).count('1') for x in netifaces.ifaddresses(i)[netifaces.AF_INET][0].get('netmask').split('.'))
       
        # Encapsulate ARP packet in Ethernet Frame with Destination MAC Address Set to Broadcast Address
        request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=f'{get_if_addr(i)}/{cidr}')
        
        # Send and Receive the Data Link Layer Packets
        # Timeout to Receive Packets Set to 2 seconds and Unanswered Packets Are Sent One More Time via Retry
        # Received Packets are Separated into Answered and Unanswered Packets
        ans, unans = srp(request, timeout=2, retry=1)
        print('Hosts Responding:', len(ans), '\nHosts Not Responding:', len(unans))
        for sent, received in ans:
            print(f'MAC = {received.hwsrc}   IP = {received.psrc}')


if __name__ == "__main__":
    sys.exit(main())
