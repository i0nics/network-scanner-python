#!/usr/bin/env python3
# Programmer: Bikram Chatterjee
# Port Scanner
# Description: This program identifies the status of transport layer ports. To accomplish this, this program uses the
# argparse module to get info about the desired ports, target, protocol etc from the user and then checks for any
# invalid port ranges. The program also uses the socket module to check if the target is valid. Next, if the user
# chooses a TCP scan, an IP datagram containing a TCP SYN packet is sent to all the desired ports of the desired IP.
# If the program receives a TCP SYN-ACK packet back from the host, then the program determines that the port is open.
# If the program receives a TCP RST packet, then the port is determined to be closed. If no answer is received within
# 5 seconds, then the port is marked as filtered. If the user chooses an UDP scan and port 53 is included in the user's
# desired port range, then an UDP packet containing a DNS query to apple.com is sent. For all other ports, an UDP packet
# with a dummy payload is sent. If the program receives either a DNS or UDP reply, then the port is determined to be
# open. If the port receives an ICMP unreachable or ICMP port unreachable error, then the port is determined to be
# closed. If there is no response from the port, it is determined to be Open|Filtered.
from scapy.all import *
import argparse
import socket


def udp_state(pkt):
    if ICMP in pkt:
        if pkt.getlayer(ICMP).type == 3 and pkt.getlayer(ICMP).code == 3:
            return 'Status: Closed            Reason: ICMP port unreachable (type: 3, code: 3)'
        if pkt.getlayer(ICMP).type == 3:
            return 'Status: Closed            Reason: ICMP unreachable (type: 3, code: other)'
    elif DNS in pkt:
        return 'Status: Open              Reason: Received DNS Response'
    elif UDP in pkt:
        return 'Status: Open              Reason: Received UDP Response'
    else:
        return 'Status: Open|Filtered     Reason: No response'


def main():
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0', help='Show Program\'s Version Number and Exit')
    parser.add_argument('--target', help='Hostname or IP to scan', default='127.0.0.1')
    parser.add_argument('--port', help='Port [X] or Port Range [X-Y] to scan', default='0-1023')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--tcp', action="store_true", help='TCP port scan (mutually exclusive with --udp)', default=True)
    group.add_argument('--udp', action="store_true", help='UDP port scan (mutually exclusive with --tcp)')
    parser.add_argument('--verbose', action="store_true", help='Verbose output (Print all ports, not just open ports)')
    args, scan_list, port_range, dns = parser.parse_args(), dict(), list(), False

    try:
        port_range = [int(i) if 0 <= int(i) <= 65535 else int('e') for i in args.port.split('-')] if '-' in args.port else [int(args.port)] if 0 <= int(args.port) <= 65535 else int('e')
        int('e') if len(port_range) > 1 and port_range[0] > port_range[1] or len(port_range) > 2 else 0
        proto = 'udp' if args.udp else 'tcp'
        if len(port_range) > 1:
            port_range = list(range(port_range[0], port_range[1] + 1))
            random.shuffle(port_range)
        org_range = port_range.copy()
    except ValueError:
        sys.exit('ERROR: Invalid Port or Port Range')

    try:
        if args.target[0].isdigit():
            target_ip, target_hostname = args.target, socket.gethostbyaddr(args.target)[0]
        else:
            target_ip = socket.gethostbyname(args.target)
            target_hostname = socket.gethostbyaddr(target_ip)[0]
    except (socket.gaierror, socket.herror):
        sys.exit('Error: Invalid hostname or IP address')

    print(f'Scan type: {proto}\nTarget: {target_hostname} ({target_ip})\nPort(s): {args.port}')
    if proto == 'tcp':
        print('TCP Scanning....')
        ans, unans = sr(IP(dst=target_ip)/TCP(sport=22434, dport=port_range), verbose=0, timeout=5)
        for s, r in ans:
            scan_list[r.sport] = 'Status: Open        Reason: Received TCP SYN-ACK' if r.getlayer(TCP).flags == 'SA' else 'Status: Closed      Reason: Received TCP RST'
        for s in unans:
            scan_list[s.dport] = 'Status: Filtered    Reason: No response'

    else:
        print('UDP Scanning....')
        if 53 in port_range:
            port_range.remove(53)
            ans, unans = sr(IP(dst=target_ip) / UDP(sport=22434, dport=53) / DNS(qd=DNSQR(qname="www.apple.com")), verbose=0, timeout=5)
            if len(ans) > 0:
                for s, r in ans:
                    scan_list[r.sport] = udp_state(r)
            else:
                for s in unans:
                    scan_list[s.dport] = 'Status: Open|Filtered     Reason: No response'
        ans, unans = sr(IP(dst=target_ip) / UDP(sport=22434, dport=port_range) / Raw('Hello World'), verbose=0, timeout=5)
        for s, r in ans:
            scan_list[r.sport] = udp_state(r)
        for s in unans:
            scan_list[s.dport] = 'Status: Open|Filtered     Reason: No response'

    for i in sorted(org_range):
        print(f'Port: {i}' + ' ' * 5 + scan_list[i]) if args.verbose else print(f'Port: {i}' + ' ' * 5 + scan_list[i]) if 'Open ' in scan_list[i] else 0


if __name__ == "__main__":
    sys.exit(main())
