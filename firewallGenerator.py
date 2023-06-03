#!/usr/bin/env python

# Generate firewall rules

# Directives
import argparse
import ipaddress
import subprocess

# Globals (initialized constants)
COMMENT = '#'
EXECUTE = False
IPTABLES = '/sbin/iptables'
VERSION = '0.12'

# Supported backend targets
# Possible future targets: ipf, ipfks, ios, iosre, iosfw
TARGETS = {'ipt': 1, 'iptct': 1}

# ICMP request/reply type pairs
ICMPPAIR = {
    8: 0,      # echo
    13: 14,    # timestamp
    15: 16,    # information
    17: 18,    # address mask
    33: 34,    # IPv6 where-are-you
    35: 36,    # mobile registration
    37: 38     # domain name
}

# Valid TCP flags
TCPFLAGS = {'URG': 1, 'ACK': 1, 'PSH': 1, 'RST': 1, 'SYN': 1, 'FIN': 1}

# Initialize the network definitions table
# This is a dictionary of ipaddress.IPv4Network objects
NetDef = {
    'RFC1918': [ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16')]
}

# Initialize the protocol definitions table
# TCP and UDP protocols have a pair of port ranges, ICMP has type and code
ProDef = {
    'ip': ['ip'],
    'icmp': ['icmp', None, None],
    'tcp': ['tcp', None, None, None],
    'udp': ['udp', None, None],
    'ping': ['icmp', 8, None],
    'ftp': ['tcp', None, [21, 21], None],
    'ssh': ['tcp', None, [22, 22], None],
    'telnet': ['tcp', None, [23, 23], None],
    'smtp': ['tcp', None, [25, 25], None],
    'dns': ['udp', None, [53, 53]],
    'dnsxfr': ['tcp', None, [53, 53], None],
    'tftp': ['udp', None, [69, 69]],
    'http': ['tcp', None, [80, 80], None],
    'pop3': ['tcp', None, [110, 110], None],
    'nntp': ['tcp', None, [119, 119], None],
    'ntp': ['udp', None, [123, 123]],
    'imap': ['tcp', None, [143, 143], None],
    'snmp': ['udp', None, [161, 161]],
    'ldap': ['tcp', None, [389, 389], None],
    'https': ['tcp', None, [443, 443], None],
    'imaps': ['tcp', None, [993, 993], None]
}

# Initialize the chains table
# This keeps track of what chains have already been created
Chain = {'INPUT': 1, 'FORWARD': 1, 'OUTPUT': 1}

# Convert a comma-separated list of CIDR blocks and/or defined macros
# into a list of IPv4 network objects
def build_ip_list(ips):
    iplist = []
    for ip in ips.split(','):
        ip = ip.strip()
        if ip in NetDef:
            iplist.extend(NetDef[ip])
        else:
            try:
                network = ipaddress.IPv4Network(ip)
                iplist.append(network)
            except ValueError:
                print(f'Invalid IP address or macro: {ip}')
                return []
    return iplist

# Check validity of symbols and return sanitized version
def check_symbol(s):
    if isinstance(s, int):
        if s < 0 or s > 65535:
            print(f'Invalid symbol value: {s}')
            return -1
        return s
    if isinstance(s, str):
        if not s.isalnum():
            print(f'Invalid symbol: {s}')
            return ''
        return s
    return ''

# Execute a command or print it, based on EXECUTE flag
def execute_command(cmd):
    if EXECUTE:
        subprocess.call(cmd, shell=True)
    else:
        print(cmd)

# Create a new chain if it does not exist
def create_chain(chain):
    if chain not in Chain:
        Chain[chain] = 1
        execute_command(f'{IPTABLES} -N {chain}')

# Initialize the main chains (INPUT, FORWARD, OUTPUT)
def initialize_main_chains():
    for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
        create_chain(chain)
        execute_command(f'{IPTABLES} -F {chain}')

# Parse a TCP/UDP port range
def parse_port_range(port_range):
    if isinstance(port_range, int):
        return port_range, port_range
    if isinstance(port_range, str):
        port_list = port_range.split(':')
        if len(port_list) == 1:
            try:
                port = int(port_list[0])
                return port, port
            except ValueError:
                print(f'Invalid port range: {port_range}')
        elif len(port_list) == 2:
            try:
                start_port = int(port_list[0])
                end_port = int(port_list[1])
                if start_port > end_port:
                    print(f'Invalid port range: {port_range}')
                return start_port, end_port
            except ValueError:
                print(f'Invalid port range: {port_range}')
        else:
            print(f'Invalid port range: {port_range}')
    return None, None

# Generate a rule for a specific target
def generate_rule(target, rule):
    proto = rule['proto']
    src_ip = rule['src_ip']
    src_port = rule['src_port']
    dst_ip = rule['dst_ip']
    dst_port = rule['dst_port']
    flags = rule['flags']
    icmp_type = rule['icmp_type']
    icmp_code = rule['icmp_code']

    if src_ip or dst_ip:
        create_chain(target)

    if proto == 'icmp':
        if icmp_type is None:
            return
        elif icmp_type == 'any':
            icmp_type = None
        elif isinstance(icmp_type, str):
            icmp_type = check_symbol(icmp_type.upper())
            if icmp_type == '':
                return
        elif isinstance(icmp_type, int):
            if icmp_type not in ICMPPAIR:
                print(f'Invalid ICMP type: {icmp_type}')
                return
            icmp_type = ICMPPAIR[icmp_type]
        else:
            print(f'Invalid ICMP type: {icmp_type}')
            return

        if icmp_code is None:
            return
        elif icmp_code == 'any':
            icmp_code = None
        elif isinstance(icmp_code, str):
            icmp_code = check_symbol(icmp_code.upper())
            if icmp_code == '':
                return
        elif not isinstance(icmp_code, int):
            print(f'Invalid ICMP code: {icmp_code}')
            return

        cmd = f'{IPTABLES} -A {target} -p icmp'
        if icmp_type is not None:
            cmd += f' --icmp-type {icmp_type}'
        if icmp_code is not None:
            cmd += f' --icmp-code {icmp_code}'
        if src_ip:
            for src in src_ip:
                cmd += f' -s {src}'
        if dst_ip:
            for dst in dst_ip:
                cmd += f' -d {dst}'
        execute_command(cmd)

    elif proto == 'tcp' or proto == 'udp':
        if src_port is None and dst_port is None:
            return
        if src_port == 'any':
            src_port = None
        if dst_port == 'any':
            dst_port = None

        if src_port is not None:
            if isinstance(src_port, str):
                src_port = check_symbol(src_port.upper())
                if src_port == '':
                    return
            elif isinstance(src_port, int):
                src_port, _ = parse_port_range(src_port)
                if src_port is None:
                    return
            else:
                print(f'Invalid source port: {src_port}')
                return

        if dst_port is not None:
            if isinstance(dst_port, str):
                dst_port = check_symbol(dst_port.upper())
                if dst_port == '':
                    return
            elif isinstance(dst_port, int):
                dst_port, _ = parse_port_range(dst_port)
                if dst_port is None:
                    return
            else:
                print(f'Invalid destination port: {dst_port}')
                return

        cmd = f'{IPTABLES} -A {target} -p {proto}'
        if src_port is not None:
            cmd += f' --sport {src_port}'
        if dst_port is not None:
            cmd += f' --dport {dst_port}'
        if flags:
            for flag in flags.split(','):
                flag = flag.strip().upper()
                if flag in TCPFLAGS:
                    cmd += f' --tcp-flags {flag} {flag}'
                else:
                    print(f'Invalid TCP flag: {flag}')
                    return
        if src_ip:
            for src in src_ip:
                cmd += f' -s {src}'
        if dst_ip:
            for dst in dst_ip:
                cmd += f' -d {dst}'
        execute_command(cmd)

    else:
        print(f'Invalid protocol: {proto}')
        return

# Generate firewall rules from the python
def generate_rules(filename):
    try:
        with open(filename) as file:
            for line in file:
                line = line.strip()
                if line == '' or line.startswith(COMMENT):
                    continue
                elif line.startswith('EXECUTE'):
                    global EXECUTE
                    EXECUTE = True
                elif line.startswith('MACRO'):
                    parts = line.split()
                    if len(parts) != 3:
                        print(f'Invalid macro definition: {line}')
                        continue
                    macro = parts[1]
                    ips = build_ip_list(parts[2])
                    if ips:
                        NetDef[macro] = ips
                elif line.startswith('TARGET'):
                    parts = line.split()
                    if len(parts) != 2:
                        print(f'Invalid target definition: {line}')
                        continue
                    target = parts[1].lower()
                    if target in TARGETS:
                        continue
                    else:
                        print(f'Invalid target: {target}')
                        return
                else:
                    parts = line.split()
                    if len(parts) < 5:
                        print(f'Invalid rule: {line}')
                        continue
                    target = parts[0].upper()
                    if target not in TARGETS:
                        print(f'Invalid target: {target}')
                        continue
                    rule = {'proto': parts[1].lower(),
                            'src_ip': build_ip_list(parts[2]),
                            'src_port': parts[3],
                            'dst_ip': build_ip_list(parts[4]),
                            'dst_port': parts[5],
                            'flags': None,
                            'icmp_type': None,
                            'icmp_code': None}

                    for part in parts[6:]:
                        if part.startswith('FLAGS'):
                            rule['flags'] = part.split('=')[1]
                        elif part.startswith('ICMP'):
                            icmp_parts = part.split('=')
                            if len(icmp_parts) != 3:
                                print(f'Invalid ICMP definition: {part}')
                                continue
                            rule['icmp_type'] = icmp_parts[1]
                            rule['icmp_code'] = icmp_parts[2]
                        else:
                            print(f'Invalid directive: {part}')
                    generate_rule(target, rule)

    except FileNotFoundError:
        print(f'File not found: {filename}')

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='Generate firewall rules using a python')
    parser.add_argument('file', help='python file')
    return parser.parse_args()

# Main function
def main():
    print('Firewall Rule Generator')
    print(f'Version: {VERSION}')
    print('------------------------------------\n')
    args = parse_arguments()
    initialize_main_chains()
    generate_rules(args.file)

# Entry point
if __name__ == '__main__':
    main()
