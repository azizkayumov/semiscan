import os
import sys
import numpy as np
from scapy.all import rdpcap


def pcap_to_csv(pcap_path, csv_path):
    print(f'\n   => processing pcap: {pcap_path}')
    packets = rdpcap(pcap_path)
    with open(csv_path, 'w') as f:
        for packet in packets:
            if packet.haslayer('IP') and packet.haslayer('TCP'):
                src_ip = packet['IP'].src
                dst_port = packet['TCP'].dport
                timestamp = packet.time
                f.write(f'{timestamp},{src_ip},{dst_port}\n')
    print(f'      csv saved at {csv_path}')


def csv_to_ports(csvpath, vectorspath):
    print(f'\n   => processing csv: {csvpath}')
    # csv -> port sequences
    scanners = {}
    with open(csvpath, 'r') as f:
        for line in f:
            timestamp, src_ip, dst_port = line.strip().split(',')
            if src_ip not in scanners:
                scanners[src_ip] = []
            scanners[src_ip].append(int(dst_port))

    # save port sequences to output folder
    with open(vectorspath, 'w') as f:
        for src_ip, ports in scanners.items():
            f.write(f'{src_ip},{",".join(map(str, ports))}\n')
    print(f'      port sequences saved at {vectorspath}')


def deduplicate(vectors_path, output_path):
    print(f'\n   => deduplicating vectors: {vectors_path}')
    seen = set()
    outfile = open(output_path, 'w')
    with open(vectors_path, 'r') as f:
        for line in f:
            line = line.strip().split(',')
            label = line[1]
            vector = ','.join(line[2:])
            if vector in seen:
                continue
            seen.add(vector)
            outfile.write(f'{label},{vector}\n')
    print(f'      number of unique vectors: {len(seen)}')
    print(f'      deduplicated vectors saved at {output_path}')
    outfile.close()
    