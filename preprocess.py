import os
import sys
import numpy as np
import time
import subprocess

def pcap_to_csv(pcap_path, csv_path):
    filesize = os.path.getsize(pcap_path)
    print(f'\n   => processing pcap: {pcap_path} ({filesize / (1024 * 1024):.2f} MB)')
    # pcap -> csv
    now = time.time()

    # tshark -r input.pcap -T fields -e frame.time -e ip.src -e tcp.dstport -E separator=, > output.csv
    command = f'tshark -r {pcap_path} -Y "tcp" -T fields -e frame.time -e ip.src -e tcp.dstport -E separator=, > {csv_path}'
    subprocess.run(command, shell=True)
    
    print(f'      csv saved at {csv_path} (took {time.time() - now:.2f} seconds)')

def csv_to_ports(csvpath, vectorspath):
    filesize = os.path.getsize(csvpath)
    print(f'\n   => processing csv: {csvpath} ({filesize / (1024 * 1024):.2f} MB)')
    # csv -> port sequences
    scanners = {}
    with open(csvpath, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            splits = line.strip().split(',')
            if len(splits) != 3:
                continue
            timestamp, src_ip, dst_port = splits
            if src_ip not in scanners:
                scanners[src_ip] = []
            scanners[src_ip].append(int(dst_port))

    # save port sequences to output folder
    with open(vectorspath, 'w') as f:
        for src_ip, ports in scanners.items():
            f.write(f'{src_ip},{",".join(map(str, ports))}\n')
    print(f'      port sequences saved at {vectorspath}')


def deduplicate(vectors_path, output_path):
    filesize = os.path.getsize(vectors_path)
    print(f'\n   => processing vectors: {vectors_path} ({filesize / (1024 * 1024):.2f} MB)')
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
    