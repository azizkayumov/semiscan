import os
import sys
import time
import dpkt

def pcap_to_csv(pcap_path, csv_path):
    filesize = os.path.getsize(pcap_path)
    print(f'\n   => processing pcap: {pcap_path} ({filesize / (1024 * 1024):.2f} MB)')
    # skip if csv already exists and not empty
    if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
        print(f'      csv already exists at {csv_path}, skipping...')
        return
    
    # pcap -> csv
    now = time.time()
    with open(pcap_path, 'rb') as f:
        csv_file = open(csv_path, 'w')
        reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            # Process packet (ts is timestamp, buf is raw packet data)
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            src_ip = '%d.%d.%d.%d' % tuple(map(int, ip.src))
            dst_port = tcp.dport
            csv_file.write(f'{ts},{src_ip},{dst_port}\n')
        csv_file.close()
    print(f'      csv saved at {csv_path} (took {time.time() - now:.2f} seconds)')

def csv_to_ports(csvpath, portspath):
    filesize = os.path.getsize(csvpath)
    print(f'\n   => processing csv: {csvpath} ({filesize / (1024 * 1024):.2f} MB)')
    # csv -> port sequences
    scanners = {}
    now = time.time()
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
    with open(portspath, 'w') as f:
        for src_ip, ports in scanners.items():
            f.write(f'{src_ip},{",".join(map(str, ports))}\n')
    print(f'      port sequences saved at {portspath} (took {time.time() - now:.2f} seconds)')


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
    