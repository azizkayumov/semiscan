from scapy.all import rdpcap

def process_packets(datapath, outputpath):
    # pcap -> port sequences
    scanners = {}
    packets = rdpcap(datapath)
    for packet in packets:
        if packet.haslayer('IP') and packet.haslayer('TCP'):
            src_ip = packet['IP'].src
            dst_port = packet['TCP'].dport
            if src_ip not in scanners:
                scanners[src_ip] = []
            scanners[src_ip].append(dst_port)

    # save port sequences to output folder
    with open(outputpath, 'w') as f:
        for src_ip, ports in scanners.items():
            f.write(f'{src_ip},{",".join(map(str, ports))}\n')
    print(f'   => port sequences saved at {outputpath}')