import scapy.all as sc
pcap_file = "Ressources SAE101/Wireshark/McDiarmid.pcapng"
output_file = "Ressources SAE101/Wireshark/output.txt"
packets = sc.rdpcap(pcap_file)

ftp_data = b''
for packet in packets:
    if 'Raw' in packet and 'FTP-DATA' in packet:
        ftp_data += bytes(packet['Raw'].load)

with open(output_file, 'wb') as f:
    f.write(ftp_data)