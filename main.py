import scapy.all as sc
pcap_file = "Ressources SAE101/Wireshark/McDiarmid.pcapng"
output_file = "Ressources SAE101/Wireshark/output.pdf"
packets = sc.rdpcap(pcap_file)

ftp_data = b''
for packet in packets:
    if 'Raw' in packet :
        ftp_data += bytes(packet['Raw'].load)

with open(output_file, 'wb') as f:
    f.write(ftp_data) 
    

def read_data_password(packets):
    password = b''
    for packet in packets[4]:
        if 'Raw' in packet :
            password += bytes(packet['Raw'].load)
    return password

def read_data_username(packets):
    username = b''
    for packet in packets[2]:
        if 'Raw' in packet :
            username += bytes(packet['Raw'].load)
    return username

print(read_data_password(packets))
print(read_data_username(packets))