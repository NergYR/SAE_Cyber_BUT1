import scapy.all as sc
import PyPDF2

input_file = ""
output_file = "output/output.pdf"
packets = sc.rdpcap(input_file)

ftp_data = b''
for packet in packets:
    if 'Raw' in packet :
        ftp_data += bytes(packet['Raw'].load)

with open(output_file, 'wb') as f:
    f.write(ftp_data) 
    
    
def recherche_text(packets, string=None):
    tcp = []
    for packet in packets:
        if "Raw" in packet:
            if string in (packet['Raw'].load):
                #print(packet["Raw"].load.split(sep=None)[1].decode("UTF-8"))
                return packet["Raw"].load.split(sep=None)[1].decode("UTF-8")


print(recherche_text(packets, b"USER"))    
print(recherche_text(packets, b"PASS"))
port = recherche_text(packets, b"PORT").split(",")
port_s = int(port[4]) * 256 + int(port[5])
print(port_s)
print(recherche_text(packets, b"RETR"))