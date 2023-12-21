import scapy.all as scapy
import re
from PyPDF2 import PdfFileWriter, PdfFileReader

#interface = scapy.conf.iface
#output = "output"

#def sniff_ftp(packet):
#    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
#        src_ip = packet[scapy.IP].src
#        dst_ip = packet[scapy.IP].dst
 #       src_port = packet[scapy.TCP].sport
#        dst_port = packet[scapy.TCP].dport
#
#        if packet.haslayer(scapy.Raw):
#            data = packet[scapy.Raw].load.decode("utf-8", errors="ignore")
#
#            if "USER" in data or "PASS" in data:
#                print(f"[+] FTP Credentials detected on {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
#                print(f"    {data}")
#                negotiated_port = packet[scapy.TCP].sport if src_ip == packet[scapy.IP].src else packet[scapy.TCP].dport
#                print(f"    Negotiated Port: {negotiated_port}")

#def sniff_and_save_pdf(packet):
#    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
#        src_ip = packet[scapy.IP].src
#        dst_ip = packet[scapy.IP].dst
#        src_port = packet[scapy.TCP].sport
#        dst_port = packet[scapy.TCP].dport
#
#        if packet.haslayer(scapy.Raw):
#            data = packet[scapy.Raw].load
#
#            # Recherche de l'en-tête PDF dans les données brutes
#            pdf_match = re.search(b'%PDF-1.', data)
#
#            # Recherche de la commande RETR pour extraire le nom du fichier PDF
#            retr_match = re.search(b'RETR (.+)', data)
#
#            if pdf_match and retr_match:
#                pdf_data = data[pdf_match.start():]
#                pdf_filename = retr_match.group(1).decode("utf-8", errors="ignore").strip()
#                save_pdf(src_ip, src_port, dst_ip, dst_port, pdf_filename, pdf_data)

#def save_pdf(src_ip, src_port, dst_ip, dst_port, pdf_filename, pdf_data):
#    pdf_filename = f"captured_pdf_{src_ip}_{src_port}_{dst_ip}_{dst_port}_{pdf_filename}.pdf"
#    pdf_path = output + "/" + pdf_filename
#    with open(pdf_path, 'wb') as pdf_file:
#        pdf_file.write(pdf_data)
        
        
#        print(f"[+] PDF File captured and saved as: {pdf_filename}")

#def start_sniff(interface):
#    scapy.sniff(iface=interface, store=False, prn=sniff_ftp, filter="tcp port 21 or tcp port 20 or tcp port 22")
#    print("Start SNIFF file capture and save as: {interface} and")
    # Ajoutez d'autres ports ou modifiez le filtre selon vos besoins
#    scapy.sniff(iface=interface, store=False, prn=sniff_and_save_pdf, filter="tcp port 21")



# Remplacez 'eth0' par le nom de votre interface réseau
#start_sniff(interface)
interface = scapy.conf.iface
output_dir = "output"
def recherche_text(packets, string=None):
    for packet in packets:
        if "Raw" in packet:
            if string in (packet['Raw'].load):
                #print(packet["Raw"].load.split(sep=None)[1].decode("UTF-8"))
                return packet["Raw"].load.split(sep=None)[1].decode("UTF-8")

def sniff_tcp(packets):
    if scapy.haslayer(scapy.TCP):
        data = packets["Raw"].load
        tcp_data = b''
        for packet in packets:
            if 'Raw' in packet :
                tcp_data += bytes(packet['Raw'].load)

        file_name = recherche_text(packets, b"RETR")
        output_file = output_dir + "/" + file_name
        with open(output_file, 'wb') as f:
            f.write(tcp_data) 
        
        
        

    
    

scapy.sniff(iface=scapy.conf.iface, store=False, prn=sniff_tcp)


    
    
