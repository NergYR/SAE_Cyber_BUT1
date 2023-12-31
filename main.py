import scapy.all as sc
import PyPDF2

pcap_file = "Ressources SAE101/Wireshark/McDiarmid.pcapng"
output_file = "Ressources SAE101/Wireshark/SW2.pdf"
packets = sc.rdpcap(pcap_file)

ftp_data = b''
for packet in packets:
    if 'Raw' in packet :
        ftp_data += bytes(packet['Raw'].load)

with open(output_file, 'wb') as f:
    f.write(ftp_data) 
    



key = {
    "W":"A",
    "S":"B",
    "E":"C",
    "R":"D",
    "D":"E",
    "X":"F",
    "C":"G",
    "F":"H",
    "T":"I",
    "Y":"J",
    "G":"K",
    "V":"L",
    "B":"M",
    "H":"N",
    "U":"O",
    "N":"P",
    "J":"Q",
    "I":"R",
    "O":"S",
    "K":"T",
    "L":"U",
    "M":"V",
    "P":"W",
    "A":"X",
    "Z":"Y",
    "Q":"Z"
}

def extract_text_from_pdf(pdf_path):
    text = ""
    with open(pdf_path, "rb") as file:
        pdf_reader = PyPDF2.PdfReader(file)

        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            
            text += page.extract_text()

    return text

pdf_path = output_file
extracted_text = extract_text_from_pdf(pdf_path)
print(extracted_text)

def decode_pdf(extracted_text):
    for i in range(len(extracted_text)):
        #print(extracted_text[i], end="")
        line = extracted_text[i]
        #print(line)
        for j in range(len(line)):
            if line[j] in key:
                print(key[line[j]], end="")
            else:
                print(line[j], end="")



def recherche_text(packets, string=None):
    for packet in packets:
        if "Raw" in packet:
            if string in (packet['Raw'].load):
                #print(packet["Raw"].load.split(sep=None)[1].decode("UTF-8"))
                return packet["Raw"].load.split(sep=None)[1].decode("UTF-8")


decode_pdf(extracted_text)






print(recherche_text(packets, b"USER"))    
print(recherche_text(packets, b"PASS"))
print(recherche_text(packets, b"PORT"))
port = recherche_text(packets, b"PORT").split(",")
port_s = int(port[4]) * 256 + int(port[5])
print(port_s)
print(recherche_text(packets, b"RETR"))




