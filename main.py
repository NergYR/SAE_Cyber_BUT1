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
    

def read_data_password(packets):
    password = b''
    for packet in packets[4]:
        if 'Raw' in packet :
            password += bytes(packet['Raw'].load)
    return password.decode("UTF-8")

def read_data_username(packets):
    username = b''
    for packet in packets[2]:
        if 'Raw' in packet :
            username += bytes(packet['Raw'].load)
    return username.decode("UTF-8")

print(read_data_password(packets))
print(read_data_username(packets))


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

for i in range(len(extracted_text)):
    print(extracted_text[i], end="")
    line = extracted_text[i]
    print(line)
    

