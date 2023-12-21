import scapy.all as scapy
interface = scapy.conf.iface
output_dir = "output"
port_s  = 0
tcp_data = b""
output_file = ""
def recherche_text(packets, string=None):
    for packet in packets:
        if "Raw" in packet:
            if string in (packet['Raw'].load):
                return packet["Raw"].load.split(sep=None)[1].decode("UTF-8")

def sniff_tcp(packets):
    global port_s
    global tcp_data 
    global output_file
    if packets.haslayer(scapy.TCP):
        if packets.haslayer(scapy.Raw):
                
            if packets["TCP"].dport == 21:
                if "PORT" in str(packets["Raw"].load.decode("UTF-8")):
                    port = str(recherche_text(packets, b"PORT")).split(",")
                    port_s = int(port[4]) * 256 + int(port[5])
                    print("port negocie : ", port_s)

                if packets["TCP"].dport == 21:
                    if "USER" in str(packets["Raw"].load.decode("UTF-8")):
                        user = recherche_text(packets, b"USER")
                        print(f"User = {user}")
                    if "PASS" in str(packets["Raw"].load.decode("UTF-8")):
                        password = recherche_text(packets, b"PASS")
                        print(f"PASS = {password}")
                    if "RETR" in str(packets["Raw"].load.decode("UTF-8")):
                        file_name = str(packets["Raw"].load.decode("UTF-8", errors="ignore"))
                        file_name = file_name.replace("RETR ", "")
                        file_name = file_name.replace("\r\n", "")
                        print(f"File name = {file_name}")
                        output_file = output_dir + "/" + file_name
            if packets["TCP"].dport == port_s:
                tcp_data += packets["Raw"].load
                with open(output_file, "wb") as file:
                    file.write(tcp_data)
                

        
        

    
    

#scapy.sniff(iface=scapy.conf.iface, store=False, prn=sniff_tcp)

scapy.sniff(prn=sniff_tcp, store=0)


    
    
