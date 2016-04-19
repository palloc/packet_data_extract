from scapy.all import *

#show all packets
def show_all(packet):
    for i in packet:
        print packet.show()

#export arrived time    
def export_time(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += str(i.time) + '\n'
        except AttributeError:
            s += "No time" + '\n'
    file.write(s)
    file.close()
        
#export source mac address
def export_mac_src(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        s += i.src + '\n'
    file.write(s)
    file.close()

#export destination mac address
def export_mac_dst(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        s += i.dst + '\n'
    file.write(s)
    file.close()

#export source ip address
def export_ip_src(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += i[IP].src + '\n'
        except IndexError:
            s += "No IPLayer\n"
    file.write(s)
    file.close()

#export destination ip address
def export_ip_dst(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += i[IP].dst + '\n'
        except IndexError:
            s += "No IPLayer\n"
    file.write(s)
    file.close()

#export ttl
def export_ttl(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += str(i[IP].ttl) + '\n'
        except IndexError:
            s += "No IPLayer\n"
    file.write(s)
    file.close()
    
#export protocol number
def export_protocol(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += str(i.proto) + '\n'
        except AttributeError:
            s += "No IPLayer\n"
    file.write(s)
    file.close()

#export packet's data    
def export_data(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += i.load + '\n'
        except AttributeError:
            s += "NoData" + '\n'
    file.write(s)
    file.close()


if __name__ == "__main__":
    packet_data = rdpcap("data/sample1.pcap")
    output_name = "data/test"

#    f_name = raw_input("enter pcap file name:")
#    output_name = raw_input("enter output file name:")
#    packet_data = rdpcap(f_name)
#    export_mac_src(packet_data,output_name)
#    export_protocol(packet_data,output_name)
#    export_mac_dst(packet_data,output_name)
#    export_data(packet_data,output_name)
#    export_ip_src(packet_data,output_name)
#    export_ip_dst(packet_data,output_name)
#    export_ttl(packet_data,output_name)
    export_time(packet_data,output_name)
