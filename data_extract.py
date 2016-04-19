from scapy.all import *

#show all packets
def show_all(packet):
    for i in packet:
        print packet.show()
#export source mac address
def export_mac_src(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        s += i.src + '\n'
    file.write(s)

#export destination mac address
def export_mac_dst(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        s += i.dst + '\n'
    file.write(s)

#export protocol number
def export_protocol(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += str(i.proto) + '\n'
        except AttributeError:
            s += "L2 packet\n"
    file.write(s)

def export_data(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += i.load + '\n'
        except AttributeError:
            s += "NoData" + '\n'
    file.write(s)
    
if __name__ == "__main__":
    packet_data = rdpcap("data/sample1.pcap")
    output_name = "data/test"

#    f_name = raw_input("enter pcap file name:")
#    output_name = raw_input("enter output file name:")
#    packet_data = rdpcap(f_name)
#    export_mac_src(packet_data,output_name)
#    export_protocol(packet_data,output_name)
#    export_mac_dst(packet_data,output_name)

