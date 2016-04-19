from scapy.all import *

#show all packets
def show_all(packet):
    for i in packet:
        print packet.show()

def export_mac_src(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        str += i.src + '\n'
    file.write(s)

def export_protocol(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            s += str(i.proto) + '\n'
        except AttributeError:
            s += "L2 packet\n"
    file.write(s)

    
if __name__ == "__main__":
#    f_name = raw_input("enter pcap file name:")
#    output_name = raw_input("enter output file name:")
#    packet_data = rdpcap(f_name)
#    export_mac_src(packet_data,output_name)
    packet_data = rdpcap("data/sample1.pcap")
    output_name = "data/test"

    export_protocol(packet_data,output_name)
