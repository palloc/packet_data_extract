import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys


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

#export destination port
def export_dport(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            #UDP
            if i[IP].proto == 17:
                s += str(i[UDP].dport) + ','
                s += str(i[UDP].sport) + '\n'
            else:
                s += str(i[TCP].dport) + ','
                s += str(i[TCP].sport) + '\n'
        except IndexError:
            s += "No IPLayer\n"
    file.write(s)
    file.close()

#export source port
def export_sport(packet,output):
    file = open(output,'w')
    s = ""
    for i in packet:
        try:
            #UDP
            if i[IP].proto == 17:
                s += str(i[UDP].sport) + '\n'
            else:
                s += str(i[TCP].sport) + '\n'
        except IndexError:
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
    #input pcap file name
    f_name = "data/" + raw_input("enter pcap file name:")
    #input output file name
    output_name = "result/" + raw_input("enter output file name:")

    #read pcapfile
    pcap = rdpcap(f_name)

    #export data
    if sys.argv[1] == "data":
        export_data(pcap,output_name)

    #export source port
    elif sys.argv[1] == "sport":
        export_sport(pcap,output_name)

    #export destination port
    elif sys.argv[1] == "dport":
        export_dport(pcap,output_name)

    #export protocol
    elif sys.argv[1] == "protocol":
        export_protocol(pcap,output_name)

    #export ttl
    elif sys.argv[1] == "ttl":
        export_ttl(pcap,output_name)

    #export source ip address
    elif sys.argv[1] == "src":
        export_src(pcap,output_name)

    #export destination ip address
    elif sys.argv[1] == "dst":
        export_dst(pcap,output_name)

    #export source mac address
    elif sys.argv[1] == "mac_src":
        export_mac_src(pcap,output_name)

    #export destination mac address
    elif sys.argv[1] == "mac_dst":
        export_mac_dst(pcap,output_name)

    #export time of arrival
    elif sys.argv[1] == "time":
        export_time(pcap,output_name)

    #export all packets detail
    elif sys.argv[1] == "all":
        export_show_all(pcap,output_name)

    else:
        print "wrong argument..."
    print "finish program!"
    
