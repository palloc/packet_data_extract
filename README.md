# Packet data extractor
This program can extract packet's IPaddress, MACaddress, port, ttl, time and data.
You must use python2.

## How to use?

[1]
`git clone https://github.com/palloc/packet_data_extract`

[2]
Put your pcap file in `packet_data_extract/data/` .

[3]
`python data_extract.py [argument]`

Replace [argument] for following words.

```
data  (data)
sport  (source port)
dport  (destination port)
protocol  (protocol)
ttl  (ttl)
src  (source ip address)
dst  (destination ip address)
mac_src  (source mac address)
mac_dst  (destination mac address)
time  (time of arrival)
all  (packets detail)
```

[4]
Extracted file is in `/packet_data_extract/result/`

### Sample
[1]
`git clone https://github.com/palloc/packet_data_extract`

[2]
`cd packet_data_extract`

[3]
`python data_extract.py data`

[4]
Input `sample1.pcap`.

[5]
Input `sample1_data`.

[6]
Wait a moment...

[7]
finish!

