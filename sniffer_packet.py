from scapy.all import sniff , IP, TCP, UDP, ICMP, ARP, Ether, Raw 
import time 
from datetime import datetime

# -----------------------------------

#! global counters 
pack_coun = 0  # number of packet 
start = time.time() 

#! functions 
def pack_callback(pack):
    # process each captured packet
    global pack_coun
    pack_coun +=1 # --> increment packet counter 
    # calcute time it take and packet rate 
    current = time.time() 
    taken_time = current - start 
    if taken_time > 0 :
        rate = pack_coun / taken_time 
    else :
        0  # does nothing 
    # display packet information  
    print(f"\n[Packet #{pack_coun}] - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Packet rate: {rate:.2f} packets/sec") 
    # This information is useful for: Monitoring network activity levels
    # Understanding how busy your network is,  Identifying sudden increases in traffic that might indicate network issues

    #! MAC Address 
    if Ether in pack :
        src_MAC = pack[Ether].src  # the source MAC address
        dst_MAC = pack[Ether].dst  # the dstination  MAC address 
        ether_type = pack[Ether].type 
        print(f"Ethernet: {src_MAC} -> {dst_MAC}, type: {hex(ether_type)}") #! 

    #! IP Address 
    if IP in pack:
        src_ip = pack[IP].src
        dst_ip = pack[IP].dst
        proto = pack[IP].proto
        print(f"IP: {src_ip} -> {dst_ip}, proto: {proto}")
        # proto --) A numerical identifier that specifies what type of protocol is carried in the IP packet 
    if TCP in pack:
        sport = pack[TCP].sport
        dport = pack[TCP].dport
        seq = pack[TCP].seq # --> number sequance of packet 
        flags = pack[TCP].flags # --> ACK , SYN , FIN , ..etc 
        print(f"TCP: Port {sport} -> {dport}, Seq: {seq}, Flags: {flags}")

        if dport == 80 or sport == 80:
            print(" HTTP Traffic")
        elif dport == 443 or sport == 443:
            print(" HTTPS Traffic")
        elif dport == 53 or sport == 53:
            print(" DNS Traffic")   
        elif dport == 21 or sport == 21:
            print(" FTP Traffic")          
        elif dport == 23 or sport == 23:
            print(" Telnet Traffic")  
        elif dport == 25 or 465 or 587 or sport == 25 or 465 or 587:
            print(" STMP Traffic") 
        # Check for payload data
        if Raw in pack:
            data_len = len(pack[Raw].load)
            print(f"Payload: {data_len} bytes")

            if data_len > 0:
                payload = pack[Raw].load
                hex_data = payload[:20].hex(' ')
                # display few bytes of payload in hex 
                print(f"Data preview: {hex_data}")
    
    elif UDP in pack:
        sport = pack[UDP].sport
        dport = pack[UDP].dport
        print(f"UDP: Port {sport} -> {dport}")
        if dport == 53 or sport == 53:
            print("DNS Traffic")

        if Raw in pack:
            data_len = len(pack[Raw].load)
            print(f"Payload: {data_len} bytes")
    elif ICMP in pack:
        icmp_type = pack[ICMP].type
        icmp_code = pack[ICMP].code
        print(f"ICMP: Type {icmp_type}, Code {icmp_code}")

        if icmp_type == 8:
            print("Echo Request (Ping)")
        elif icmp_type == 0:
            print("Echo Reply (Ping Response)")
    
    # ARP Layer
    elif ARP in pack:
        op = "who-has" if pack[ARP].op == 1 else "is-at"
        print(f"ARP: {op}")
        print(f"{pack[ARP].psrc} ({pack[ARP].hwsrc}) -> {pack[ARP].pdst} ({pack[ARP].hwdst})")  
    print("_" * 60)
def main():
    print("Simple Network Sniffer ")
    print("Press Ctrl+C to stop capturing packets")
    print("_" * 60)
    
    try:
        # 1)  Start packet capture
        sniff(prn=pack_callback, store=0)
    except KeyboardInterrupt:
        # 2) Show summary when user stops the program
        taken_time = time.time() - start
        print("\nCapture stopped by user")
        print(f"Captured {pack_coun} packets in {taken_time:.2f} seconds")
        print(f"Average rate: {pack_coun/taken_time:.2f} packets/sec")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()     
   



# Protocol Number (proto):

# A numerical identifier that specifies what type of protocol is carried in the IP packet
# Common values include:

# 1: ICMP (Internet Control Message Protocol - used for ping)
# 6: TCP (Transmission Control Protocol - used for web browsing, email, etc.)
# 17: UDP (User Datagram Protocol - used for DNS, streaming, etc.)
# 47: GRE (Generic Routing Encapsulation - used for VPNs)
# 50: ESP (Encapsulating Security Payload - used for IPsec)
        
