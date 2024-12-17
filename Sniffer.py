from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffing():
    global scanning_active
    print("เริ่มการแสกนทราฟฟิค...")
    sniff(prn=packet_callback, store=0, filter="ip", stop_filter=lambda x: not scanning_active)
