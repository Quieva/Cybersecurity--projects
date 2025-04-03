from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    
    result = srp(packet, timeout=2, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})
    
    return devices

# Change "192.168.1.1/24" to match your network
network_range = "192.168.1.1/24"
devices_found = scan_network(network_range)

print("Connected Devices:")
for device in devices_found:
    print(f"IP: {device['IP']}, MAC: {device['MAC']}")
