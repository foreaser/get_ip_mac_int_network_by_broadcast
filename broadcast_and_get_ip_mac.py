import scapy.all as scapy

def scan_network(ip, mask):
    # 브로드캐스팅
    network = ip + '/' + mask
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # IP / MAC 주소 저장
    clients_list = []
    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

# 네트워크 브로드캐스트를 위한 IP 대역 지정
ip = '192.168.0.1'
mask = '24'

# 동일 네트워크 내 연결된 기기의 IP/MAC 출력
clients = scan_network(ip, mask)
print(clients)
print(type(clients))
for client in clients:
    print(f"IP Address: {client['ip']}\tMAC Address: {client['mac']}")
