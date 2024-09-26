from sonde_dns_test import *
from scapy.all import rdpcap

packet = rdpcap("tests/test_dns.cap")[0]

def test_ethernet_block():
    assert sonde_dns()._ethernet_block(packet[Ether]) == {'macdst': 'ac:cf:7b:ea:f6:10', 'macsrc': '08:00:27:cb:7e:f5'}

def test_ip_block():
    assert sonde_dns()._ip_block(packet[IP]) == {'ipsrc': '192.168.1.19', 'ipdst': '192.168.1.1'}

def test_id_and_timestamp():
    assert sonde_dns()._id_and_timestamp(packet[IP])['ID'] == 15254

def test_id_from_ip_block():
    assert sonde_dns()._id_from_ip_block(packet[IP]) == 15254

def test_udp_block():
    assert sonde_dns()._udp_block(packet[UDP]) == {'portsrc': 49567, 'portdst': 53}

def test_dns_block():
    assert sonde_dns()._dns_block(packet[DNS]) == {'dnsID': 62836, 'qr': 0, 'opcode': 0, 'aa': 0, 'tc': 0, 'rd': 1, 'ra': 0, 'z': 0, 'rcode': 0, 'nQuery': 1, 'nAnswer': 0, 'nAuthority': 0, 'nAdditional': 0, 'query': 'mail.etu.umontpellier.fr.   A   IN', 'answer': 'None', 'authority': 'None', 'additional': 'None'}

def test_fusion_dico():
    assert sonde_dns()._fusion_dico(packet) == {'macdst': 'ac:cf:7b:ea:f6:10', 'macsrc': '08:00:27:cb:7e:f5', 'ipsrc': '192.168.1.19', 'ipdst': '192.168.1.1', 'portsrc': 49567, 'portdst': 53, 'dns': {'dnsID': 62836, 'qr': 0, 'opcode': 0, 'aa': 0, 'tc': 0, 'rd': 1, 'ra': 0, 'z': 0, 'rcode': 0, 'nQuery': 1, 'nAnswer': 0, 'nAuthority': 0, 'nAdditional': 0, 'query': 'mail.etu.umontpellier.fr.   A   IN', 'answer': 'None', 'authority': 'None', 'additional': 'None'}}

