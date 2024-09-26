from sonde_dhcp_test import *

from scapy.all import rdpcap

packet = rdpcap("tests/test_dhcp.cap")[0]



def test_ethernet_block():

    assert sonde_dhcp()._ethernet_block(packet[Ether]) == {'macdst': 'ff:ff:ff:ff:ff:ff', 'macsrc': '08:00:27:cb:7e:f5'}



def test_ip_block():

    assert sonde_dhcp()._ip_block(packet[IP]) == {'ipsrc': '0.0.0.0', 'ipdst': '255.255.255.255'}



def test_udp_block():

    assert sonde_dhcp()._udp_block(packet[UDP]) == {'portsrc': 68, 'portdst': 67}



def test_bootp_block():

    assert sonde_dhcp()._bootp_block(packet[BOOTP]) == {'op': 1, 'htype': 1, 'hlen': 6, 'hops': 0, 'xid': 2714185221, 'secs': 0, 'flags': 0, 'ciaddr': '0.0.0.0', 'yiaddr': '0.0.0.0', 'siaddr': '0.0.0.0', 'giaddr': '0.0.0.0', 'chaddr': '08:00:27:cb:7e:f5:00:00:00:00:00:00:00:00:00:00', 'magicCookie': 1669485411}



def test_dhcp_options_block():

    assert sonde_dhcp()._dhcp_options_block(packet[DHCP]) == {'options': {'message-type': 1, 'requested_addr': '192.168.1.19', 'hostname': 'kali', 'param_req_list': [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42]}}



def test_fusion_dico():

    assert sonde_dhcp()._fusion_dico(packet) == {'macdst': 'ff:ff:ff:ff:ff:ff', 'macsrc': '08:00:27:cb:7e:f5', 'ipsrc': '0.0.0.0', 'ipdst': '255.255.255.255', 'portsrc': 68, 'portdst': 67, 'dhcp': {'op': 1, 'htype': 1, 'hlen': 6, 'hops': 0, 'xid': 2714185221, 'secs': 0, 'flags': 0, 'ciaddr': '0.0.0.0', 'yiaddr': '0.0.0.0', 'siaddr': '0.0.0.0', 'giaddr': '0.0.0.0', 'chaddr': '08:00:27:cb:7e:f5:00:00:00:00:00:00:00:00:00:00', 'magicCookie': 1669485411, 'options': {'message-type': 1, 'requested_addr': '192.168.1.19', 'hostname': 'kali', 'param_req_list': [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42]}}}
