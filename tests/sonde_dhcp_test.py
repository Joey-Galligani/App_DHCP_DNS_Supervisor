import logging
from scapy.all import IP, sniff, UDP, Ether, DHCP, BOOTP
import time
import json
import binascii


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class sonde_dhcp:
    filter = "udp and (port 67 or port 68)"

    def __init__(self):
        self.time = time.time()

    def launch(self):
        self.sniffer()

    def sniffer(self):
        """
        Launch dhcp packet sniffer
        """
        interface = "eth0"
        sniff(iface=interface, filter=self.filter, prn=self._rebuild_frame)
    
    def _ethernet_block(self, block: DHCP) -> dict[str: str]:
        """
        Get mac src and dst from IP block
        Args:
            block (Ether Block): Block Ethernet from DHCP

        Returns:
            dict[str: str]: mac src and mac dst in dict
        """
        return {'macdst': block.dst, 'macsrc':block.src}
    
    def _ip_block(self, block: DHCP) -> dict[str: str]:
        """
        Get ip src and dst from IP block
        Args:
            block (IP Block): IP block from DHCP

        Returns:
            dict[str: str]: ip src and dst in dict
        """
        return {
            'ipsrc': block.src,
            'ipdst': block.dst,
        }

    def _timestamp(self) -> dict[str: float]:
        """
        Get timestamp

        Returns:
            dict[str: float]: Timestamp
        """
        return {
            'timestamp': self.time
        }

    def _udp_block(self, block: DHCP) -> dict[str: int]:
        """
        Get ports src and dst from UDP block 
        Args:
            block (UDP Block): UDP block from DHCP

        Returns:
            dict[str: int]: ports src and dst in dict
        """
        return {
            'portsrc': block.sport,
            'portdst': block.dport,
        }
    
    def _bootp_block(self, block: DHCP) -> dict[str: any]:
        """
        Get bootp block from dhcp 
        Args:
            block (BOOTP Block): BOOTP block from DHCP

        Returns:
            dict[str: any]: Args from BOOTP block in dict
        """
        mac_address = ':'.join(['{:02x}'.format(byte) for byte in block.chaddr])
        return {
            'op': block.op,
            'htype': block.htype,
            'hlen': block.hlen,
            'hops': block.hops,
            'xid': block.xid,
            'secs': block.secs,
            'flags': block.flags.decode() if block.flags else 0,
            'ciaddr': block.ciaddr,
            'yiaddr': block.yiaddr,
            'siaddr': block.siaddr,
            'giaddr': block.giaddr,
            'chaddr': mac_address,
            'magicCookie': int.from_bytes(block.options, "big"),
        }
    
    def _dhcp_options_block(self, block: DHCP) -> dict[str: str]:
        """
        Get options block from dhcp 
        Args:
            block (Options Block): Options block from DHCP

        Returns:
            dict[str: any]: Args from BOOTP block in dict
        """
        list_dhcp = [i for i in block.options if i not in ['end', 'pad']]
        dico_dhcp = {}
        for i in list_dhcp:
            value = i[1]
            if isinstance(value, bytes):
                value = value.decode()
            dico_dhcp[i[0]] = value if len(i) == 2 else [j for j in i[1:]]
        return {'options': dico_dhcp}
    
    def _rebuild_frame(self, packet: DHCP):
        """
        Rebuilt dict and lauch the post to send it on the api
        Args:
            packet (DHCP): DHCP packet
        """
        if DHCP in packet:
            dico = self._timestamp() | self._fusion_dico(packet)
    
    def _fusion_dico(self, packet: DHCP) -> dict[str: any]:
        """
        Fusion of all dico built 

        Args:
            packet (DHCP): DHCP packet

        Returns:
            dict[str: any]: fusion completed between all dico built.
        """
        result_dict = {}
        list_functions_dhcp = [
            self._bootp_block(packet[BOOTP]),
            self._dhcp_options_block(packet[DHCP]),
        ]
        list_functions_individually = [
            self._ethernet_block(packet[Ether]),
            self._ip_block(packet[IP]),
            self._udp_block(packet[UDP]),
        ]
        for i in list_functions_individually:
            result_dict |= i
        for i in list_functions_dhcp:
            result_dict['dhcp'] = i if not result_dict.get('dhcp') else result_dict['dhcp'] | i
        return result_dict
            

sonde_dhcp()