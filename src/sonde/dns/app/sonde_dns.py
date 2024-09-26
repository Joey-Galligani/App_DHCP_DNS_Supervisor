import logging
import requests
from scapy.all import *
import time
import binascii
import json
import os

API_SERV = os.getenv('API_SERV')
INTERFACE = os.environ.get('INTERFACE')

dns_types = {
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    17: "RP",
    18: "AFSDB",
    19: "X25",
    20: "ISDN",
    21: "RT",
    22: "NSAP",
    23: "NSAP_PTR",
    24: "SIG",
    25: "KEY",
    26: "PX",
    27: "GPOS",
    28: "AAAA",
    29: "LOC",
    30: "NXT",
    31: "EID",
    32: "NIMLOC",
    33: "SRV",
    34: "ATMA",
    35: "NAPTR",
    36: "KX",
    37: "CERT",
    38: "A6",
    39: "DNAME",
    40: "SINK",
    41: "OPT",
    42: "APL",
    43: "DS",
    44: "SSHFP",
    45: "IPSECKEY",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    49: "DHCID",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    53: "SMIMEA",
    55: "HIP",
    56: "NINFO",
    57: "RKEY",
    58: "TALINK",
    59: "CDS",
    60: "CDNSKEY",
    61: "OPENPGPKEY",
    62: "CSYNC",
    63: "ZONEMD",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    100: "UINFO",
    101: "UID",
    102: "GID",
    103: "UNSPEC",
    104: "NID",
    105: "L32",
    106: "L64",
    107: "LP",
    108: "EUI48",
    109: "EUI64",
    249: "TKEY",
    250: "TSIG",
    251: "IXFR",
    252: "AXFR",
    253: "MAILB",
    254: "MAILA",
    255: "ANY",
    256: "URI",
    257: "CAA",
    258: "AVC",
    259: "DOA",
    260: "AMTRELAY",
    32768: "TA",
    32769: "DLV",
}
dns_classes = {
    1: "IN",
    2: "CS",
    3: "CH",
    4: "HS",
    255: "ANY",
}

class sonde_dns:
    filter = "udp and (port 53)"

    def __init__(self):
        self.time = time.time()

    def launch(self):
        self.sniffer()

    def sniffer(self):
        """
        Launch dns packet sniffer
        """
        sniff(iface=INTERFACE, filter=self.filter, prn=self._rebuild_frame)
    
    def _ethernet_block(self, block: DNS) -> dict[str: str]:
        """
        Get mac src and dst from IP block
        Args:
            block (Ether Block): Block Ethernet from DNS

        Returns:
            dict[str: str]: mac src and mac dst in dict
        """
        return {'macdst': block.dst, 'macsrc':block.src}
    
    def _ip_block(self, block: DNS) -> dict[str: str]:
        """
        Get ip src and dst from IP block
        Args:
            block (IP Block): IP block from DNS

        Returns:
            dict[str: str]: ip src and dst in dict
        """
        return {
            'ipsrc': block.src,
            'ipdst': block.dst,
        }

    def _id_and_timestamp(self, block: DNS) -> dict[str: float]:
        """
        Get timestamp and id of the request

        Returns:
            dict[str: int       ID
                str: float      Timestamp
                ]: Timestamp
        """
        return {
            'ID': self._id_from_ip_block(block),
            'timestamp': self.time
        }

    def _id_from_ip_block(self, block):
        
        return block.id
        

    def _udp_block(self, block: DNS) -> dict[str: int]:
        """
        Get ports src and dst from UDP block 
        Args:
            block (UDP Block): UDP block from DNS

        Returns:
            dict[str: int]: ports src and dst in dict
        """
        return {
            'portsrc': block.sport,
            'portdst': block.dport,
        }
    
    def _dns_block(self, packet: DNS) -> dict[str: any]:
        """
        Get dns block
        Args:
            packet (packet): DNS Block

        Returns:
            dict[str: any]: args from DNS block
        """
        records_count = [
            packet.qdcount,
            packet.ancount,
            packet.nscount,
            packet.arcount,
        ]
        return {
            'dnsID': packet.id,
            'qr': packet.qr,
            'opcode': packet.opcode,
            'aa': packet.aa,
            'tc': packet.tc,
            'rd': packet.rd,
            'ra': packet.ra,
            'z': packet.z,
            'rcode': packet.rcode,
            'nQuery': records_count[0],
            'nAnswer': records_count[1],
            'nAuthority': records_count[2],
            'nAdditional': records_count[3]
            } | self._record_to_string(packet, records_count)

    def _record_to_string(self, packet: DNS, records_count: list[str]) -> dict[str: any]:
        """
        Get records from dns
        Args:
            packet : DNS packet

        Returns:
            dict[str: any]: Args from DNS block
        """
        if records_count[0]:
            dnsqr = []
            for dnsqrr in packet['DNSQR']:
                dnsqr.append(str(dnsqrr.qname.decode()) + '   ' + \
                    str(dns_types[dnsqrr.qtype]) + '   ' + \
                    str(dns_classes[dnsqrr.qclass]))
        else: dnsqr = []
        
        if records_count[1]:
            dnsrr = []
            for dnsrrr in packet.an:
                dnsrr.append(str(dnsrrr.rrname.decode()) + '   ' + \
                            str(dns_types[dnsrrr.type]) + '   ' + \
                            str(dns_classes[dnsrrr.rclass]) + '   ' + \
                            str(dnsrrr.ttl) + '   ' + \
                            str(dnsrrr.rdlen) + '   ' + \
                            str(dnsrrr.rdata))
        else: dnsrr = []

        if records_count[2]:
            dnsar = []
            for dnsarr in packet.ns:
                dnsar.append(str(dnsarr.rname.decode()) + '   ' + \
                            str(dns_types[dnsarr.type]) + '   ' + \
                            str(dns_types[dnsarr.type]) + '   ' + \
                            str(dnsarr.ttl) + '   ' + \
                            str(dnsarr.rdlen) + '   ' + \
                            str(dnsarr.mname) + '   ' + \
                            str(dnsarr.rname) + '   ' + \
                            str(dnsarr.serial) + '   ' + \
                            str(dnsarr.refresh) + '   ' + \
                            str(dnsarr.retry) + '   ' + \
                            str(dnsarr.expire) + '   ' + \
                            str(dnsarr.minimum))
        else: dnsar = []

        if records_count[3]:              
            dnsns = []
            for dnsnss in packet.ar:
                dnsns.append(str(dnsnss.rname.decode()) + '   ' + \
                            'NS' + '   ' + \
                            str(dnsnss.ttl) + '   ' + \
                            str(dnsnss.rdata))
        else: dnsns = []

        return {'query': dnsqr, 'answer': dnsrr, 'authority': dnsar, 'additional': dnsns}


    def _rebuild_frame(self, packet: DNS):
        """
        Rebuilt dict and lauch the post to send it on the api
        Args:
            packet (DNS): DNS packet
        """
        if DNS in packet:
            dico = self._id_and_timestamp(packet[IP]) | self._fusion_dico(packet)
            self.post(dico)
    
    def _fusion_dico(self, packet: DNS) -> dict[str: any]:
        """
        Fusion of all dico built 

        Args:
            packet (DNS): DNS packet

        Returns:
            dict[str: any]: fusion completed between all dico built.
        """
        result_dict = {}
        list_functions_individually = [
            self._ethernet_block(packet[Ether]),
            self._ip_block(packet[IP]),
            self._udp_block(packet[UDP]),
        ]


        for i in list_functions_individually:
            result_dict |= i

        result_dict['dns'] = self._dns_block(packet[DNS])
        return result_dict
            
    def post(self, data: dict[str: any]):
        """
        Post data on the api entry
        Args:
            data (dict[str: any]): dict of data to post on the api entry
        """
        url = API_SERV+"/entry/dns"
        rep = requests.post(url, json.dumps(data))

if __name__ == '__main__':
    sonde = sonde_dns()
    sonde.launch()
