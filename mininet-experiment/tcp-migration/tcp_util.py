from dataclasses import dataclass

from ryu.lib.packet import packet, ethernet, ipv4, tcp
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


@dataclass
class TcpEndpoint:
    mac: str
    ipv4: str
    tcp_port: int


@dataclass
class TcpConn:
    dst: TcpEndpoint
    src: TcpEndpoint
    dst_isn: int = 0
    src_isn: int = 0
    dst_seq: int = 0
    src_seq: int = 0
    last_received_seq: int = 0
    src_ack: int = 0
    dst_ack: int = 0
    last_event_seq: int = 0
    len_psh_src: int = 0
    len_psh_dst: int = 0
    data_pkt = None

def data_paket(dst: TcpEndpoint, src: TcpEndpoint, seq=0, ack=0, flags=0, data=""):
    pkt_eth = Ether(dst=dst.mac, src=src.mac)
    pkt_ipv4 = IP(dst=dst.ipv4, src=src.ipv4)
    pkt_tcp = TCP(dport=dst.tcp_port, sport=src.tcp_port, seq=seq, ack=ack, flags=flags)
    pkt = pkt_eth / pkt_ipv4 / pkt_tcp / data
    return pkt.build()
    
    
def build_tcp(dst: TcpEndpoint, src: TcpEndpoint, seq=0, ack=0, flags=0) -> bytes:
    pkt_eth = Ether(dst=dst.mac, src=src.mac)
    pkt_ipv4 = IP(dst=dst.ipv4, src=src.ipv4)
    pkt_tcp = TCP(dport=dst.tcp_port, sport=src.tcp_port, seq=seq, ack=ack, flags=flags)
    pkt = pkt_eth / pkt_ipv4 / pkt_tcp
    return pkt.build()
    



def format_tcp_flags(flags: int) -> str:
    tcp_flags = {
        'F': 0x01,  # FIN
        'S': 0x02,  # SYN
        'R': 0x04,  # RST
        'P': 0x08,  # PSH
        '.': 0x10,  # ACK
        'U': 0x20,  # URG
        'E': 0x40,  # ECE
        'C': 0x80,  # CWR
        'N': 0x100,  # NS
    }

    res = [k for k, v in tcp_flags.items() if v & flags]
    return ''.join(res)


def format_tcp(pkt: packet.Packet) -> str:
    pkt_ipv4: ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)
    pkt_tcp: tcp.tcp = pkt.get_protocol(tcp.tcp)

    return (f'{pkt_ipv4.src}:{pkt_tcp.src_port} -> {pkt_ipv4.dst}:{pkt_tcp.dst_port} '
            f'Flags [{format_tcp_flags(pkt_tcp.bits)}], seq {pkt_tcp.seq} ack {pkt_tcp.ack} '
            f'length {len(pkt_tcp)}')
