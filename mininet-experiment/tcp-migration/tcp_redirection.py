import array
from typing import List, Dict, Tuple

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, DEAD_DISPATCHER, \
    HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER
from ryu.lib import snortlib
from ryu.lib.packet import ether_types, packet, ethernet, ipv4, tcp, in_proto, arp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPAction, OFPMatch
from ryu.utils import hex_array

from tcp_util import TcpEndpoint, format_tcp, build_tcp, TcpConn, data_paket
import timeit
import sys

class TcpMigrationDp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths: Dict[str, Datapath] = {}
        self.snort = kwargs['snortlib']
        self.snort_port = 4
        socket_config = {'unixsock': True}

        self.mac_to_port: Dict[str, Dict[str, int]] = {}
        self.backend_mac_to_port: Dict[int, Dict[str, int]] = {
            1: {
                '00:00:00:00:00:01': 2,
            }
        }
        self.backend_ports = [2]
        self.backend_ports_migrated = []
        self.tcp_connections: Dict[Tuple[str, int, str, int], TcpConn] = {}
        self.tcp_connections_migrated: Dict[Tuple[str, int, str, int], TcpConn] = {}
        self.migration_control=0
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        self.control=0
        self.first_migration=0

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug(f'register datapath: {datapath.id:016x}')
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug(f'unregister datapath: {datapath.id:016x}')
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        self.logger.error(f'OFPErrorMsg received: type={ev.msg.type} code={ev.msg.code} '
                          f'message={hex_array(ev.msg.data)}')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, table_id=0, priority=0, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.warn(f'packet truncated: only {ev.msg.msg_len} of {ev.msg.total_len} bytes')

        datapath: Datapath = ev.msg.datapath
        dpid: str = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port: int = ev.msg.match['in_port']

        pkt = packet.Packet(ev.msg.data)
        pkt_eth: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)

        # ignore lldp packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        # ignore ipv6 packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        self.logger.info(f'packet_in dpid={datapath.id} src={pkt_eth.src} dst={pkt_eth.dst} '
                         f'in_port={in_port}')

        self.mac_to_port.setdefault(dpid, {})
        if in_port not in self.backend_ports:
            self.mac_to_port[dpid][pkt_eth.src] = in_port

        if pkt_eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][pkt_eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        pkt_ipv4: ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp: tcp.tcp = pkt.get_protocol(tcp.tcp)

        if pkt_ipv4 and pkt_tcp:
            tcp_id = (pkt_ipv4.dst, pkt_tcp.dst_port, pkt_ipv4.src, pkt_tcp.src_port)
            tcp_reverse_id = (pkt_ipv4.src, pkt_tcp.src_port, pkt_ipv4.dst, pkt_tcp.dst_port)
            #self.logger.info(f'{self.tcp_connections}')
            #self.logger.info(f'Packet in {format_tcp(pkt)}')

            if tcp_id in self.tcp_connections:
                tcp_conn = self.tcp_connections[tcp_id]

                # first data packet from client: send to snort and save
                if pkt_tcp.bits ==  tcp.TCP_ACK:
                    self.logger.info('PSH/ACK received...')
                    self.logger.info('Sending out PSH/ACK...')
                    self.send_packet_out(datapath, out_port=self.snort_port, pkt=pkt)
                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    self.logger.info(f'DIRECTO ACK ')
                    return
                    
                elif pkt_tcp.bits == (tcp.TCP_PSH | tcp.TCP_ACK):  
                    if tcp_conn.last_received_seq == pkt_tcp.seq:
                        return
                    tcp_conn.last_received_seq = pkt_tcp.seq
                    tcp_conn.src_seq = pkt_tcp.seq
                    tcp_conn.src_ack = pkt_tcp.ack
                    tcp_conn.data_pkt = pkt
                    tcp_conn.len_psh_src=len(pkt.protocols[-1])
                    self.logger.info('Sending out PSH/ACK second or more...')
                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    self.send_packet_out(datapath, out_port=self.snort_port, pkt=pkt)
                    return
            
            elif tcp_id in self.tcp_connections_migrated and pkt_tcp.bits == (tcp.TCP_PSH|tcp.TCP_ACK):
                
                self.logger.info('PSH/ACK received migration direct...')
                tcp_conn_migrated = self.tcp_connections_migrated[tcp_id]
                tcp_conn_migrated.len_psh_src=len(pkt.protocols[-1])
                tcp_conn_migrated.src_seq=pkt_tcp.seq
                tcp_conn_migrated.src_ack=pkt_tcp.ack
                
                #Modificar numeros de seq y ack y crear nuevo paquete
                paquete = data_paket(dst=tcp_conn_migrated.dst, src=tcp_conn_migrated.src,
                        seq=tcp_conn_migrated.dst_ack , ack= tcp_conn_migrated.dst_seq + tcp_conn_migrated.len_psh_dst,
                        flags=tcp.TCP_PSH|tcp.TCP_ACK, data=pkt.protocols[-1])
                        
                tcp_conn_migrated.data_pkt = pkt
                 
                self.logger.info(f'Sending out PSH/ACK migration... {tcp_conn_migrated.src_seq} {tcp_conn_migrated.src_ack} {pkt.protocols[-1]}')
                msg = pkt.get_protocol(ethernet.ethernet)
                if self.migration_control==1:
                    out_port = self.backend_ports_migrated
                else:
                    out_port=self.backend_mac_to_port[dpid][msg.dst]
                    
                self.send_packet_out(datapath, out_port=out_port, pkt=paquete)
                self.send_packet_out(datapath, out_port=self.snort_port, pkt=paquete)  
                return
                
            
            if tcp_reverse_id in self.tcp_connections_migrated and pkt_tcp.bits == (tcp.TCP_PSH|tcp.TCP_ACK):
            
                self.logger.info('PSH/ACK received migration reverse...')
                tcp_conn_migrated = self.tcp_connections_migrated[tcp_reverse_id]
                tcp_conn_migrated.len_psh_dst=len(pkt.protocols[-1])
                tcp_conn_migrated.dst_seq=pkt_tcp.seq
                tcp_conn_migrated.dst_ack=pkt_tcp.ack

                
                paquete = data_paket(dst=tcp_conn_migrated.src, src=tcp_conn_migrated.dst,
                        seq=tcp_conn_migrated.src_ack , ack= tcp_conn_migrated.src_seq + tcp_conn_migrated.len_psh_src,
                        flags=tcp.TCP_PSH|tcp.TCP_ACK, data=pkt.protocols[-1])
                        
                self.logger.info(f'{tcp_conn_migrated.src_seq} {tcp_conn_migrated.src_ack}') 
                self.logger.info(f'Sending out PSH/ACK migration reverse...')
                out_port=3
                self.send_packet_out(datapath, out_port=out_port, pkt=paquete)  
                return
            
              
            if tcp_reverse_id in self.tcp_connections_migrated and self.control == 0:
                
                self.control=1
                tcp_conn = self.tcp_connections[tcp_reverse_id]
                tcp_conn_migrated = self.tcp_connections_migrated[tcp_reverse_id]
                if pkt_tcp.bits == tcp.TCP_SYN | tcp.TCP_ACK:
                    tcp_conn_migrated.dst_isn = pkt_tcp.seq
                    tcp_conn_migrated.dst_seq = pkt_tcp.seq
                    tcp_conn_migrated.dst_ack=pkt_tcp.ack
                    self.logger.info(f'{self.tcp_connections}')
                    self.logger.info(f'REVERSO SYN/ACK {tcp_conn_migrated}')
                    self.tcp_migrate_handle_synack(datapath, tcp_conn=tcp_conn,
                                                   tcp_conn_migrated=tcp_conn_migrated)
                    return
                    

            if tcp_reverse_id in self.tcp_connections and len(self.tcp_connections_migrated)==0:
                tcp_conn = self.tcp_connections[tcp_reverse_id]
                if pkt_tcp.bits == (tcp.TCP_SYN | tcp.TCP_ACK):
                    tcp_conn.dst_isn = pkt_tcp.seq
                    tcp_conn.dst_seq = pkt_tcp.seq
                    tcp_conn.dst_ack = pkt_tcp.ack
                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    self.logger.info(f'REVERSO SYN/ACK {tcp_conn}')
                    return
                    
                elif pkt_tcp.bits ==  tcp.TCP_ACK: 
                    self.logger.info('Sending out PSH/ACK second or more...')
                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    self.send_packet_out(datapath, out_port=self.snort_port, pkt=pkt)
                    self.logger.info(f'REVERSO ACK {tcp_conn}')
                    return
                    
                elif pkt_tcp.bits ==  (tcp.TCP_ACK | tcp.TCP_PSH): 
                    if tcp_conn.last_received_seq == pkt_tcp.seq:
                        return
                    tcp_conn.last_received_seq = pkt_tcp.seq
                    tcp_conn.dst_seq = pkt_tcp.seq
                    tcp_conn.dst_ack = pkt_tcp.ack
                    tcp_conn.len_psh_dst=len(pkt.protocols[-1])
                    self.logger.info('Sending out PSH/ACK second or more...')
                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    self.send_packet_out(datapath, out_port=self.snort_port, pkt=pkt)
                    self.logger.info(f'REVERSO PSH/ACK {tcp_conn}')
                    return
                    
            else:

                if pkt_tcp.bits == tcp.TCP_SYN:
                    tcp_conn = TcpConn(dst=TcpEndpoint(pkt_eth.dst, pkt_ipv4.dst, pkt_tcp.dst_port),
                                       src=TcpEndpoint(pkt_eth.src, pkt_ipv4.src, pkt_tcp.src_port),
                                       src_isn=pkt_tcp.seq)
                    tcp_conn.src_seq = pkt_tcp.seq                
                    tcp_conn.last_received_seq = pkt_tcp.seq
                    self.logger.info('SYN Cliente')
                    self.tcp_connections[tcp_id] = tcp_conn
                    self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
                    self.logger.info(f'DIRECTO SYN {tcp_conn}')
                    return


        pkt_arp: arp.arp = pkt.get_protocol(arp.arp)

        if pkt_arp:
            if pkt_arp.dst_mac in self.backend_mac_to_port[dpid]:
                backend_out_port = self.backend_mac_to_port[dpid][pkt_arp.dst_mac]
                actions: List[OFPAction] = [parser.OFPActionOutput(port=out_port),
                                            parser.OFPActionOutput(port=backend_out_port)]

                self.send_packet_out(datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                     in_port=ofproto.OFPP_CONTROLLER, actions=actions, pkt=pkt)
                return
            self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
        
        #self.send_packet_out(datapath, out_port=out_port, pkt=pkt)
        #self.send_packet_out(datapath, out_port=self.snort_port, pkt=pkt)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        self.logger.info('OFPBarrierReply received')

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def alert_handler(self, ev):
        datapath = next(iter(self.datapaths.values()))
        dpid = int(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(array.array('B', ev.msg.pkt))
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        # type(ev.msg.alertmsg) is tuple(bytes,)
        alert_msg: str = ev.msg.alertmsg[0].decode('utf-8')

        if pkt_ipv4 and pkt_tcp:
            tcp_id = (pkt_ipv4.dst, pkt_tcp.dst_port, pkt_ipv4.src, pkt_tcp.src_port)

            
            # ignore duplicate alerts


            self.logger.info(f'snort alert: {alert_msg}')

            if alert_msg.startswith('MIGRATE'):
                

                if self.first_migration==0:
                    tcp_conn = self.tcp_connections[tcp_id]
                    self.first_migration=1
                    self.migration_control=0
                    self.backend_ports_migrated=[]
                    if tcp_conn.dst.mac in self.mac_to_port[dpid]:
                        self.backend_ports_migrated = self.mac_to_port[dpid][tcp_conn.dst.mac]
                        
                    self.logger.info(f'{self.backend_ports_migrated}')
                    tcp_conn_migrated = self.tcp_migrate_start(datapath=datapath, src=tcp_conn.src,
                                                           dst=tcp_conn.dst, isn=tcp_conn.src_seq)                                        
                    tcp_conn_migrated.src_isn=tcp_conn.src_seq
                    tcp_conn_migrated.src_seq=tcp_conn.src_seq
                    tcp_conn_migrated.src_ack=tcp_conn.src_ack
                    tcp_conn_migrated.data_pkt=tcp_conn.data_pkt
                    tcp_conn_migrated.len_psh_src=tcp_conn.len_psh_src
                    tcp_conn_migrated.len_psh_dst=tcp_conn.len_psh_dst
                    self.tcp_connections_migrated[tcp_id] = tcp_conn_migrated
                else:
                    self.control=0
                    tcp_conn_migrated = self.tcp_connections_migrated[tcp_id]
                    self.migration_control=1 
                    tcp_conn_return = self.tcp_migrate_start(datapath=datapath, src=tcp_conn_migrated.src,
                                                           dst=tcp_conn_migrated.dst, isn=tcp_conn_migrated.src_seq)                                        
                    tcp_conn_return.src_isn=tcp_conn_migrated.src_seq
                    tcp_conn_return.src_seq=tcp_conn_migrated.src_seq
                    tcp_conn_return.src_ack=tcp_conn_migrated.src_ack
                    tcp_conn_return.data_pkt=tcp_conn_migrated.data_pkt
                    self.logger.info(f'{self.tcp_connections}')
                    tcp_conn_return.len_psh_src=tcp_conn_migrated.len_psh_src
                    tcp_conn_return.len_psh_dst=tcp_conn_migrated.len_psh_dst
                    self.tcp_connections={}
                    self.tcp_connections[tcp_id]=tcp_conn_migrated
                    self.logger.info(f'{self.tcp_connections}')
                    self.logger.info(f'{self.tcp_connections_migrated}')
                    self.tcp_connections_migrated={}
                    self.tcp_connections_migrated[tcp_id] = tcp_conn_return
                    self.logger.info(f'{self.tcp_connections_migrated}')
                    self.logger.info(f'DIRECTO SYN {tcp_conn_migrated.src_seq} {tcp_conn_migrated.src_ack}')
                

                return

    def tcp_migrate_start(self, datapath: Datapath, src: TcpEndpoint, dst: TcpEndpoint, isn: int) \
            -> TcpConn:
        dpid = datapath.id

        self.backend_mac_to_port.setdefault(dpid, {})
        #out_port = 2
        if self.migration_control==1:
            out_port = self.backend_ports_migrated
        else:
            out_port=self.backend_mac_to_port[dpid][dst.mac]
            
        
            
        syn = build_tcp(dst=dst, src=src, seq=isn, flags=tcp.TCP_SYN)
        self.send_packet_out(datapath, out_port=out_port, pkt=syn)
        tcp_conn = TcpConn(dst=dst, src=src)

        return tcp_conn

    def tcp_migrate_handle_synack(self, datapath: Datapath, tcp_conn: TcpConn,
                                  tcp_conn_migrated: TcpConn):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if self.migration_control==1:
            out_port = self.backend_ports_migrated
        else:
            out_port = self.backend_mac_to_port[dpid][tcp_conn_migrated.dst.mac]
        
        ack = build_tcp(dst=tcp_conn_migrated.dst, src=tcp_conn_migrated.src,
                        seq=tcp_conn_migrated.dst_ack , ack= tcp_conn_migrated.dst_seq + 1,
                        flags=tcp.TCP_ACK)
        
        self.send_packet_out(datapath, out_port=out_port, pkt=ack)
        self.logger.info(f'DIRECTO ACK')
        # add flow rules for seq/ack synchronization
        if self.migration_control==1:
            out_port = self.backend_ports_migrated
        else:
            out_port = 2
        
        
        self.tcp_reset(datapath, tcp_conn,tcp_conn_migrated)
        
        pkt=tcp_conn.data_pkt
        
        
        paquete = data_paket(dst=tcp_conn.dst, src=tcp_conn.src,
                        seq=tcp_conn_migrated.dst_ack,ack=tcp_conn_migrated.dst_seq+1,
                        flags=tcp.TCP_PSH | tcp.TCP_ACK, data=pkt.protocols[-1])
                        
        tcp_conn_migrated.dst_ack=tcp_conn_migrated.dst_seq+1
        tcp_conn_migrated.dst_seq=tcp_conn_migrated.dst_ack
        
        self.logger.info(f'PSH COPIA')
        self.send_packet_out(datapath, out_port=out_port, pkt=paquete)
        
        tcp_id = (tcp_conn.dst.ipv4, tcp_conn.dst.tcp_port, tcp_conn.src.ipv4, tcp_conn.src.tcp_port)
        self.logger.info(f'REVERSO SYN/ACK {tcp_conn_migrated}')
        del self.tcp_connections[tcp_id]

    def tcp_reset(self, datapath: Datapath, tcp_conn: TcpConn,tcp_conn_migrated :TcpConn):
        dpid = datapath.id
        self.logger.info('RESET')
        #out_port = 1
        if self.migration_control==0:
            out_port = self.backend_ports_migrated
        else:
            out_port = self.backend_mac_to_port[dpid][tcp_conn_migrated.dst.mac]
        
        self.logger.info(f'{tcp_conn}')
        self.logger.info(f'{tcp_conn_migrated.src_seq}')
        self.logger.info(f'{tcp_conn.len_psh_src}')
        if self.migration_control==0:
            
            rst = build_tcp(dst=tcp_conn.dst, src=tcp_conn.src,
                        seq=tcp_conn.src_seq + tcp_conn.len_psh_src,
                        flags=tcp.TCP_RST )
        else:
            rst = build_tcp(dst=tcp_conn.dst, src=tcp_conn.src,
                        seq=tcp_conn.dst_ack,
                        flags=tcp.TCP_RST )
            
        
        
        self.send_packet_out(datapath, out_port=out_port, pkt=rst)
        
    def send_packet_out(self, datapath: Datapath, buffer_id: int = None, in_port: int = None,
                        actions: List[OFPAction] = None, out_port: int = None, pkt=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER
        if in_port is None:
            in_port = ofproto.OFPP_CONTROLLER
        if actions is None:
            actions = [parser.OFPActionOutput(port=out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port,
                                  actions=actions, data=pkt)

        self.logger.info(f'Packet out dpid={datapath.id} in_port={in_port} actions={actions} '
                         f'buffer_id={buffer_id}')
        return datapath.send_msg(out)

    def add_flow(self, datapath: Datapath, table_id: int, priority: int, match: OFPMatch,
                 actions: List[OFPAction], buffer_id: int = None, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id=table_id,
                                buffer_id=buffer_id,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                **kwargs)

        self.logger.info(f'Add flow dpid={datapath.id} priority={priority} match={match} '
                         f'actions={actions} buffer_id={buffer_id} {kwargs}')
        return datapath.send_msg(mod)

    def delete_flow(self, datapath: Datapath, priority: int, match: OFPMatch, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                command=ofproto.OFPFC_DELETE,
                                **kwargs)

        self.logger.info(f'Delete flow dpid={datapath.id} priority={priority} match={match} '
                         f'{kwargs}')
        return datapath.send_msg(mod)

    def send_barrier_request(self, datapath: Datapath):
        parser = datapath.ofproto_parser

        req = parser.OFPBarrierRequest(datapath)

        self.logger.info('Barrier request')
        return datapath.send_msg(req)
