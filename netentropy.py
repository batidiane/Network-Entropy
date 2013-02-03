#!/usr/bin/env python2
import sys
import string
import struct
import argparse
import dpkt
import pcap
from Algos.shannon import *
from Algos.kolmogorov import *

calculateentropy={
    'sha':shannon,
    'kol':kolmogorov
}
algorithm =  'sha'

def decodeipv4(ip):
    pktinfos = dict()
    pktinfos['src_addr'] = pcap.ntoa(struct.unpack('i',ip.src)[0])
    pktinfos['dst_addr'] = pcap.ntoa(struct.unpack('i',ip.dst)[0])
    pktinfos['proto'] = ip.p
    
    if dpkt.ip.IP_PROTO_TCP == ip.p: #Check for TCP packets
        tcp = ip.data
        pktinfos['proto_name'] = 'TCP'
        pktinfos['src_port'] = tcp.sport
        pktinfos['dst_port'] = tcp.dport
        payload = tcp.data
    elif dpkt.ip.IP_PROTO_UDP == ip.p: #Check for UDP packets
        udp = ip.data
        pktinfos['proto_name'] = 'UDP'
        pktinfos['src_port'] = udp.sport
        pktinfos['dst_port'] = udp.dport
        payload = udp.data
    elif dpkt.ip.IP_PROTO_ICMP == ip.p: #Check for ICMP packets
        icmp = ip.data
        pktinfos['proto_name'] = 'ICMP'
        pktinfos['src_port'] = 0
        pktinfos['dst_port'] = 0
        payload = str(icmp.data)
    else:
        return None, None
           
    return pktinfos, payload
    

def extractpayload(eth):
    if dpkt.ethernet.ETH_TYPE_IP == eth.type:      # ipv4 packet
        return decodeipv4(eth.data)
    elif dpkt.ethernet.ETH_TYPE_IP6 == eth.type:    # ipv6 packet
        return None, None
    elif dpkt.ethernet.ETH_TYPE_ARP == eth.type:    # arp packet
        return None, None
    elif dpkt.ethernet.ETH_TYPE_REVARP == eth.type:    # rarp packet
        return None, None
    else:
        return None, None
    
'''
    packet analyser, dispatch handler
'''
def analysepacket (pktlen, data, timestamp):
    if not data:
        return
    
    pktinfos, payload = extractpayload(dpkt.ethernet.Ethernet(data))
    
    if pktinfos and payload:
        print '\n%d | %s:%d > %s:%d | proto:%s | %s:%f' % (timestamp,
                                  pktinfos['src_addr'],
                                  pktinfos['src_port'],
                                  pktinfos['dst_addr'],
                                  pktinfos['dst_port'],
                                  pktinfos['proto_name'],
                                  algorithm,
                                  calculateentropy[algorithm](payload))
    
'''
    main function
'''    
if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Calculate entropy from live capture or pcap file')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--interface', dest='interface', help='live capture from an interface (default:lo)')
    group.add_argument('-f', '--file', dest='pcapfile', help='filename of a capture file to read from')
    parser.add_argument('-a', '--algo', dest="algo", choices=['sha','kol'], help='entropy algorithm. 2 choices: "sha" for shannon entropy or "kol" for kolmogorov')
    parser.add_argument('bpf', help='BPF filter like "tcp and port 22"')
    
    options = parser.parse_args()
    if options.interface:
        interface = options.interface
        live = True
    elif options.pcapfile:
        interface = options.pcapfile
        live = False
    else:
        interface = 'lo'
        live = True
    
    if options.algo:
        algorithm = options.algo
    
    bpf = options.bpf
    p = pcap.pcapObject()
    if True == live :
        net, mask = pcap.lookupnet(interface)
        p.open_live(interface, 65535, 0, 50)
    else:
        p.open_offline(interface)
    p.setfilter(bpf, 0, 0)

    # try-except block to catch keyboard interrupt.  Failure to shut
    # down cleanly can result in the interface not being taken out of promisc.
    # mode
    try:
        while 1:
            p.dispatch(1, analysepacket)
            
    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
    