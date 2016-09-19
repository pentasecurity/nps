#! /usr/bin/env python
# -*- coding: UTF-8 -*-

"""
arp response send module
"""

from scapy.all import *


def arp_monitor_callback(pkt):
    """
    tp0 08:00:27:f4:9c:09 20.0.0.1
    tp1 08:00:27:0d:56:93 20.0.0.1
    ###[ ARP ]###
         hwtype    = 0x1	#1 for ethernet
         ptype     = 0x800	#the same of Ethernet header field carrying IP datagram!
         hwlen     = 6		#length in bytes of hardware addresses (6 bytes for ethernet(mac))
         plen      = 4		#length in bytes of logical addresses (4 bytes for IP)
         op        = is-at	#1=request; 2=reply; 3/4=RARP req/reply
         hwsrc     = 08:00:27:38:62:de
         psrc      = 30.0.0.1
         hwdst     = 08:00:27:0d:56:93
         pdst      = 20.0.0.1
    """

    SERVER_IFACE = 'tp1'
    SERVER_MAC = '08:00:27:38:62:de'
    SERVER_IP = '1.1.1.3'

    dut_mac = '08:00:27:0d:56:93'

    if ((ARP in pkt) and (pkt[ARP].op == (1)) and
            (pkt[ARP].pdst == SERVER_IP) and (pkt[Ether].src == dut_mac)):
        print 'got the packet'

        #make ether info
        eth = Ether(dst=pkt[Ether].src, src=SERVER_MAC)

        #make arp info (use swap, mac info)
        arp = ARP(hwdst=pkt[ARP].hwsrc,
                pdst=pkt[ARP].psrc,
                hwsrc=SERVER_MAC,
                psrc=SERVER_IP,
                op=2)

        #make packet
        arp_res = eth / arp

        #send arp response
        sendp(arp_res, iface=SERVER_IFACE)

        #for debug
        pkt.show()
        arp_res.show()

        exit(0)


def main():
    sniff(prn=arp_monitor_callback, filter="arp", store=0)


if __name__ == '__main__':
    main()
