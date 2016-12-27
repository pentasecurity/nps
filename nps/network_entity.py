# -*- coding: UTF-8 -*-
from collections import deque


class NetworkEntity(object):
    """Client or Server simulation network entity"""

    def __init__(self, name):
        # "client" or "server"
        self.name = name

        # simulatation packet list(queue)
        # _packet_list contains send/recv PacketBuff
        self._packet_list = deque()

        # for scapy sniff
        # ex)tp0, eth0, ...
        self._interface_name = ""
        self._interface_mac_addr = "00:00:00:00:00:00"

        # nat!!
        # port random generator for DUT
        #self._nat_port = 0
        #self._nat_magic_number = 99999
        #self._use_nat_port = "False"

    def get_name(self):
        return self.name

    def append_packet_list(self, packet_buff):
        self._packet_list.append(packet_buff)

    def pop_packet_list(self):
        return self._packet_list.popleft()

    def get_packet_list(self):
        return self._packet_list

    def is_empty_packet_list(self):
        return (len(self._packet_list) == 0)

    def set_interface(self, iface_name, iface_mac):
        self._interface_name = iface_name
        self._interface_mac_addr = iface_mac

    def get_interface_name(self):
        return self._interface_name

    def get_interface_mac_addr(self):
        return self._interface_mac_addr

#    def set_use_nat_port(self, use_or_not):
#        self._use_nat_port = use_or_not
#
#    def get_use_nat_port(self):
#        return self._use_nat_port
#
#    def set_dut_nat_port(self, port):
#        self._nat_port = port
#
#    def get_dut_nat_port(self):
#        return self._nat_port
#
#    def get_nat_magic_number(self):
#        return self._nat_magic_number
#
