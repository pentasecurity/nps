# -*- coding: utf-8 -*-
import unittest
import xml.etree.ElementTree as ET

from nps.packet_buff import PacketBuff
from nps.parser import XmlTestCaseParser
from nps.network_entity import NetworkEntity
from nps.accessibility import MacAddressHelper, AccessibilityManager


class TestMacAddrHelper(MacAddressHelper):
    def get_interface_mac_addr(self, interface):
        pass

    def request_arp(self, ip):
        pass


class TestParser(unittest.TestCase):
    def setUp(self):
        self.accessibility_manager = AccessibilityManager()
        self.test_entity = NetworkEntity("test")

        self.parser = XmlTestCaseParser(TestMacAddrHelper(),
                                        self.accessibility_manager)

    def tearDown(self):
        pass

    def __get_xml_root_by_data(self, string_data):
        return ET.fromstring(string_data)

    def test_parse_accessibilty_tag(self):
        tc_str = """
<accessibility>
 <addressBinding>
  <client>
   <interface>eth2</interface>
   <source>
    <mac>00:00:11:11:11:11</mac>
    <ip>3.1.1.1</ip>
    <port>45678</port>
   </source>
   <destination>
    <mac>00:00:11:11:11:12</mac>
    <ip>3.1.1.2</ip>
    <port>80</port>
   </destination>
  </client>
 </addressBinding>
</accessibility>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._analyze_accessbility_node(root_node, self.test_entity, None)

        addressbinding = self.accessibility_manager.get_list()[0]
        self.assertEqual(addressbinding.get_src_mac(), "00:00:11:11:11:11")
        self.assertEqual(addressbinding.get_src_ip(), "3.1.1.1")
        self.assertEqual(addressbinding.get_src_port(), 45678)
        self.assertEqual(addressbinding.get_dest_mac(), "00:00:11:11:11:12")
        self.assertEqual(addressbinding.get_dest_ip(), "3.1.1.2")
        self.assertEqual(addressbinding.get_dest_port(), 80)

    def test_parse_accessibilty_tag2(self):
        tc_str = """
<accessibility>
 <autoFillSeqAck>
  <clientStartSeq>1000</clientStartSeq>
  <serverStartSeq>2000</serverStartSeq>
 </autoFillSeqAck>
</accessibility>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._analyze_accessbility_node(root_node, self.test_entity, None)

        auto_fill = self.accessibility_manager.get_list()[0]
        self.assertEqual(auto_fill.get_client_tcp_sequence(), 1000)
        self.assertEqual(auto_fill.get_server_tcp_sequence(), 2000)

    def test_parse_client_interface(self):
        tc_str = """
<client interface="eth0">
</client>
"""
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._analyze_entity_node(root_node, self.test_entity)
        self.assertEqual(self.test_entity.get_interface_name(), "eth0")

    def test_parse_packet_send_tag(self):
        tc_str = """
<packet>
  <action>send</action>
  <step>connection_open</step>
  <delay>100</delay>
</packet>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_packet_action(), "send")
        self.assertEqual(packet_buff.get_packet_delay(), 100L)
        self.assertEqual(packet_buff.get_tc_step(), "connection_open")

    def test_parse_packet_recv_tag(self):
        tc_str = """
<packet>
  <action>recv</action>
  <step>connection_open</step>
  <timeo>30</timeo>
</packet>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_packet_action(), "recv")
        self.assertEqual(packet_buff.get_timeo(), 30L)
        self.assertEqual(packet_buff.get_tc_step(), "connection_open")

    def test_parse_eth_packet_tag(self):
        tc_str = """
<packet>
  <eth>
   <src>aa:00:00:00:00:01</src>
   <dest>aa:00:00:00:00:02</dest>
  </eth>
</packet>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_src_eth(), "aa:00:00:00:00:01")
        self.assertEqual(packet_buff.get_dest_eth(), "aa:00:00:00:00:02")

    def test_parse_ipv4_packet_tag(self):
        tc_str = """
<packet>
  <ip>
   <src>1.1.1.1</src>
   <dest>2.2.2.2</dest>
  </ip>
</packet>
        """

        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_src_ip_addr(), "1.1.1.1")
        self.assertEqual(packet_buff.get_dest_ip_addr(), "2.2.2.2")

    def test_parse_tcp_header_packet_tag(self):
        tc_str = """
<packet>
  <tcp>
   <srcPort>5555</srcPort>
   <destPort>80</destPort>
   <flag>syn</flag>
   <seq>1000</seq>
   <ack>0</ack>
  </tcp>
</packet>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_src_port(), 5555)
        self.assertEqual(packet_buff.get_dest_port(), 80)
        self.assertEqual(packet_buff.get_tcp_seq(), 1000L)
        self.assertEqual(packet_buff.get_tcp_ack(), 0L)
        self.assertEqual(packet_buff.get_tcp_flag(), "S")
        self.assertEqual(packet_buff.get_tcp_sack_permitted(), False)
        self.assertEqual(packet_buff.get_tcp_mss(), 1460)

    def test_parse_tcp_header_packet_tag2(self):
        tc_str = """
<packet>
  <tcp>
   <srcPort>4444</srcPort>
   <destPort>81</destPort>
   <flag>fin+ack</flag>
   <seq>1000</seq>
   <ack>999</ack>
  </tcp>
</packet>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_src_port(), 4444)
        self.assertEqual(packet_buff.get_dest_port(), 81)
        self.assertEqual(packet_buff.get_tcp_seq(), 1000L)
        self.assertEqual(packet_buff.get_tcp_ack(), 999L)
        self.assertEqual(packet_buff.get_tcp_flag(), "FA")

    def test_parse_tcp_header_packet_tag3(self):
        tc_str = """
<packet>
  <tcp>
   <srcPort>5555</srcPort>
   <destPort>80</destPort>
   <flag>push</flag>
   <seq>1200</seq>
   <ack>1</ack>
  </tcp>
</packet>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_src_port(), 5555)
        self.assertEqual(packet_buff.get_dest_port(), 80)
        self.assertEqual(packet_buff.get_tcp_seq(), 1200L)
        self.assertEqual(packet_buff.get_tcp_ack(), 1L)
        self.assertEqual(packet_buff.get_tcp_flag(), "P")


    def test_parse_tcp_options_packet_tag(self):
        #
        # TODO: tcp options sle, sre
        tc_str = """
<packet>
  <tcp>
   <mss>1440</mss>
   <sackPerm>true</sackPerm>
  </tcp>
</packet>
        """
        root_node = self.__get_xml_root_by_data(tc_str)
        self.parser._set_packet_node(root_node, self.test_entity)

        packet_buff = self.test_entity.get_packet_list()[0]
        self.assertEqual(packet_buff.get_tcp_mss(), 1440)
        self.assertEqual(packet_buff.get_tcp_sack_permitted(), True)

    def test_parse_tcp_payload_packet_tag(self):
        # TODO!!!
        pass

