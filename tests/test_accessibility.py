# -*- coding: utf-8 -*-
import unittest

from nps.packet_buff import PacketBuff
from nps.network_entity import NetworkEntity
from nps.accessibility import MacAddressHelper, AddressBinder


class TestMacAddressHelper(MacAddressHelper):
    def _request_arp(self, ip):
        if ip == "1.1.1.1":
            return "00:00:00:00:00:01"
        if ip == "1.1.1.2":
            return "00:00:00:00:00:02"
        if ip == "1.1.1.3":
            return "00:00:00:00:00:03"

        return None


class TestAccessbility(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_process_addressbinding(self):
        test_entity = NetworkEntity("test")

        packet_buff1 = PacketBuff()
        packet_buff1.set_packet_action("send")
        packet_buff2 = PacketBuff()
        packet_buff2.set_packet_action("recv")

        test_entity.append_packet_list(packet_buff1)
        test_entity.append_packet_list(packet_buff2)

        ab = AddressBinder(test_entity)
        ab.set_src_addr("AA:BB:00:00:00:01", "10.0.0.100", 4567)
        ab.set_dest_addr("BB:CC:00:00:00:01", "10.0.0.200", 8080)

        ab.process()

        self.assertEqual(packet_buff1.get_src_eth(), "AA:BB:00:00:00:01")
        self.assertEqual(packet_buff1.get_src_ip_addr(), "10.0.0.100")
        self.assertEqual(packet_buff1.get_src_port(), 4567)

        self.assertEqual(packet_buff1.get_dest_eth(), "BB:CC:00:00:00:01")
        self.assertEqual(packet_buff1.get_dest_ip_addr(), "10.0.0.200")
        self.assertEqual(packet_buff1.get_dest_port(), 8080)

        self.assertEqual(packet_buff2.get_src_eth(), "BB:CC:00:00:00:01")
        self.assertEqual(packet_buff2.get_src_ip_addr(), "10.0.0.200")
        self.assertEqual(packet_buff2.get_src_port(), 8080)

        self.assertEqual(packet_buff2.get_dest_eth(), "AA:BB:00:00:00:01")
        self.assertEqual(packet_buff2.get_dest_ip_addr(), "10.0.0.100")
        self.assertEqual(packet_buff2.get_dest_port(), 4567)

    def test_request_arp_mac_address_helper(self):
        test_mac_addr_helper = TestMacAddressHelper()

        # request arp
        ip = "1.1.1.1"
        mac = test_mac_addr_helper.request_arp(ip)
        self.assertEqual(mac, "00:00:00:00:00:01")

        ip = "1.1.1.2"
        mac = test_mac_addr_helper.request_arp(ip)
        self.assertEqual(mac, "00:00:00:00:00:02")

        ip = "1.1.1.8"
        mac = test_mac_addr_helper.request_arp(ip)
        self.assertEqual(mac, None)

        # confirm learn mac addr
        ip = "1.1.1.1"
        self.assertEqual(test_mac_addr_helper.get_mac_addr_cache(ip), "00:00:00:00:00:01")

        ip = "1.1.1.2"
        self.assertEqual(test_mac_addr_helper.get_mac_addr_cache(ip), "00:00:00:00:00:02")

        ip = "1.1.1.8"
        self.assertEqual(test_mac_addr_helper.get_mac_addr_cache(ip), None)

        # clear mac addr
        test_mac_addr_helper.clear_mac_addr_cache()

        ip = "1.1.1.1"
        self.assertEqual(test_mac_addr_helper.get_mac_addr_cache(ip), None)
