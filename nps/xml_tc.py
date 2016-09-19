# -*- coding: UTF-8 -*-

import subprocess
import xml.etree.ElementTree as ET

from nps.common import TcListAutoSeqAck, SERVER_TO_CLIENT, CLIENT_TO_SERVER
from nps.packet_info import PacketInfo

XML_EXTENTION = ".xml"
SCRIPT_BASE_PATH = "/opt/penta/nps/script/"
IFACE_CONF_PATH = "/opt/penta/nps/conf/ifaceConf.xml"
TCP_DATA_BASE_PATH = "/opt/penta/nps/script/tcpData/"
CLIENT_PORT_CONF_PATH = "/opt/penta/nps/conf/clientPort"
COMMON_SCRIPT_BASE_PATH = "/opt/penta/nps/script/include/"


class Xml2TcConverter():

    def get_bridge_port(self, direction):
        doc = ET.parse(IFACE_CONF_PATH)
        root = doc.getroot()

        bridgePort = ""

        for port in root.getiterator(direction):
            bridgePort = port.findtext("int")

        return bridgePort

    def analyze_xml_tc_file(self, filename, client_tc_list_info, server_tc_list_info):
        self._analyze_xml_tc_file(filename, client_tc_list_info, server_tc_list_info)

        tc_auto_seqack = TcListAutoSeqAck()
        if client_tc_list_info.get_auto_fill_seq_ack() == 'True':
            tc_auto_seqack.calc_tcp_seq(client_tc_list_info,
                                   long(client_tc_list_info.get_start_tcp_seq()),
                                   long(server_tc_list_info.get_start_tcp_seq()))
            tc_auto_seqack.calc_tcp_ack(client_tc_list_info,
                                   long(client_tc_list_info.get_start_tcp_seq()),
                                   long(server_tc_list_info.get_start_tcp_seq()))

        if server_tc_list_info.get_auto_fill_seq_ack() == 'True':
            tc_auto_seqack.calc_tcp_seq(server_tc_list_info,
                                   long(server_tc_list_info.get_start_tcp_seq()),
                                   long(client_tc_list_info.get_start_tcp_seq()))
            tc_auto_seqack.calc_tcp_ack(server_tc_list_info,
                                   long(server_tc_list_info.get_start_tcp_seq()),
                                   long(client_tc_list_info.get_start_tcp_seq()))

        for packetInfo in client_tc_list_info.get_packet_list():
            print 'client packet generated : ' + packetInfo._inner_value2str_s()

        for packetInfo in server_tc_list_info.get_packet_list():
            print 'server packet generated : ' + packetInfo._inner_value2str_s()

    def _analyze_xml_tc_file(self, filename, client_tc_list_info, server_tc_list_info):
        doc = ET.parse(SCRIPT_BASE_PATH + filename)
        root = doc.getroot()

        for child in root.getchildren():
            if child.tag == "client" or child.tag == "server":
                self._analyze_node(child, child.tag, client_tc_list_info, server_tc_list_info)
            elif child.tag == "script":
                self._analyze_xml_tc_file(child.text + XML_EXTENTION, client_tc_list_info, server_tc_list_info)
            elif child.tag == "autoFillSeqAck":
                client_tc_list_info.set_auto_fill_seq_ack(child.text)
                server_tc_list_info.set_auto_fill_seq_ack(child.text)
            elif child.tag == "clientStartSeq":
                client_tc_list_info.set_start_tcp_seq(child.text)
            elif child.tag == "serverStartSeq":
                server_tc_list_info.set_start_tcp_seq(child.text)

    def _analyze_tcp_info_node(self, packet_info, tcp_info_node):
        for child in tcp_info_node.getchildren():
            if child.tag == "fileName":
                packet_info.set_raw_data(self.get_tcp_data(child.text))
                packet_info.set_file_size(TCP_DATA_BASE_PATH, child.text)
            elif child.tag == "index":
                packet_info.set_tcp_index(child.text)
            elif child.tag == "length":
                packet_info.set_tcp_length(child.text)

    def _analyze_packet_node(self, packet_node, direction, client_tc_list_info, server_tc_list_info):
        packet_info = PacketInfo()
        packet_info.set_packet_action(packet_node.findtext("action"))

        if packet_node.findtext("delay") != None:
            packet_info.set_delay(packet_node.findtext("delay"))

        tcp_options = []
        if packet_node.findtext("include") != None:
            self._analyze_include_tc_file(
                "include/" + packet_node.findtext("include") + XML_EXTENTION,
                packet_info, direction, client_tc_list_info, server_tc_list_info,
                tcp_options)

        if packet_node.findtext("tcpDataFile") != None:
            packet_info.set_raw_data(self.get_tcp_data(packet_node.findtext("tcpDataFile")))
            packet_info.set_file_size(TCP_DATA_BASE_PATH, child.text)

        if packet_node.findtext("tcpDataInfo") != None:
            self._analyze_tcp_info_node(packet_info, packet_node.find("tcpDataInfo"))

        if packet_node.findtext("vrrpInfo") != None:
            self.analyzeVrrpInfoNode(packet_info, packet_node.find("vrrpInfo"))

        packet_info.set_tcp_flags(packet_node.findtext("flag"))

        if packet_node.findtext("window") != None:
            packet_info.set_window_size(packet_node.findtext("window"))

        if packet_node.findtext("seq") != None:
            packet_info.set_tcp_seq(packet_node.findtext("seq"))

        if packet_node.findtext("ack") != None:
            packet_info.set_tcp_ack(packet_node.findtext("ack"))

        if packet_node.findtext("step") != None:
            packet_info.set_tc_step(packet_node.findtext("step"))

        if packet_node.findtext("timeo") != None:
            packet_info.set_timeo(packet_node.findtext("timeo"))

        if (packet_node.findtext("sle") != None) and (packet_node.findtext("sre") != None):
            sle = long(packet_node.findtext("sle"))
            sre = long(packet_node.findtext("sre"))
            tcp_options.append(("SAck", (sle, sre)))

        if ((packet_node.findtext("sle") != None) != (packet_node.findtext("sre") != None)):
            print "[WARNING] sle, sre value must be used together!!"

        if (packet_node.findtext("sackPerm") != None):
            tcp_options.append(("SAckOK", ""))

        packet_info.replace_tcp_options(tcp_options)

        if direction == SERVER_TO_CLIENT:
            server_tc_list_info.append_packet_list(packet_info)
        elif direction == CLIENT_TO_SERVER:
            client_tc_list_info.append_packet_list(packet_info)

    def _analyze_node(self, node, direction, client_tc_list_info, server_tc_list_info):
        for child in node.getchildren():
            if child.tag == "packet" or child.tag == "bigPacket":
                self._analyze_packet_node(child, direction, client_tc_list_info, server_tc_list_info)

    def _analyze_include_tc_file(self, filename, packet_info, direction,
                                 client_tc_list_info, server_tc_list_info, tcp_options):
        doc = ET.parse(SCRIPT_BASE_PATH + filename)
        root = doc.getroot()

        if packet_info == None:
            return

        for object_node in root.getiterator("object"):
            if object_node.findtext("include") != None:
                self._analyze_common_tc_file(
                    "include/" + object_node.findtext("include") +
                    XML_EXTENTION, packet_info, direction, client_tc_list_info,
                    server_tc_list_info)

            # REFACTORING
            if object_node.findtext("clientInt") != None:
                self._analyze_common_tc_file(filename, packet_info, direction, client_tc_list_info, server_tc_list_info)

            packet_info.set_tc_step(object_node.findtext("step"))
            packet_info.set_tcp_flags(object_node.findtext("flag"))

            if object_node.findtext("window") != None:
                packet_info.set_window_size(object_node.findtext("window"))

            if object_node.findtext("seq") != None:
                packet_info.set_tcp_seq(object_node.findtext("seq"))

            if object_node.findtext("ack") != None:
                packet_info.set_tcp_ack(object_node.findtext("ack"))

            if (object_node.findtext("sle") != None) and ( object_node.findtext("sre") != None):
                sle = long(object_node.findtext("sle"))
                sre = long(object_node.findtext("sre"))
                tcp_options.append(("SAck", (sle, sre)))

            if (object_node.findtext("sackPerm") != None):
                tcp_options.append(("SAckOK", ""))

    def get_interface_mac_addr(self, interface):
        with open('/sys/class/net/{0}/address'.format(interface), 'r') as f:
            return f.read().replace('\n','')

    def _analyze_common_tc_file(self, filename, pkt_inf, in_direction, client_tc_list_info, server_tc_list_info):
        doc = ET.parse(SCRIPT_BASE_PATH + filename)
        root = doc.getroot()

        client_nic_name = ""
        server_nic_name = ""
        client_mac = ""
        server_mac = ""
        dut_client_side_mac = ""
        dut_server_side_mac = ""
        client_ip = ""
        server_ip = ""
        dut_client_side_ip = ""
        dut_server_side_ip = ""
        client_tcp_port = ""
        server_tcp_port = ""
        dut_client_side_tcp_port = ""
        dut_server_side_tcp_port = ""
        use_nat_port = "False"

        for object_node in root.getiterator("object"):
            client_nic_name = object_node.findtext("clientInt")
            server_nic_name = object_node.findtext("serverInt")

            client_mac = self.get_interface_mac_addr(client_nic_name)
            server_mac = self.get_interface_mac_addr(server_nic_name)

            dut_client_side_mac = server_mac
            dut_server_side_mac = client_mac

            client_ip = object_node.findtext("clientIp")
            server_ip = object_node.findtext("serverIp")

            dut_client_side_ip = server_ip
            dut_server_side_ip = client_ip

            client_tcp_port = object_node.findtext("clientPort")
            server_tcp_port = object_node.findtext("serverPort")

            dut_client_side_tcp_port = server_tcp_port
            dut_server_side_tcp_port = client_tcp_port

            if (object_node.findtext("wpClientMac") != None) and (object_node.findtext("wpServerMac") != None):
                dut_client_side_mac = object_node.findtext("wpClientMac")
                dut_server_side_mac = object_node.findtext("wpServerMac")

            if (object_node.findtext("wpClientIp") != None) and (object_node.findtext("wpServerIp") != None):
                dut_client_side_ip = object_node.findtext("wpClientIp")
                dut_server_side_ip = object_node.findtext("wpServerIp")

            if (object_node.findtext("wpClientPort") != None) and (object_node.findtext("wpServerPort") != None):
                dut_client_side_tcp_port = object_node.findtext("wpClientPort")
                dut_server_side_tcp_port = object_node.findtext("wpServerPort")

            if (int(dut_client_side_tcp_port) == client_tc_list_info.get_nat_magic_number() or
                    int(dut_server_side_tcp_port) == server_tc_list_info.get_nat_magic_number()):
                use_nat_port = "True"

            #proxy일 때 : client - DUT - server
            #inline일 때 : client - server
            act = pkt_inf.get_packet_action()
            if in_direction == CLIENT_TO_SERVER:
                if (act == 'recv'):
                    pkt_inf.set_ether_datas(dut_client_side_mac, client_mac)
                    pkt_inf.set_ip_addr(dut_client_side_ip, client_ip)
                    pkt_inf.set_tcp_port_num(dut_client_side_tcp_port, client_tcp_port)
                else:
                    pkt_inf.set_ether_datas(client_mac, dut_client_side_mac)
                    pkt_inf.set_ip_addr(client_ip, dut_client_side_ip)
                    pkt_inf.set_tcp_port_num(client_tcp_port, dut_client_side_tcp_port)
            elif in_direction == SERVER_TO_CLIENT:
                if (act == 'recv'):
                    pkt_inf.set_ether_datas(dut_server_side_mac, server_mac)
                    pkt_inf.set_ip_addr(dut_server_side_ip, server_ip)
                    pkt_inf.set_tcp_port_num(dut_server_side_tcp_port, server_tcp_port)
                else:
                    pkt_inf.set_ether_datas(server_mac, dut_server_side_mac)
                    pkt_inf.set_ip_addr(server_ip, dut_server_side_ip)
                    pkt_inf.set_tcp_port_num(server_tcp_port, dut_server_side_tcp_port)

        #end of loop

        client_tc_list_info.set_interface(client_nic_name, client_mac)
        server_tc_list_info.set_interface(server_nic_name, server_mac)

        client_tc_list_info.set_interface_ip_addr(client_ip)
        server_tc_list_info.set_interface_ip_addr(server_ip)

        client_tc_list_info.set_interface_tcp_port(client_tcp_port)
        server_tc_list_info.set_interface_tcp_port(server_tcp_port)

        client_tc_list_info.set_use_nat_port(use_nat_port)
        server_tc_list_info.set_use_nat_port(use_nat_port)

    def get_tcp_data(self, fileName):
        f = open(TCP_DATA_BASE_PATH + fileName, "r")

        data = ""
        for line in f.readlines():
            data += line

        f.close()
        return data

    def get_client_port(self):
        f = open(CLIENT_PORT_CONF_PATH, "r")
        port = f.read()
        f.close()
        return port
