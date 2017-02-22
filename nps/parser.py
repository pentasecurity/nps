# -*- coding: UTF-8 -*-
import xml.etree.ElementTree as ET
from nps.packet_buff import PacketBuff
from nps.accessibility import AddressBinder, TcListAutoSeqAck


class XmlTestCaseParser():
    XML_EXTENTION = ".xml"
    TC_SERVER_NODE = "server"
    TC_CLIENT_NODE = "client"
    TC_ACCESSIBILLITY_NODE = "accessibility"
    TC_AUTOFILL_TCP_SEQ = "autoFillSeqAck"

    def __init__(self, tc_dir,  mac_addr_helper, ac_manager):
        # set directory
        self.script_base_dir = tc_dir
        self.common_data_dir = self.script_base_dir + "/data/"
        self.common_script_dir = self.script_base_dir + "/include/"

        self.accessbility_manager = ac_manager
        self.mac_addr_helper = mac_addr_helper

        # verbose variable for debuggin
        self.print_entity_packetlist = False
        self.print_tc_preprocessing = False

    def get_common_script_dir(self):
        return self.common_script_dir

    def get_data_base_dir(self):
        return self.common_data_dir

    def __get_xml_root_by_file(self, filename):
        """xml file open"""
        doc = ET.parse(filename)
        return doc.getroot()

    def __indent(self, elem, level=0):
        """xml indent method"""
        i = "\n" + level*"  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                self.__indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i

    def __get_tcp_data_from_file(self, fileName):
        f = open(self.common_data_dir + fileName, "r")

        data = ""
        for line in f.readlines():
            data += line

        f.close()
        return data

    def analyze_tc_file(self, filename, client_entity, server_entity):
        root_node = self.__get_xml_root_by_file(self.script_base_dir + filename)

        self._analyze_tc(root_node, client_entity, server_entity)

        if self.accessbility_manager is not None:
            self.accessbility_manager.process()

        # print packetlist for debugging
        if self.print_entity_packetlist is True:
            for packet_buff in client_entity.get_packet_list():
                print("client packet generated : " + packet_buff._inner_value2str_s())

            for packet_buff in server_entity.get_packet_list():
                print("server packet generated : " + packet_buff._inner_value2str_s())

    def _analyze_tc(self, root, client_entity, server_entity):
        for child in root.getchildren():
            if child.tag == XmlTestCaseParser.TC_CLIENT_NODE:
                self._analyze_entity_node(child, client_entity)

            elif child.tag == XmlTestCaseParser.TC_SERVER_NODE:
                self._analyze_entity_node(child, server_entity)

            elif child.tag == XmlTestCaseParser.TC_ACCESSIBILLITY_NODE:
                self._analyze_accessbility_node(child, client_entity, server_entity)

    def _analyze_entity_node(self, node, entity):
        interface = node.get("interface")
        if interface is not None:
            mac_address = self.mac_addr_helper.get_interface_mac_addr(interface)
            entity.set_interface(interface, mac_address)

        for child in node.getchildren():
            if child.tag == "packet":
                # pre processing "include" node
                # TODO: Possible to be deleted
                #self.__add_include_to_packet_node(child)

                # analyze packet node!
                self._set_packet_node(child, entity)

        if self.print_tc_preprocessing is True:
            self.__indent(node)
            ET.dump(node)

    def __add_include_to_packet_node(self, packet_node):
        include_nodes = packet_node.findall("include")
        for include_node in include_nodes:
            include_root_node = self.__get_xml_root_by_file(common_script_dir +
                                                            include_node.text +
                                                            XmlTestCaseParser.XML_EXTENTION)

            # "include" tag allow object root node only
            if include_root_node.tag != "object":
                continue

            for node in include_root_node.getchildren():
                packet_node.append(node)

            # remove "include" node
            packet_node.remove(include_node)

    def _set_packet_node(self, packet_node, entity):
        packet_buff = PacketBuff()

        # README: Keep the packet tag simple.
        #
        # The packet tag should contain packet data.
        # Except the four(action, step,...) user settings, all settings for packet data.
        # if you need adding user settings, use the AccessibilityManager or NetworkEntity.
        if packet_node.findtext("action") is not None:
            packet_buff.set_packet_action(packet_node.findtext("action"))

        if packet_node.findtext("step") is not None:
            packet_buff.set_tc_step(packet_node.findtext("step"))

        if packet_node.findtext("delay") is not None:
            packet_buff.set_delay(packet_node.findtext("delay"))

        if packet_node.findtext("timeo") is not None:
            packet_buff.set_timeo(packet_node.findtext("timeo"))

        self.__set_eth_to_packetbuff(packet_buff, packet_node)
        self.__set_ip_to_packetbuff(packet_buff, packet_node)
        self.__set_tcp_to_packetbuff(packet_buff, packet_node)

        entity.append_packet_list(packet_buff)

    def __set_eth_to_packetbuff(self, packet_buff, packet_node):
        eth_node = packet_node.find("eth")
        if eth_node is None:
            return

        src_mac = eth_node.findtext("src")
        dest_mac = eth_node.findtext("dest")
        packet_buff.set_ether_datas(dest_mac, src_mac)

    def __set_ip_to_packetbuff(self, packet_buff, packet_node):
        ip_node = packet_node.find("ip")
        if ip_node is None:
            return

        src_ip = ip_node.findtext("src")
        dest_ip = ip_node.findtext("dest")
        packet_buff.set_ip_addr(dest_ip, src_ip)

    def __set_tcp_to_packetbuff(self, packet_buff, packet_node):
        tcp_node = packet_node.find("tcp")
        if tcp_node is None:
            return

        src_port = tcp_node.findtext("srcPort")
        dest_port = tcp_node.findtext("destPort")
        packet_buff.set_tcp_port_num(dest_port, src_port)

        if tcp_node.findtext("seq") != None:
            packet_buff.set_tcp_seq(tcp_node.findtext("seq"))

        if tcp_node.findtext("ack") != None:
            packet_buff.set_tcp_ack(tcp_node.findtext("ack"))

        packet_buff.set_tcp_flags(tcp_node.findtext("flag"))

        if tcp_node.findtext("window") != None:
            packet_buff.set_window_size(tcp_node.findtext("window"))

        # set tcp options
        if (tcp_node.findtext("sackPerm") != None):
            packet_buff.set_tcp_sack_permitted()

        if (tcp_node.findtext("mss") != None):
            packet_buff.set_tcp_mss(tcp_node.findtext("mss"))

        # TODO: sle, sre has multiple value!
        if (tcp_node.findtext("sle") != None) and (tcp_node.findtext("sre") != None):
            packet_buff.set_tcp_sack_block(tcp_node.findtext("sle"), tcp_node.findtext("sre"))

        if ((tcp_node.findtext("sle") != None) != (tcp_node.findtext("sre") != None)):
            print("[WARNING] sle, sre value of tcp options must be used together.")

        # TODO: payload tag
        #  tcpDataFile and tcpDataInfo => payload
        if tcp_node.findtext("tcpDataFile") != None:
            tcp_data_node = tcp_node.findtext("tcpDataFile")
            packet_buff.set_raw_data(self.__get_tcp_data_from_file(tcp_data_node.text))
            packet_buff.set_file_size(self.common_data_dir, tcp_data_node.text)

        if tcp_node.findtext("tcpDataInfo") != None:
            # TODO: refactoring => set_raw_data
            # set_raw_data used to so much memory
            tcp_info_node = tcp_node.findtext("tcpDataInfo")
            for child in tcp_info_node.getchildren():
                if child.tag == "fileName":
                    packet_buff.set_raw_data(self.__get_tcp_data_from_file(child.text))
                    packet_buff.set_file_size(self.common_data_dir, child.text)
                elif child.tag == "index":
                    packet_buff.set_tcp_index(child.text)
                elif child.tag == "length":
                    packet_buff.set_tcp_length(child.text)

    def _analyze_accessbility_node(self, accessbility_node, client_entity, server_entity):
        ab_node = accessbility_node.find("addressBinding")
        if ab_node is not None:
            client_node = ab_node.find("client")
            self.__set_address_binding(client_node, client_entity)

            server_node = ab_node.find("server")
            self.__set_address_binding(server_node, server_entity)

        # auto_fill_seqack need client and server entity both
        auto_node = accessbility_node.find("autoFillSeqAck")
        if auto_node is not None:
            self.__set_auto_fill_seqack(auto_node, client_entity, server_entity)

    def __set_address_binding(self, node, entity):
        if node is None:
            return

        # first, set entity interface setting
        interface = node.findtext("interface")
        if interface is not None:
            mac_address = self.mac_addr_helper.get_interface_mac_addr(interface)
            entity.set_interface(interface, mac_address)

        # set address binder, source setting
        #
        ab = AddressBinder(entity)

        src_node = node.find("source")

        # source ip/port
        src_ip = src_node.findtext("ip")
        src_port = src_node.findtext("port")
        src_mac = ""

        # source mac
        src_mac_node = src_node.find("mac")
        src_mac_property = src_mac_node.get("value")

        if src_mac_property is None or src_mac_property == "static":
            src_mac = src_mac_node.text
        elif src_mac_property == "interface":
            src_mac = entity.get_interface_mac_addr()
        elif src_mac_property == "arp":
            src_mac = self.mac_addr_helper.request_arp(src_ip)

        ab.set_src_addr(src_mac, src_ip, src_port)

        # set address binder, destination setting
        #
        dest_node = node.find("destination")

        # destination ip/port
        dest_ip = dest_node.findtext("ip")
        dest_port = dest_node.findtext("port")
        dest_mac = ""

        # destination mac
        dest_mac_node = dest_node.find("mac")
        dest_mac_property = dest_mac_node.get("value")

        if dest_mac_property is None or dest_mac_property == "static":
            dest_mac = dest_mac_node.text
        elif dest_mac_property == "interface":
            dest_mac = entity.get_interface_mac_addr()
        elif dest_mac_property == "arp":
            dest_mac = self.mac_addr_helper.request_arp(dest_ip)

        ab.set_dest_addr(dest_mac, dest_ip, dest_port)

        # add to accessbility manager
        #
        self.accessbility_manager.add(ab)

    def __set_auto_fill_seqack(self, auto_node, client_entity, server_entity):
        client_start_tcp_seq = 0L
        server_start_tcp_seq = 0L

        client_seq = auto_node.findtext("clientStartSeq")
        if client_seq is not None:
            client_start_tcp_seq = long(client_seq)

        server_seq = auto_node.findtext("serverStartSeq")
        if server_seq is not None:
            server_start_tcp_seq = long(server_seq)

        auto_seqack = TcListAutoSeqAck(client_entity, server_entity)
        auto_seqack.set_tcp_sequence(client_start_tcp_seq, server_start_tcp_seq)

        # add to accessbility manager
        #
        self.accessbility_manager.add(auto_seqack)
