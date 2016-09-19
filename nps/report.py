# -*- coding: UTF-8 -*-
# XXX: Please do not use this - it's working on it

import os
import codecs
import nps.packet_info


CAPTURED_PACKET_REPORT_PATH = "/root/scapy/caputerd_packet.report"


class nps_report():
    received_packet_info_list = []

    def write_captured_packet_info(self, direction, captured_packet_info):
        with codecs.open(CAPTURED_PACKET_REPORT_PATH, 'a', encoding='utf-8') as f :
            f.write("direction : %s\n" % direction)
            f.write("#########################################\n")
            for rawData in str(captured_packet_info).split('/'):
                f.write(rawData)
                f.write("\n")
            f.write("#########################################\n\n")

    def remove_previous_dumpfile(self):
        if os.path.exists(CAPTURED_PACKET_REPORT_PATH):
            os.remove(CAPTURED_PACKET_REPORT_PATH)

    def convert_received_packet2packet_Info(self, rawPacketDataList):
        for packet in rawPacketDataList:
            packetInfo = packet_info.PacketInfo()
            packetInfo.initialize(packet)
            self.received_packet_info_list.append(packetInfo)

    def get_received_packet_list(self):
        return self.received_packet_info_list
