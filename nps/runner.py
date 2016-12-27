#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import optparse
import time
import threading
import Queue
from multiprocessing import Process

from nps.core import PacketSimulator, PacketSniff
from nps.parser import XmlTestCaseParser
from nps.network_entity import NetworkEntity
from nps.accessibility import AccessibilityManager, MacAddressHelper
from nps.file_log import *


def process_main(network_entity, ):
    recv_queue_lock = threading.Lock()

    # create queue for packet receive.
    # send/recv의 복잡한 구조를 피하기 위해 recv thread를 별도로 만들었고,
    # scapy sniff으로 전달 받은 패킷들을 직접 처리하지 않고 queue에 포함시킨다.
    recv_queue = Queue.Queue()

    sniff = PacketSniff()
    recv_thread = threading.Thread(target=sniff.register,
                                   args=(recv_queue, recv_queue_lock, network_entity))

    # packet simulator thread에서 send/recv에 대한 모든 처리를 한다.
    # send는 tc를 parsing항 얻은 packet 정보를 활용하여 전송하고,
    # recv는 sniff에서 넣어준 recv queue를 활용한다.
    simulator = PacketSimulator(network_entity, recv_queue, recv_queue_lock)
    simulation_thread = threading.Thread(target=simulator.start)

    recv_thread.start()

    time.sleep(1)

    simulation_thread.start()

    simulation_thread.join()

    # sniff function of recv_thread does not terminate.
    # to terminate sniff, use the stop_filter of the sniff function.
    # need an idea of stop_filter implementation.
    #
    #recv_thread.join()


def main():
    parser = optparse.OptionParser('%prog -f <TC file name>')
    parser.add_option('-f', dest='tc_filename', type='string', help='TC file name')

    (options, args) = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        exit(0)

    if options.tc_filename is None:
        print('TC file is not exist.')
        exit(0)

    mac_addr_helper = MacAddressHelper()
    accessibility_manager = AccessibilityManager()
    parser = XmlTestCaseParser(mac_addr_helper, accessibility_manager)

    server = NetworkEntity("server")
    client = NetworkEntity("client")

    parser.analyze_tc_file(options.tc_filename, client, server)

    server_process = None
    if server.is_empty_packet_list() == False:
        server_iface = server.get_interface_name()
        server_start_time = write_report_init(server_iface, options.tc_filename)
        server_process = Process(target=process_main, args=(server, ))
        server_process.start()

    time.sleep(1)

    client_process = None
    if client.is_empty_packet_list() == False:
        client_iface = client.get_interface_name()
        client_start_time = write_report_init(client_iface, options.tc_filename)
        client_process = Process(target=process_main, args=(client, ))
        client_process.start()

    if client_process is not None:
        client_process.join()
        write_report_close(client_iface, client_start_time)

    if server_process is not None:
        server_process.join()
        write_report_close(server_iface, server_start_time)


if __name__ == '__main__':
    main()
