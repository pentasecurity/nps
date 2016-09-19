#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import os
import optparse
import time
import ctypes

from nps.xml_tc import Xml2TcConverter
from nps.common import TcListInfo
from nps.process import process_main
from nps.file_log import *
from multiprocessing import Process, Manager, Lock


def main():
    parser = optparse.OptionParser('%prog -f <TC file name>')
    parser.add_option('-f', dest='tcFileName', type='string', help='TC file name')

    (options, args) = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        exit(0)

    tc_converter = Xml2TcConverter()

    if options.tcFileName == None:
        print 'tc File is not exist'
        exit(0)

    server_tc_list_info = TcListInfo("server")
    client_tc_list_info = TcListInfo("client")

    tc_converter.analyze_xml_tc_file(options.tcFileName, client_tc_list_info, server_tc_list_info)

    server_process = None
    if server_tc_list_info.is_empty_packet_list() != True:
        server_iface = server_tc_list_info.get_interface_name()
        server_start_time = write_report_init(server_iface, options.tcFileName)
        server_process = Process(target=process_main, args=(server_tc_list_info, ))
        server_process.start()

    client_process = None
    if client_tc_list_info.is_empty_packet_list() != True:
        client_iface = client_tc_list_info.get_interface_name()
        client_start_time = write_report_init(client_iface, options.tcFileName)
        client_process = Process(target=process_main, args=(client_tc_list_info, ))
        client_process.start()

    time.sleep(2)

    if client_process is not None:
        client_process.join()
        write_report_close(client_iface, client_start_time)

    if server_process is not None:
        server_process.join()
        write_report_close(server_iface, server_start_time)


if __name__ == '__main__':
    main()
