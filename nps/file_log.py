# -*- coding: UTF-8 -*-

import time
from nps.packet_lib import TcpFlagInfo

NPS_DEBUG_LOG_FILE = "debug.log"
NPS_REPORT_FILE_EXTENSION = ".rpt"


def make_packet_str(p, l):
    """
    make_packet_str: interface_name.rpt 파일로 로그를 적는 함수
    :param p:
    :param l:
    :return: ret
    """
    tcpfunc = TcpFlagInfo()
    ret = "%s(%s) -> [%s], Seq[%s], Ack[%s], len[%s]-> %s(%s)\n" % (
        str(p['IP'].src).center(15), str(p['TCP'].sport).center(5),
        str(tcpfunc.flagnumber2char(p['TCP'].flags)).center(3),
        str(p['TCP'].seq).center(6), str(p['TCP'].ack).center(6),
        str(l).center(5), str(p['IP'].dst).center(15),
        str(p['TCP'].dport).center(5))
    return ret


def write_log_file(msg):
    with open(NPS_DEBUG_LOG_FILE, "a") as f:
        log_msg = str(time.time()) + ' '
        log_msg = log_msg + msg + '\n'
        f.write(log_msg)


def write_report_file(interface, msg):
    with open(interface + NPS_REPORT_FILE_EXTENSION, "w") as f:
        f.write(msg)


def write_report_file_line(interface, msg):
    with open(interface + NPS_REPORT_FILE_EXTENSION, "a") as f:
        log_msg = str(time.time()) + ' '
        log_msg = log_msg + msg + '\n'
        f.write(log_msg)


def write_report_init(interface, conf_file):
    start_time = time.time()
    with open(interface + NPS_REPORT_FILE_EXTENSION, "w") as f:
        log_msg = '======================================================================================\n'
        log_msg = log_msg + 'Conf File : ' + conf_file + '\n'
        log_msg = log_msg + 'TC Program Start Time : ' + str(start_time) + '\n'
        log_msg = log_msg + '-------------------------------------------------------------------------------------\n'
        f.write(log_msg)

    return start_time


def write_report_close(interface, start_time):
    end_time = time.time()
    with open(interface + NPS_REPORT_FILE_EXTENSION, "a") as f:
        log_msg = '-------------------------------------------------------------------------------------\n'
        log_msg = log_msg + 'TC Program End Time : ' + str(end_time) + '\n'
        log_msg = log_msg + '======================================================================================\n'
        f.write(log_msg)


def write_packet_to_report_file(interface, step, action, packet, length):
    with open(interface + NPS_REPORT_FILE_EXTENSION, "a") as f:
        msg = str(time.time()).center(13) + '[' + step.center(16) + ']' + \
              '[' + action.center(5) + ']' + make_packet_str(packet,length)
        f.write(msg)


def write_fail_to_report_file(interface, action, fail):
    with open(interface + NPS_REPORT_FILE_EXTENSION, "a") as f:
        msg = str(time.time()) + '[' + action + ']' + fail + '\n'
        f.write(msg)


def write_debug_to_report_file(interface, msg):
    with open(interface + NPS_REPORT_FILE_EXTENSION, "a") as f:
        msg = str(time.time()) + msg
        f.write(msg)
