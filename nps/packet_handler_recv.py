# -*- coding: UTF-8 -*-

from scapy.all import *


def get_basic_capture_filter(tc_list_info):
    """
    tcp/ip filter를 통해 정해진 값들만 sniff 하도록 설정하는 함수
    :param tc_list_info:
    :return: filter info
    """
    filter = 'tcp and (host {0} '.format(tc_list_info.get_interface_ip_addr()) + ')'

    #수집 과정에서 미리 인터페이스 클래스에 proxy 사용 여부를 저장해놓음.
    #프록시를 사용한다면, 어떤 포트가 할당될 지 모르기 때문에 포트에 해당하는 필터를
    #등록하지 않고 전부 수집하는 방향으로 설정함.
    #인라인 구성이라면 특정 포트만 수집하도록 설정
    if (tc_list_info.get_use_nat_port() == "False"):
        filter = filter + ' and (port {0} '.format(tc_list_info.get_interface_tcp_port()) + ')'

    print 'filter : ' + str(filter)
    return filter


def recv_packet_hook(recv_queue, recv_queue_lock, collect_mac):
    """
    우리가 기대하는 mac address를 갖고 있는 recv에 대해서만 처리하도록 handler를 등록한다
    참고로 sniff 함수는 rx/tx 모두 받도록 되어 있다
    :param recv_queue:
    :param recv_queue_lock:
    :param collect_mac:
    :return:
    """
    def hook_handler(packet):
        #recv 하는 맥만 받도록 설정..
        #sniff 함수는 rx/tx 모두 받도록 되어있어서, 인터페이스가 한 머신 안에 존재하면
        #둘다 캡쳐하게 되어있음.(tcpdump와 그 동작 방식이 같음)
        if (packet['Ethernet'].dst != collect_mac):
            return

        #패킷을 수신하고 나서는 recvQ에 넣어놓음.
        with recv_queue_lock:
            recv_queue.put(packet)

    return hook_handler


def recv_queue_thread(recv_queue, recv_queue_lock, tc_list_info):
    """
    nps에서 recv queue에 대해서 처리하는 thread이다
    :param recv_queue:
    :param recv_queue_lock:
    :param tc_list_info:
    """
    captured_packet = sniff(
        iface=tc_list_info.get_interface_name(),
        filter=get_basic_capture_filter(tc_list_info),
        prn=recv_packet_hook(recv_queue, recv_queue_lock, tc_list_info.get_interface_mac_addr()))
