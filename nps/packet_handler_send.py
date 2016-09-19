# -*- coding: UTF-8 -*-

from scapy.all import *

from nps.timer import PeriodicThread
from nps.file_log import *
from nps.packet_lib import TcpFlagInfo


def send_packet(interface, step, tc, tc_list_info):
    """
    send_nps_packet 함수는 tc에 저장된 값을 토대로 각각의 계층을 만들어내서 전송한다
    :param interface:
    :param step:
    :param tc:
    :param tc_list_info:
    """
    eth = tc.get_ether_layer()
    ip4 = tc.get_ipv4_layer()

    #proxy port check
    sport = tc.get_src_port()
    dport = tc.get_dest_port()

    if (str(sport) == str(tc_list_info.get_nat_magic_number())):
        sport = tc_list_info.get_dut_nat_port()
    if (str(dport) == str(tc_list_info.get_nat_magic_number())):
        dport = tc_list_info.get_dut_nat_port()

    tcp = tc.get_tcp_layer_for_proxy(sport, dport)
    raw = tc.get_raw_data()
    packet = eth / ip4 / tcp / raw

    write_packet_to_report_file(interface, step, "send", packet, tc.get_tcp_len())
    sendp(packet, iface=interface)


def compare_tc_vs_packet(tc, packet, tc_list_info):
    """
    compare_tc_vs_packet 함수는 받은 패킷과 tc를 비교한다
    :param tc:
    :param packet:
    :param tc_list_info:
    :return:
    """
    if (tc.get_src_ip_addr() != packet['IP'].src):
        msg = 'sip not matched tc:' + str(tc.get_src_ip_addr()) + ',pckt:' + packet['IP'].src
        return msg
    if (tc.get_dest_ip_addr() != packet['IP'].dst):
        msg = 'dip not matched'
        return msg
    #nat 사용여부에 따라 port 비교 값 적용이 달라짐
    if (str(tc.get_src_port()) != str(packet['TCP'].sport)):
        msg = 'sport not matched ' + str(tc.get_src_port()) + ' ' + str(packet['TCP'].sport)
        print msg
        if (str(tc.get_src_port()) != str(tc_list_info.get_nat_magic_number())):
            msg = 'sport not matched ' + str(tc.get_src_port()) + ' ' + str(tc_list_info.get_nat_magic_number())
            return msg
        tc_list_info.set_dut_nat_port(packet['TCP'].sport)

    #nat 사용여부에 따라 port 비교 값 적용이 달라짐
    if (str(tc.get_dest_port()) != str(packet['TCP'].dport)):
        if (str(tc.get_dest_port()) != str(tc_list_info.get_nat_magic_number())):
            msg = 'dport not matched'
            return msg
        tc_list_info.set_dut_nat_port(packet['TCP'].dport)

    tcpFlagInfo = TcpFlagInfo()
    if (tc.get_tcp_flag() != tcpFlagInfo.flagnumber2char(packet['TCP'].flags)):
        if (tc.get_tcp_flag() == 'F'):
            if ('FA' == tcpFlagInfo.flagnumber2char(packet['TCP'].flags)):
                return 'same'
        elif (tc.get_tcp_flag() == 'P'):
            if ('PA' == tcpFlagInfo.flagnumber2char(packet['TCP'].flags)):
                return 'same'
        else:
            msg = 'flag not matched tc:' + str(tc.get_tcp_flag()) + ',pckt:' + str(packet['TCP'].flags)
            return msg

    return 'same'

#recv 시간 관련 이벤트 플래그, expire 되기 전 0을 가짐.
timer_flag = 0


def recv_expire_timer_callback(interface, tc_list, tc_list_lock):
    """
    recv 대기 시간이 만료되면 flag값을 1로 변경
    :param interface:
    :param tc_list:
    :param tc_list_lock:
    """
    global timer_flag
    timer_flag = 1


def recv_queue_loop(interface, step, recv_queue, recv_queue_lock, tc, tc_list_info):
    """
    recv queue에 새로운 데이터가 있는지 loop로 체크하는 함수
    :param interface:
    :param step:
    :param recv_queue:
    :param recv_queue_lock:
    :param tc:
    :param tc_list_info:
    :return:
    """
    packet = ''
    global timer_flag

    while True:
        #대기중에 recv timer flag가 1로 설정된다면, recv 대기 시간 초과로 대기열에서 빠져나감.
        if timer_flag == 1:
            #msg = '[' + str(interface) + '] in recv q loop, timer expired'
            #writeLogFile(msg)
            return

        if (recv_queue.empty() == False):
            with recv_queue_lock:
                packet = recv_queue.get()

            if (packet != '') == (packet != None):
                #패킷이 정상적으로 들어왔다면, tc에서 예상하는 패킷이 들어왔는지 검사.
                ret = compare_tc_vs_packet(tc, packet, tc_list_info)
                if (ret == 'same'):
                    #원하는 패킷이 들어왔다면, 패킷을 리턴
                    return packet

                #원하지 않는 패킷이 들어왔다면, 로그에 남기고 다시 대기 루프
                write_packet_to_report_file(interface, step, "recv|unexpected", packet, packet["IP"].len)

        #과잉 loop를 방지하기위한 딜레이
        time.sleep(0.01)


def packet_state_machine_thread(recv_queue, recv_queue_lock, tc_list_info, tc_list_lock):
    """
    packet_state_machine_thread 함수는 프로세스에서 호출하는 진입점이다
    tc 리스트에서 tc를 pop하여 해당하는 액션별로 처리한다
    :param recv_queue:
    :param recv_queue_lock:
    :param tc_list_info:
    :param tc_list_lock:
    """
    tc_list = tc_list_info.get_packet_list()
    interface = tc_list_info.get_interface_name()

    #recv시 대기 시간을 설정하는 부분
    #최초 설정값 30초 이후 타이머에 의한 스레드 종료를 실행
    receive_due_second = 30
    recv_expire_timer = PeriodicThread(recv_expire_timer_callback,
                                     receive_due_second,
                                     'recv_expire_timer', )
    recv_expire_timer.set_interface(interface)
    recv_expire_timer.set_tc_list(tc_list)
    recv_expire_timer.set_tc_list_loc(tc_list_lock)
    #recv_expire_timer.start()

    usleep = lambda x: time.sleep(x / 1000000.0)

    global timer_flag

    while True:
        #리스트가 모두 비워지면 스레드 종료
        if len(tc_list) == 0:
            write_fail_to_report_file(interface, "fin", "TC list is empty")
            return
        #recv 대기시간이 초과하면 스레드 종료
        if timer_flag == 1:
            write_fail_to_report_file(interface, "fail", "receive timer is expired")
            return

        #tclist에서 아이템 갖고옴.
        with tc_list_lock:
            tc = tc_list.pop()

        #for debug
        print interface + ' tc is ' + str(tc._inner_value2str_s())

        #해당 tc의 액션과 step을 갖고옴
        action = tc.get_packet_action()
        step = tc.get_tc_step()

        #Packet state handling
        if action == 'send':
            #send 액션인 경우 보내고 루프처음으로
            send_packet(interface, step, tc, tc_list_info)
        elif action == 'wait':
            #wait 액션인 경우 해당 시간을 기다리고 루프 처음으로
            write_packet_to_report_file(interface, step, "wait", packet, 0)
            print 'start wait' + str(tc.get_packet_delay()) + '\n'
            while 1:
                usleep(tc.get_packet_delay())
                break
            print 'end wait' + str(tc.get_packet_delay()) + '\n'
        else:
            #recv 액션인 경우 아래와 같이 처리 후 루프 처음으로
            #timeo값이 있는 경우 그 값으로 설정
            #아닌 경우, 기본 값(receive_due_second)으로 설정
            if (tc.get_timeo() != 0):
                recv_expire_timer.set_period_msec(long(tc.get_timeo()))
            else:
                recv_expire_timer.set_period_sec(receive_due_second)

            #recv 대기 타이머 실행
            recv_expire_timer.start()

            #recvQ loop wait
            packet = recv_queue_loop(interface, step, recv_queue, recv_queue_lock, tc, tc_list_info)

            #recv 대기 타이머 종료
            recv_expire_timer.cancel()
            if (packet == None):
                #대기 타이머가 강제 종료 될때, packet이 none으로 오는데, 이때 에러로그 기록후 종료
                write_fail_to_report_file(interface, "fail", "receive timer is expired")
                return

            #받은 패킷을 로그에 기록
            write_packet_to_report_file(interface, step, "recv", packet, packet["IP"].len)
