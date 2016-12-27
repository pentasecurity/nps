# -*- coding: UTF-8 -*-
from scapy.all import *
from nps.timer import PeriodicThread
from nps.file_log import *
from nps.packet_buff import TcpFlagInfo


class PacketSniff:
    def _get_basic_capture_filter(self):
        """
        tcp/ip filter를 통해 정해진 값들만 sniff 하도록 설정하는 함수
        :return: filter info
        """
        filter = 'tcp'
        return filter

    def _process_packet_hook(self, recv_queue, recv_queue_lock, recv_interface_mac):
        """
        :param recv_queue:
        :param recv_queue_lock:
        :param recv_interface_mac:
        :return:
        """
        def hook_handler(packet):
            # sniff 함수는 rx/tx 모두 받도록 되어있다.
            # mac address의 destination이 local interface의 mac address가 아닌 패킷들은
            # recv queue에 넣지 않게 폐기한다. send packet이나 broadcast 패킷이
            # sniff되었을 가능성이 높기 때문이다.
            if (packet['Ethernet'].dst != recv_interface_mac):
                return

            with recv_queue_lock:
                recv_queue.put(packet)

        return hook_handler

    def register(self, recv_queue, recv_queue_lock, network_entity):
        """
        nps에서 recv queue에 대해서 처리하는 thread이다
        :param recv_queue:
        :param recv_queue_lock:
        :param network_entity:
        """
        sniff_mac_addr = network_entity.get_interface_mac_addr()
        sniff(iface=network_entity.get_interface_name(),
              filter=self._get_basic_capture_filter(),
              store=0,
              prn=self._process_packet_hook(recv_queue, recv_queue_lock, sniff_mac_addr))


class PacketSimulator:
    def __init__(self, network_entity, recv_queue, recv_queue_lock):
        self.network_entity = network_entity
        self.recv_queue = recv_queue
        self.recv_queue_lock = recv_queue_lock
        self.recv_timer_expired = False

    def _send_packet(self, interface, step, packet_buff):
        """
        send_nps_packet 함수는 packet_buff에 저장된 값을 토대로 각각의 계층을 만들어내서 전송한다
        :param interface:
        :param step:
        :param packet_buff:
        """
        eth = packet_buff.get_ether_layer()
        ip4 = packet_buff.get_ipv4_layer()
        tcp = packet_buff.get_tcp_layer()

        # TODO: consider used to nat DUT

        raw = packet_buff.get_raw_data()
        packet = eth / ip4 / tcp / raw

        write_packet_to_report_file(interface, step, "send", packet, packet_buff.get_tcp_len())
        sendp(packet, iface=interface)

    def _compare_packet_buff_and_recv_packet(self, packet_buff, packet):
        """
        :param packet_buff:
        :param packet:
        :return:
        """
        if (packet_buff.get_src_ip_addr() != packet['IP'].src):
            msg = 'sip not matched packet_buff:' + str(packet_buff.get_src_ip_addr()) + ',pckt:' + packet['IP'].src
            return msg

        if (packet_buff.get_dest_ip_addr() != packet['IP'].dst):
            msg = 'dip not matched'
            return msg

        # TODO: tcp port checking
        # consider used to nat DUT

        tcpflag = TcpFlagInfo()
        if (packet_buff.get_tcp_flag() != tcpflag.flagnumber2char(packet['TCP'].flags)):
            if (packet_buff.get_tcp_flag() == 'F'):
                if ('FA' == tcpflag.flagnumber2char(packet['TCP'].flags)):
                    return 'same'
            elif (packet_buff.get_tcp_flag() == 'P'):
                if ('PA' == tcpflag.flagnumber2char(packet['TCP'].flags)):
                    return 'same'
            else:
                msg = 'flag not matched packet_buff:' + str(packet_buff.get_tcp_flag()) + ',pckt:' + str(packet['TCP'].flags)
                return msg

        # TODO: tcp data compare

        return 'same'

    def _recv_expire_timer_callback(self, *args, **kwargs):
        """
        recv 대기 시간이 만료되면 flag값을 1로 변경
        """
        self.recv_timer_expired = True

    def process_recv_queue(self, interface, step, packet_buff):
        """
        recv queue에 새로운 데이터가 있는지 loop로 체크하는 함수
        :param interface:
        :param step:
        :param packet_buff:
        :return:
        """
        packet = ''

        while True:
            if self.recv_timer_expired == True:
                return None

            with self.recv_queue_lock:
                if self.recv_queue.empty() == True:
                    time.sleep(0.01)
                    continue

            with self.recv_queue_lock:
                packet = self.recv_queue.get()

            # Check expected packet arrived.
            ret = self._compare_packet_buff_and_recv_packet(packet_buff, packet)
            if (ret == 'same'):
                #원하는 패킷이 들어왔다면, 패킷을 리턴
                return packet

            #원하지 않는 패킷이 들어왔다면, 로그에 남기고 다시 대기 루프
            write_packet_to_report_file(interface, step, "recv|unexpected", packet, packet["IP"].len)


    def start(self):
        interface = self.network_entity.get_interface_name()

        usleep = lambda x: time.sleep(x / 1000000.0)

        # create receive timer
        # default value second
        default_receive_timeout = 10
        recv_expire_timer = PeriodicThread(self._recv_expire_timer_callback,
                                           default_receive_timeout,
                                           'packet_receive_expire_timer',)

        while True:
            if self.network_entity.is_empty_packet_list() == True:
                write_fail_to_report_file(interface, "fin", "TC list is empty")
                break

            if self.recv_timer_expired == True:
                write_fail_to_report_file(interface, "fail", "receive timer is expired")
                break

            # get packet buff from pakcet list(queue)
            packet_buff = self.network_entity.pop_packet_list()

            print(interface + ' packet_buff is ' + str(packet_buff._inner_value2str_s()))

            action = packet_buff.get_packet_action()
            step = packet_buff.get_tc_step()

            # Packet state handling
            #
            if action == 'send':
                if packet_buff.get_packet_delay() > 0:
                    usleep(packet_buff.get_packet_delay())

                self._send_packet(interface, step, packet_buff)
            else:
                # recv action.
                #
                if (packet_buff.get_timeo() > 0):
                    recv_expire_timer.set_period_msec(long(packet_buff.get_timeo()))
                else:
                    recv_expire_timer.set_period_sec(default_receive_timeout)

                # first, receive expire timer start
                recv_expire_timer.start()

                # process receive queue
                expected_packet = self.process_recv_queue(interface, step, packet_buff)

                recv_expire_timer.cancel()

                if (self.recv_timer_expired == True):
                    write_fail_to_report_file(interface, "fail", "receive timer is expired")
                    break

                if expected_packet is not None:
                    write_packet_to_report_file(interface, step, "recv",
                                                expected_packet, expected_packet["IP"].len)
            # remove packet buff
            del(packet_buff)

        recv_expire_timer.join()
