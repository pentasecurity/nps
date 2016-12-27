# -*- coding: UTF-8 -*-
from scapy.all import srp, Ether, ARP, conf


class AccessibilityManager:
    def __init__(self):
        self._accessibilty_list = []

    def add(self, obj):
        self._accessibilty_list.append(obj)

    def get_list(self):
        return self._accessibilty_list

    def process(self):
        for accessibilty in self._accessibilty_list:
            accessibilty.process()


class AbstractAccessibilty:
    def __init__(self):
        self._verbose = False

    def process(self):
        pass


# TODO: create that consider port option(proxy configure)
#
# Server Simulation
#  - server does not know tcp port of DUT
#  - need ip/port learn function.


class AddressBinder(AbstractAccessibilty):
    def __init__(self, entity):
        self._src_mac = "00:00:00:00:00:01"
        self._src_ip = "1.1.1.1"
        self._src_port = 12345
        self._dest_mac = "00:00:00:00:00:02"
        self._dest_ip = "2.2.2.2"
        self._dest_port = 80

        # server or client entity
        self._network_entity = entity

    def set_src_addr(self, src_mac, src_ip, src_port):
        self._src_mac = src_mac
        self._src_ip = src_ip
        self._src_port = int(src_port)

    def get_src_mac(self):
        return self._src_mac

    def get_src_ip(self):
        return self._src_ip

    def get_src_port(self):
        return self._src_port

    def set_dest_addr(self, dest_mac, dest_ip, dest_port):
        self._dest_mac = dest_mac
        self._dest_ip = dest_ip
        self._dest_port = int(dest_port)

    def get_dest_mac(self):
        return self._dest_mac

    def get_dest_ip(self):
        return self._dest_ip

    def get_dest_port(self):
        return self._dest_port

    def process(self):
        for packet_buff in self._network_entity.get_packet_list():
            if packet_buff.get_packet_action() == "send":
                packet_buff.set_ether_datas(self._dest_mac, self._src_mac)
                packet_buff.set_ip_addr(self._dest_ip, self._src_ip)
                packet_buff.set_tcp_port_num(self._dest_port, self._src_port)
            elif packet_buff.get_packet_action() == "recv":
                # recv action
                # change values of source and destination
                packet_buff.set_ether_datas(self._src_mac, self._dest_mac)
                packet_buff.set_ip_addr(self._src_ip, self._dest_ip)
                packet_buff.set_tcp_port_num(self._src_port, self._dest_port)


class TcListAutoSeqAck(AbstractAccessibilty):
    def __init__(self, client_entity, server_entity=None):
        self._client_entity = client_entity
        self._server_entity = server_entity
        self._client_start_seq = 0L
        self._server_start_seq = 0L

    def set_tcp_sequence(self, client_start_seq, server_start_seq):
        self._client_start_seq = client_start_seq
        self._server_start_seq = server_start_seq

    def get_client_tcp_sequence(self):
        return self._client_start_seq

    def get_server_tcp_sequence(self):
        return self._server_start_seq

    def process(self):
        self.calc_auto_tcp_seq_ack(self._client_entity, self._server_entity,
                                   self._client_start_seq, self._server_start_seq)

    def _calc_tcp_seq(self, tc_list_info, my_seq, other_seq):
        tc_list = tc_list_info.get_packet_list()

        # send는 본인의 seq를 다루고 recv는 받는 쪽의 seq를 다룬다.
        send_seq = my_seq
        recv_seq = other_seq

        send_file_list = []
        recv_file_list = []
        send_file_size = []
        recv_file_size = []

        total_client_data_size = 0
        total_server_data_size = 0

        #실제 값 채우기 이전에
        #data flow패킷의 seq 기준점으로 쓰일 파일 개수를 구함.
        for tc in tc_list:
            action = tc.get_packet_action()

            #보내는 경우, 내가 보내는 파일리스트에 저장하여,
            #각종 예외처리 이후, 리스트에 등록.
            #등록될 때, 동시에 등록되므로 index는 같다는 가정을 함.
            if (tc.get_packet_action() == "send"):
                file_name = tc.get_file_name()
                if (file_name != None) and (file_name != "") and ((file_name in send_file_list) != True):
                    send_file_list.append(file_name)
                    send_file_size.append(tc.get_file_size())
                    total_client_data_size = total_client_data_size + tc.get_file_size()

            #받는 경우, 상대가 보내는 파일리스트에 추가함.
            elif (tc.get_packet_action() == "recv"):
                file_name = tc.get_file_name()
                if (file_name != None) and (file_name != "") and ((file_name in recv_file_list) != True):
                    recv_file_list.append(file_name)
                    recv_file_size.append(tc.get_file_size())
                    total_server_data_size = total_server_data_size + tc.get_file_size()

        #fin의 시작 seq = 시작 seq + 1(syn) + 보낸 데이터 총합
        send_fin_seq = my_seq + 1 + total_client_data_size
        recv_fin_seq = other_seq + 1 + total_server_data_size

        send_flag_syn = 0  #for send/syn
        send_flag_fin = 0  #for send/fin
        recv_flag_syn = 0  #for recv/syn
        recv_flag_fin = 0  #for recv/fin

        #각각의 packet에 sequence 값을 채워 넣음
        for tc in tc_list:
            #action과 step에 따라 분류
            step = tc.get_tc_step()
            act = tc.get_packet_action()
            #기본적으로 send는 내 seq를 토대로 계산
            #recv는 상대편의 seq을 토대로 계산.

            #open 단계에서는
            #1. syn, syn+ack 패킷에 대해서는 시작 시퀀스 값을 채워넣음.
            #2. 그외의 경우, 만약 이전에 syn을 받았다면 시작 시퀀스 + 1값을,
            #	아닌경우라면 시작 시퀀스 값을 채워 넣음.
            if (step == "connection_open"):
                if (act == "send"):
                    if (tc.get_tcp_flag() == "S") or (tc.get_tcp_flag() == "SA"):
                        tc.set_tcp_seq(my_seq)
                        send_flag_syn = 1
                    else:
                        if (send_flag_syn == 1):
                            tc.set_tcp_seq(my_seq + 1)
                        else:
                            tc.set_tcp_seq(my_seq)

                elif (act == "recv"):
                    if (tc.get_tcp_flag() == "S") or (tc.get_tcp_flag() == "SA"):
                        tc.set_tcp_seq(other_seq)
                        recv_flag_syn = 1
                    else:
                        if (recv_flag_syn == 1):
                            tc.set_tcp_seq(other_seq + 1)
                        else:
                            tc.set_tcp_seq(other_seq)

            #close 단계에서는
            #1. fin, fin+ack 패킷에 대해서는 시작 시퀀스 값을 채워넣음.
            #2. 그외의 경우, 만약 이전에 fin을 받았다면 시작 시퀀스 + 1값을,
            #	아닌경우라면 시작 시퀀스 값을 채워 넣음.
            elif (step == "connection_close"):
                if (act == "send"):
                    if (tc.get_tcp_flag() == "F") or (tc.get_tcp_flag() == "FA"):
                        tc.set_tcp_seq(send_fin_seq)
                        send_flag_fin = 1
                    else:
                        if (send_flag_fin == 1):
                            tc.set_tcp_seq(send_fin_seq + 1)
                        else:
                            tc.set_tcp_seq(send_fin_seq)

                elif (act == "recv"):
                    if (tc.get_tcp_flag() == "F") or (tc.get_tcp_flag() == "FA"):
                        tc.set_tcp_seq(recv_fin_seq)
                        recv_flag_fin = 1
                    else:
                        if (recv_flag_fin == 1):
                            tc.set_tcp_seq(recv_fin_seq + 1)
                        else:
                            tc.set_tcp_seq(recv_fin_seq)

            #data flow 단계에서는
            #최초 seq + 1이 최초 data flow 시작값이라고 생각.
            #이전에 들어온 파일크기를 읽어서, 해당하는 파일의 seq 시작값을 결정하고
            #해당파일에서 해당인덱스와 이전 시작 seq 값을 더해서 seq에 설정함.
            #해당 tclist에서 data를 안보내면 send할 때, 최초 seq + 1을 보내도록 설정
            elif (step == "data_flow"):
                if (act == "send"):
                    if len(send_file_list) > 0:
                        idx = send_file_list.index(tc.get_file_name())
                        this_files_start_seq = my_seq + 1  #idx == 0
                        if (idx > 0):
                            i = idx - 1
                            #이전 파일 크기를 seq에 더함
                            while 1:
                                this_files_start_seq = this_files_start_seq + send_file_size[i]
                                if (i == 0):
                                    break
                                i = i - 1

                        #최종적응로 구해진 해당 파일의 최초 index에 file의 index를 더함.
                        tc.set_tcp_seq(this_files_start_seq + tc.get_tcp_index())
                    else:
                        #보낼 파일이 없는경우, 최초 seq + 1을 날림.
                        tc.set_tcp_seq(my_seq + 1)

                elif (act == "recv"):
                    #get file index
                    if len(recv_file_list) > 0:
                        print recv_file_list
                        print tc.get_file_name()
                        print tc._inner_value2str_s()
                        idx = recv_file_list.index(tc.get_file_name())
                        this_files_start_seq = other_seq + 1  #idx == 0
                        if (idx > 0):
                            i = idx - 1
                            while 1:
                                this_files_start_seq = this_files_start_seq + recv_file_size[i]
                                if (i == 0):
                                    break
                                i = i - 1

                        tc.set_tcp_seq(this_files_start_seq + tc.get_tcp_index())
                    else:
                        tc.set_tcp_seq(other_seq + 1)

    def _calc_tcp_ack_with_queue(self, total_recved, prev_tc_seq, prev_tc_flag_val, prev_tc_len, ack_queue):
        """
        calc_ack_with_queue

        FIXME: 오버플로우된 seq나 ack 대해서 계산 하는 방안이 필요함. (현재는 overflow 시 계산 에러)
        """

        #length는 이전 받은 flag의 값에 의한 값(0~1)과 tc의 tcp length를 더한 값.
        length = prev_tc_flag_val + prev_tc_len

        #1. 총 받은 값과 이전 tc seq가 같은 경우,
        #바로 연이어 데이터가 들어온 케이스
        #						total
        # xxxxxxxxxxxxxxxxxxxxxx|
        # --------------------------------------------------->seq Number
        #						|xxxxxx|
        #		   				 legth
        if (total_recved == prev_tc_seq):
            total_recved = total_recved + length

        #2. 이전 들어온 tc의 seq가 총 받은 값보다 큰 경우,
        #총 받은 값과 직전 받은 값 사이에 공백이 존재.
        #recv큐에 삽입
        #		total
        # xxxxxxxxxxxxxxxxxx|
        # --------------------------------------------------->seq Number
        #					|<-공백 존재->|xxxxxx|
        #		  			  		 		legth
        elif (total_recved < prev_tc_seq):
            ack_queue.append([prev_tc_seq, length])

        #3. 이전 들어온 tc의 seq가 총 받은 값보다 작은 경우
        #		total
        # xxxxxxxxxxxxxxxxxx|
        # --------------------------------------------------->seq Number
        #				|xxxxxx|
        #		  		<-->  legth
        #				겹치게 들어온 경우
        else:  #prevTcSeq < totalRecved
            #tc seq + length 값이 total보다 큰 경우,
            #total받은 값을 갱신하고, 그외의 경우는 이미 받았으므로 무시한다.
            if (prev_tc_seq + length > total_recved):
                total_recved = prev_tc_seq + length

        if len(ack_queue) == 0:
            return total_recved

        sorted(ack_queue, key=lambda x: x[0])

        while True:
            #저장된 인덱스와 위에서 계산된 총 합과 비교해서
            #total이 크거나 같으면 이어받거나 전에 받았던거랑 섞이거나 하는 케이스므로
            #total을 갱신하고 큐에서 제거, 그리고 다른 큐를 또 찾아봄.
            stored_index, stored_len = ack_queue[0]
            if (total_recved >= stored_index):
                total_recved = stored_index + stored_len
                del ack_queue[0]
                if len(ack_queue) == 0:
                    break
            else:
                break

        print 'total recved : ' + str(total_recved)
        return total_recved

    #syn/fin 중복을 계산하기 위한 변수
    _send_syn_flag = 0
    _send_fin_flag = 0
    _recv_syn_flag = 0
    _recv_fin_flag = 0

    def _clear_tcp_flags(self):
        #새롭게 ack를 계산할 때, 변수 초기화 할 때 쓰는 func.
        self._send_syn_flag = 0
        self._send_fin_flag = 0
        self._recv_syn_flag = 0
        self._recv_fin_flag = 0

    def _calc_tcp_flag_value(self, direction, flag):
        #Flag에 의한 값을 계산할 때, 사용할 코드
        if direction == "send":
            if (flag == 'S' or flag == 'SA') and self._send_syn_flag == 0:
                self._send_syn_flag = 1
                return 1

            if (flag == 'F' or flag == 'FA') and self._send_fin_flag == 0:
                self._send_fin_flag = 1
                return 1

        elif direction == "recv":
            if (flag == 'S' or flag == 'SA') and self._recv_syn_flag == 0:
                self._recv_syn_flag = 1
                return 1

            if (flag == 'F' or flag == 'FA') and self._recv_fin_flag == 0:
                self._recv_fin_flag = 1
                return 1

        return 0

    def _calc_tcp_ack(self, tc_list_info, my_seq, other_seq):
        #주의, 이전에 seq가 미리 다 계산 되어있다는 전제하에 작성 되었습니다.
        self._clear_tcp_flags()
        tc_list = tc_list_info.get_packet_list()

        send_tc_ack = other_seq
        recv_tc_ack = my_seq

        #연속적으로 오는 seq에 대한 ack 관리와 별개로,
        #순서가 건너뛰어서 오는 seq를 관리하기위해 사용되는 큐
        send_ack_queue = []
        recv_ack_queue = []

        #send 할 때는 보내는 sendTcAck를 채우고, 받을때 채울 ack를 계산하고,
        #recv 할 때는 받는 recvTcAck를 채우고, 보낼 때 채울 ack를 계산합니다.
        for tc in tc_list:
            act = tc.get_packet_action()
            if (act == "send"):
                send_tc_ack = tc.set_tcp_ack(send_tc_ack)
                recv_tc_ack = self._calc_tcp_ack_with_queue(
                    recv_tc_ack, tc.get_tcp_seq(), self._calc_tcp_flag_value("send", tc.get_tcp_flag()),
                    tc.get_tcp_len(), recv_ack_queue)

            elif (act == "recv"):
                recv_tc_ack = tc.set_tcp_ack(recv_tc_ack)
                send_tc_ack = self._calc_tcp_ack_with_queue(
                    send_tc_ack, tc.get_tcp_seq(), self._calc_tcp_flag_value("recv", tc.get_tcp_flag()),
                    tc.get_tcp_len(), send_ack_queue)

    def calc_auto_tcp_seq_ack(self, client_tc_list_handler, server_tc_list_handler, client_start_seq, server_start_seq):
        #각각의 side 별로 "seq number"를 계산합니다.
        self._calc_tcp_seq(client_tc_list_handler, long(client_start_seq), long(server_start_seq))
        self._calc_tcp_seq(server_tc_list_handler, long(server_start_seq), long(client_start_seq))

        #각각의 side 별로 "ack number"를 계산합니다.
        #ack 계산시에 syn과 fin에대해 계산할때 쓰이는 멤버 flag 를 초기화하기위해
        #flag에 따른 가중치를 계산하는 함수가 분리되어있어서 멤버 변수로 쓰이는 값을 따로 관리하는데,
        #이 값을 초기화하는게 clearFlags() 함수 입니다.
        self._clear_tcp_flags()
        self._calc_tcp_ack(client_tc_list_handler, long(client_start_seq), long(server_start_seq))
        self._clear_tcp_flags()
        self._calc_tcp_ack(server_tc_list_handler, long(server_start_seq), long(client_start_seq))

        #debug code
        print client_tc_list_handler.get_name()
        for packetInfo in client_tc_list_handler.get_packet_list():
            print 'client packet generated : ' + packetInfo._inner_value2str_s()

        print server_tc_list_handler.get_name()
        for packetInfo in server_tc_list_handler.get_packet_list():
            print 'server packet generated : ' + packetInfo._inner_value2str_s()


class MacAddressHelper:
    def __init__(self):
        # TODO1: expire timer for aging mac addr
        # TODO2: mac addr for ipv6(icmp)
        self.mac_addr_cache = dict()

    def get_interface_mac_addr(self, interface):
        try:
            with open('/sys/class/net/{0}/address'.format(interface), 'r') as f:
                return f.read().replace('\n','')
        except:
            return None

#    def _get_mac_addr_system_cache(self, ip):
#        # Sample output
#        # IP address       HW type     Flags       HW address            Mask     Device
#        # 192.168.40.1     0x1         0x2         00:10:f3:30:39:89     *        eth0
#        # 192.168.40.114   0x1         0x2         8e:9d:9d:35:35:e2     *        eth0
#        f = open('/proc/net/arp', 'r')
#
#        mac_addr = None
#        while True:
#            line = f.readline()
#            if not line:
#                break
#
#            split_line = line.split()
#            if split_line[0] == ip:
#                mac_addr = split_line[3]
#                break
#
#        f.close()
#        return mac_addr

    def clear_mac_addr_cache(self):
        self.mac_addr_cache.clear()

    def get_mac_addr_cache(self, ip):
        if ip in self.mac_addr_cache:
            return self.mac_addr_cache[ip]
        return None

    def add_mac_addr_cache(self, ip, mac_addr):
        self.mac_addr_cache[ip] = mac_addr

    def _request_arp(self, ip):
        # README: requested arp not write system arp cache
        #
        # disable scapy module verbose
        verb_conf = conf.verb
        conf.verb = 0

        # Run request arp up to three times.
        mac_addr = ""
        for i in xrange(3):
            ans, uans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1)
            for snd, rcv in ans:
                result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
                mac_addr = result[1]

            if mac_addr != None and mac_addr != "":
                break

        # rollback scapy module verbose
        conf.verb = verb_conf

        if mac_addr == "":
            return None

        return mac_addr

    def request_arp(self, ip):
        """request mac address to system arp table """
        addr = self.get_mac_addr_cache(ip)
        if addr is None:
            addr = self._request_arp(ip)
            self.add_mac_addr_cache(ip, addr)

        return addr
