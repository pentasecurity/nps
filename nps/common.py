# -*- coding: UTF-8 -*-

SERVER_TO_CLIENT = "server"
CLIENT_TO_SERVER = "client"


class TcListInfo(object):
    """서버와 클라이언트 각각에서 쓰이는 리스트 버퍼관련 핸들러"""

    _packet_list = []

    #nat 관련 내용
    #dut에서 생성 될 랜덤 포트 넘버 저장소
    _nat_port = 0
    _nat_magic_number = 99999
    _use_nat_port = "False"

    #sniff 할 때 쓰이는 변수
    _interface_name = ""  #ex)tp0, eth0, ...
    _interface_mac_addr = "00:00:00:00:00:00"
    _interface_ip_addr = ""
    _interface_tcp_port = ""

    #seq, ack 자동 채우기
    _is_auto_fill_tcp_seq_ack = "False"
    _start_tcp_seq = 0

    def __init__(self, name):
        self._packet_list = []
        self.name = name

    def get_name(self):
        return self.name

    #port
    def set_interface_tcp_port(self, port):
        self._interface_tcp_port = port

    def get_interface_tcp_port(self):
        return self._interface_tcp_port

    #ip
    def set_interface_ip_addr(self, ip):
        self._interface_ip_addr = ip

    def get_interface_ip_addr(self):
        return self._interface_ip_addr

    #tc(packet) list
    def append_packet_list(self, packet_info):
        self._packet_list.append(packet_info)

    def reverse_packet_list(self):
        self._packet_list.reverse()

    def get_packet_list(self):
        return self._packet_list

    def is_empty_packet_list(self):
        return (len(self._packet_list) == 0)

    #interface
    def set_interface(self, iface_name, iface_mac):
        self._interface_name = iface_name
        self._interface_mac_addr = iface_mac

    def get_interface_name(self):
        return self._interface_name

    def get_interface_mac_addr(self):
        return self._interface_mac_addr

    #nat port
    def set_use_nat_port(self, use_or_not):
        self._use_nat_port = use_or_not

    def get_use_nat_port(self):
        return self._use_nat_port

    def set_dut_nat_port(self, port):
        self._nat_port = port

    def get_dut_nat_port(self):
        return self._nat_port

    def get_nat_magic_number(self):
        return self._nat_magic_number

    #Auto fill seq, ack
    def set_auto_fill_seq_ack(self, is_auto_fill):
        self._is_auto_fill_tcp_seq_ack = is_auto_fill

    def get_auto_fill_seq_ack(self):
        return self._is_auto_fill_tcp_seq_ack

    def set_start_tcp_seq(self, seq):
        self._start_tcp_seq = seq

    def get_start_tcp_seq(self):
        return self._start_tcp_seq


class TcListAutoSeqAck(object):

    def calc_tcp_seq(self, tc_list_info, my_seq, other_seq):
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

    def calc_tcp_ack_with_queue(self, total_recved, prev_tc_seq, prev_tc_flag_val, prev_tc_len, ack_queue):
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

    def clear_tcp_flags(self):
        #새롭게 ack를 계산할 때, 변수 초기화 할 때 쓰는 func.
        self._send_syn_flag = 0
        self._send_fin_flag = 0
        self._recv_syn_flag = 0
        self._recv_fin_flag = 0

    def calc_tcp_flag_value(self, direction, flag):
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

    def calc_tcp_ack(self, tc_list_info, my_seq, other_seq):
        #주의, 이전에 seq가 미리 다 계산 되어있다는 전제하에 작성 되었습니다.
        self.clear_tcp_flags()
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
                recv_tc_ack = self.calc_tcp_ack_with_queue(
                    recv_tc_ack, tc.get_tcp_seq(), self.calc_tcp_flag_value("send", tc.get_tcp_flag()),
                    tc.get_tcp_len(), recv_ack_queue)

            elif (act == "recv"):
                recv_tc_ack = tc.set_tcp_ack(recv_tc_ack)
                send_tc_ack = self.calc_tcp_ack_with_queue(
                    send_tc_ack, tc.get_tcp_seq(), self.calc_tcp_flag_value("recv", tc.get_tcp_flag()),
                    tc.get_tcp_len(), send_ack_queue)

    def calc_auto_tcp_seq_ack(self, client_tc_list_handler, server_tc_list_handler, client_start_seq, server_start_seq):
        #각각의 side 별로 "seq number"를 계산합니다.
        self.calc_tcp_seq(client_tc_list_handler, long(client_start_seq), long(server_start_seq))
        self.calc_tcp_seq(server_tc_list_handler, long(server_start_seq), long(client_start_seq))

        #각각의 side 별로 "ack number"를 계산합니다.
        #ack 계산시에 syn과 fin에대해 계산할때 쓰이는 멤버 flag 를 초기화하기위해
        #flag에 따른 가중치를 계산하는 함수가 분리되어있어서 멤버 변수로 쓰이는 값을 따로 관리하는데,
        #이 값을 초기화하는게 clearFlags() 함수 입니다.
        self.clear_tcp_flags()
        self.calc_tcp_ack(client_tc_list_handler, long(client_start_seq), long(server_start_seq))
        self.clear_tcp_flags()
        self.calc_tcp_ack(server_tc_list_handler, long(server_start_seq), long(client_start_seq))

        #debug code
        print client_tc_list_handler.get_name()
        for packetInfo in client_tc_list_handler.get_packet_list():
            print 'client packet generated : ' + packetInfo._inner_value2str_s()

        print server_tc_list_handler.get_name()
        for packetInfo in server_tc_list_handler.get_packet_list():
            print 'server packet generated : ' + packetInfo._inner_value2str_s()
