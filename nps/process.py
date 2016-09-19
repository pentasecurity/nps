# -*- coding: UTF-8 -*-

import threading
import Queue
from nps.file_log import *
from nps.packet_handler_recv import recv_queue_thread
from nps.packet_handler_send import packet_state_machine_thread


def process_main(tc_list_info, ):
    """
    nps의 client와 server 각각 동작시키는 함수

    :param tc_list_info:
    """

    #recv 큐에 삽입할때 사용할 락
    recv_queue_lock = threading.Lock()

    #tcList를 pop할때 사용할 락.
    tc_list_lock = threading.Lock()

    #recv 스레드에서 패킷을 받을 때 사용할 큐 객체 생성.
    recv_queue = Queue.Queue()

    #pop을 하기 위해 리스트 순서 반전
    tc_list_info.reverse_packet_list()

    recv_thread = threading.Thread(target=recv_queue_thread,
                                   args=(recv_queue, recv_queue_lock, tc_list_info))

    send_thread = threading.Thread(target=packet_state_machine_thread,
                                   args=(recv_queue, recv_queue_lock, tc_list_info, tc_list_lock))

    recv_thread.start()

    time.sleep(3)

    send_thread.start()

    send_thread.join()
    recv_thread.join()
    #recv 스레드의 생명주기는 send 끝나면 끝나도록 설정.
    #이유는 맨 마지막 TC가 단순 recv인 경우는 nps를 켜놓으나 안켜놓으나 별 의미가 없음.
