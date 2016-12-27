# -*- coding: UTF-8 -*-
from scapy.all import *


# define for packet data
TCP_SEQUENCE_MAX = 4294967295
IP_PROTO = 0x800
TCP_PROTO = 6


class PacketBuff:
    def __init__(self):
        ## Packet User define
        self._action = ""
        self._step = ""
        self._delay = 0 # micro second
        self._timeo = 0 # micro second

        ## L2 Layer
        self._eth_dst = "00:00:00:00:00:00"
        self._eth_src = "00:00:00:00:00:00"
        self._eth_type = IP_PROTO

        ## L3 Layer
        # ipv4
        self._ip_ver = 4
        self._ip_ihl = None
        self._ip_tos = 0
        self._ip_len = None
        self._ip_id = 1
        self._ip_flags = 0
        self._ip_frag = 0

        self._ip_ttl = 64
        self._ip_proto = TCP_PROTO
        self._ip_chksum = None
        self._ip_src = "1.1.1.1"
        self._ip_dst = "1.1.1.2"
        self._ip_options = []

        ## L4 Layer
        # tcp header
        self._tcp_sport = 9014
        self._tcp_dport = 80
        self._tcp_seq = 0
        self._tcp_ack = 0
        self._tcp_dataofs = None
        self._tcp_reserved = 0
        self._tcp_flags = ""
        self._tcp_window = 65535
        self._tcp_chksum = None
        self._tcp_urgptr = 0

        # tcp header options
        #  - example
        #[("MSS", 1460), ("SAck",(20,30)), ("SAckOK", ""), ("SAck",(40,50)), ("SAck", (70,80)), ("SAckOk","ok")]
        self._tcp_options = [ ]
        self._tcp_mss = 1460
        self._tcp_sack_perm = False

        ## Payload
        self._tcp_index = 0
        self._tcp_length = 0

        self._raw_data = ""
        self._file_name = ""
        self._file_size = ""

    def set_packet_from_scapy_raw(self, scapy_rawdata):
        splitLayer = scapy_rawdata.split("/")

        if len(splitLayer) != 3:
            print("Error: scapy raw data is worng format.")
            return

        self.__init_ether_layer(splitLayer[0])
        self.__init_ip_layer(splitLayer[1])
        self.__init_tcp_layer(splitLayer[2])

    def __parse_str_value(self, str):
        ret = ""

        try:
            ret = str.split('=')[1].split("'")[1]
        except:
            print("Error: layer string value(%s) parse fail." % str)

        return ret

    def __parse_int_value(self, str):
        ret = ""

        try:
            ret = str.split('=')[1].split("'")[0]
        except:
            print "Error: layer int value(%s) parse fail." % str

        return ret

    def __parse_list_value(self, str):
        ret = ""

        try:
            ret = str.split('=')[1]
        except:
            print "Error: layer list value(%s) parse fail." % str

        return ret


    def __init_ether_layer(self, ether_str_raw_data):
        raw_data = ether_str_raw_data.split(',')

        if len(raw_data) != 3:
            print "Error: ether layer raw string."

        self._eth_src = self.__parse_str_value(raw_data[0])
        self._eth_dst = self.__parse_str_value(raw_data[1])
        self._eth_type = self.__parse_int_value(raw_data[2]).split(')')[0]

    def __init_ip_layer(self, ip_str_raw_data):
        raw_data = ip_str_raw_data.split(',')

        if len(raw_data) != 13:
            print "Error: ip layer raw string."

        self._ip_frag = self.__parse_int_value(raw_data[0])
        self._ip_src = self.__parse_str_value(raw_data[1])
        self._ip_proto = self.__parse_int_value(raw_data[2])
        self._ip_tos = self.__parse_int_value(raw_data[3])
        self._ip_dst = self.__parse_str_value(raw_data[4])
        self._ip_chksum = self.__parse_int_value(raw_data[5])
        self._ip_len = self.__parse_int_value(raw_data[6])
        self._ip_options = self.__parse_list_value(raw_data[7])
        self._ip_ver = self.__parse_int_value(raw_data[8])
        self._ip_flags = self.__parse_int_value(raw_data[9])
        self._ip_ihl = self.__parse_int_value(raw_data[10])
        self._ip_ttl = self.__parse_int_value(raw_data[11])
        self._ip_id = self.__parse_int_value(raw_data[12])

    def __init_tcp_layer(self, tcp_str_raw_data):
        tcp_options = tcp_str_raw_data[tcp_str_raw_data.find("options"):len(tcp_str_raw_data) - 1]
        raw_data = tcp_str_raw_data.replace(tcp_options, "").split(',')

        if len(raw_data) != 11:
            print "Error: tcp layer raw string."

        self._tcp_reserved = self.__parse_int_value(raw_data[0])
        self._tcp_seq = self.__parse_int_value(raw_data[1])
        self._tcp_ack = self.__parse_int_value(raw_data[2])
        self._tcp_dataofs = self.__parse_int_value(raw_data[3])
        self._tcp_urgptr = self.__parse_int_value(raw_data[4])
        self._tcp_window = self.__parse_int_value(raw_data[5])
        self._tcp_flags = self.__parse_int_value(raw_data[6])
        self._tcp_chksum = self.__parse_int_value(raw_data[7])
        self._tcp_dport = self.__parse_int_value(raw_data[8])
        self._tcp_sport = self.__parse_int_value(raw_data[9])

        #FIXME - tcpOptions scapy 2.1.0 does not support options
        self._tcp_options = self.__parse_list_value(raw_data[10])

#    def is_big_packet(self):
#        return True if len(self._raw_data) != 0 else False


    ## set user defined data
    def set_packet_action(self, in_action):
        self._action = in_action

    def set_tc_step(self, in_step):
        self._step = in_step

    def set_timeo(self, in_timeo):
        self._timeo = long(in_timeo)

    def set_delay(self, delay):
        self._delay = long(delay)

    ## set ehternet of packet
    def set_ether_data(self, in_dst, in_src, in_type):
        if in_dst is not None:
            self._eth_dst = in_dst
        if in_src is not None:
            self._eth_src = in_src

        self._eth_type = in_type

    def set_ether_datas(self, in_dst, in_src):
        if in_dst is not None:
            self._eth_dst = in_dst
        if in_src is not None:
            self._eth_src = in_src

    ## set internet protocol of packet
    def set_ip_addr(self, dip, sip):
        if dip is not None:
            self._ip_dst = dip
        if sip is not None:
            self._ip_src = sip

    ## set transmission control protocol of packet
    def set_tcp_port_num(self, dport, sport):
        if dport is not None:
            self._tcp_dport = int(dport)
        if sport is not None:
            self._tcp_sport = int(sport)

    def set_window_size(self, windsz):
        self._tcp_window = long(windsz)

    def set_tcp_flags(self, in_flag):
        if self._tcp_flags == "" or self._tcp_flags == "N/A":
            tcpflag = TcpFlagInfo()
            self._tcp_flags = tcpflag.convert_tcp_flag(in_flag)

    def set_tcp_seq(self, in_seq):
        num = long(in_seq)
        if (num > TCP_SEQUENCE_MAX):
            num = num - TCP_SEQUENCE_MAX
        self._tcp_seq = num
        return num

    def set_tcp_ack(self, in_ack):
        num = long(in_ack)
        if (num > TCP_SEQUENCE_MAX):
            num = num - TCP_SEQUENCE_MAX
        self._tcp_ack = num
        return num

    def set_tcp_sack_block(self, in_sle, in_sre):
        sle = long(in_sle)
        sre = long(in_sre)
        self._tcp_options.append(("SAck", (sle, sre)))

    def set_tcp_sack_permitted(self):
        self._tcp_options.append(("SAckOK", ""))
        self._tcp_sack_perm = True

    def set_tcp_mss(self, in_mss):
        mss = int(in_mss)
        self._tcp_options.append(("MSS", mss))
        self._tcp_mss = mss

    def set_tcp_options(self, **tcp_options):
        options = []

        for key in tcp_options.keys():
            options.append((key.upper(), tcp_options[key]))

        self._tcp_options = options

    def replace_tcp_options(self, in_options):
        self._tcp_options = copy.deepcopy(in_options)

    def set_raw_data(self, raw_data):
        self._raw_data = raw_data

    def set_file_size(self, path, filename):
        self._file_name = filename
        stat_info = os.stat(path + filename)
        self._file_size = stat_info.st_size

    def set_tcp_index(self, index):
        self._tcp_index = long(index)

    def set_tcp_length(self, length):
        self._tcp_length = long(length)

    def check_payload(self, payload):
        # REFACT
        payload = payload[10:len(payload) - 2]
        self._raw_data = self._raw_data.replace(payload, "")

    ## get method ##
    def get_src_eth(self):
        return self._eth_src

    def get_dest_eth(self):
        return self._eth_dst

    def get_tcp_len(self):
        return self._tcp_length

    def get_src_ip_addr(self):
        return self._ip_src

    def get_dest_ip_addr(self):
        return self._ip_dst

    def get_src_port(self):
        return self._tcp_sport

    def get_dest_port(self):
        return self._tcp_dport

    def get_tcp_seq(self):
        return self._tcp_seq

    def get_tcp_ack(self):
        return self._tcp_ack

    def get_tcp_options(self):
        return self._tcp_options

    def get_tcp_sack_permitted(self):
        return self._tcp_sack_perm

    def get_tcp_mss(self):
        return self._tcp_mss

    def get_packet_action(self):
        return self._action

    def get_packet_delay(self):
        return self._delay

    def get_timeo(self):
        return self._timeo

    def get_tc_step(self):
        return self._step

    def get_ether_layer(self):
        return Ether(dst=self._eth_dst, src=self._eth_src, type=self._eth_type)

    def get_ipv4_layer(self):
        return IP(version=self._ip_ver,
                  ihl=self._ip_ihl,
                  tos=self._ip_tos,
                  len=self._ip_len,
                  id=self._ip_id,
                  flags=self._ip_flags,
                  frag=self._ip_frag,
                  ttl=self._ip_ttl,
                  proto=self._ip_proto,
                  chksum=self._ip_chksum,
                  src=self._ip_src,
                  dst=self._ip_dst,
                  options=self._ip_options)

    def get_tcp_layer(self):
        return TCP(sport=self._tcp_sport,
                   dport=self._tcp_dport,
                   seq=self._tcp_seq,
                   ack=self._tcp_ack,
                   dataofs=self._tcp_dataofs,
                   reserved=self._tcp_reserved,
                   flags=self._tcp_flags,
                   window=self._tcp_window,
                   chksum=self._tcp_chksum,
                   urgptr=self._tcp_urgptr,
                   options=self._tcp_options)

    def get_raw_data(self):
        if self._raw_data == "":
            return ""

        data = ""
        if self._tcp_length != 0:
            data = self._raw_data[self._tcp_index:self._tcp_index + self._tcp_length]
        else:
            data = self._raw_data

        return Raw(load=data)

    def get_tcp_flag(self):
        return self._tcp_flags

    def get_file_name(self):
        return self._file_name

    def get_file_size(self):
        return self._file_size

    def get_tcp_index(self):
        return self._tcp_index

    ## method for debug ##
    def _print_inner_value(self):
        print("###### start ######")
        print("action : " + self._action)
        print("step : " + self._step)
        print("eth_src : " + self._eth_src)
        print("eth_dst : " + self._eth_dst)
        print("ip_src : " + self._ip_src)
        print("ip_dst : " + self._ip_dst)
        print("tcp_sport : " + str(self._tcp_sport))
        print("tcp_dport : " + str(self._tcp_dport))
        print("tcp_seq : " + str(self._tcp_seq))
        print("tcp_ack : " + str(self._tcp_ack))
        print("tcp_flags : " + str(self._tcp_flags))
        print("tcp_mss : " + str(self._tcp_mss))
        print("tcp options :")
        for option in self._tcp_options:
            print(option)
        print("tcp_sackPerm :" + str(self._tcp_sack_perm))
        print("raw_data : ")
        print(self._raw_data)
        print("###### end ######")

    def _inner_value2str_l(self):
        msg = ''
        msg += "###### start ######" + '\n'
        msg += "action : " + self._action + '\n'
        if self._step == None:
            msg += "step : None" + '\n'
        else:
            msg += "step : " + self._step + '\n'
        msg += "ip_src : " + self._ip_src + '\n'
        msg += "ip_dst : " + self._ip_dst + '\n'
        msg += "tcp_sport : " + str(self._tcp_sport) + '\n'
        msg += "tcp_dport : " + str(self._tcp_dport) + '\n'
        msg += "tcp_seq : " + str(self._tcp_seq) + '\n'
        msg += "tcp_ack : " + str(self._tcp_ack) + '\n'
        msg += "tcp_flags : " + str(self._tcp_flags) + '\n'
        msg += "tcp_mss : " + self._tcp_mss + '\n'
        msg += "tcp options" + '\n'
        for option in self._tcp_options:
            msg += str(option) + '\n'
        msg += "tcp_sackPerm" + self._tcp_sack_perm + '\n'
        msg += "raw_data : "
        msg += self._raw_data + '\n'
        msg += "###### end ######" + '\n'
        return msg

    def _inner_value2str_s(self):
        msg = ''
        msg = "%s/%s/[%s]%s(%s) > %s(%s), seq=%s, ack=%s, %s>%s" % (
            self._action, self._step, self._tcp_flags, self._ip_src,
            str(self._tcp_sport), self._ip_dst, str(self._tcp_dport),
            str(self._tcp_seq), str(self._tcp_ack), str(self._eth_src),
            str(self._eth_dst))
        return msg


class TcpFlagInfo:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def make_flag_str(self, f):
        ret = "."
        if (f == None):
            return 'None'

        if (f & self.FIN):
            ret = ret + '+FIN'
        if (f & self.SYN):
            ret = ret + '+SYN'
        if (f & self.RST):
            ret = ret + '+RST'
        if (f & self.PSH):
            ret = ret + '+PSH'
        if (f & self.ACK):
            ret = ret + '+ACK'
        if (f & self.URG):
            ret = ret + '+URG'
        if (f & self.ECE):
            ret = ret + '+ECE'
        if (f & self.CWR):
            ret = ret + '+CWR'
        return ret

    def flagnumber2char(self, f):
        ret = ''
        if (f == None):
            return 'None'
        chkf = f & ~self.FIN
        if (f & self.FIN):
            ret = ret + 'F'
        if (f & self.SYN):
            ret = ret + 'S'
        if (f & self.RST):
            ret = ret + 'R'
        if (f & self.PSH):
            ret = ret + 'P'
        if (f & self.ACK):
            ret = ret + 'A'
        if (f & self.URG):
            ret = ret + 'U'
        if (f & self.ECE):
            ret = ret + 'E'
        if (f & self.CWR):
            ret = ret + 'C'
        return ret

    def convert_tcp_flag(self, in_flag):
        if in_flag == "syn":
            return "S"
        elif in_flag == "fin":
            return "F"
        elif in_flag == "fin+ack":
            return "FA"
        elif in_flag == "rst":
            return "R"
        elif in_flag == "ack":
            return "A"
        elif in_flag == "push":
            return "P"
        elif in_flag == "push+ack":
            return "PA"
        elif in_flag == "urg":
            return "U"
        elif in_flag == "ece":
            return "E"
        elif in_flag == "cwr":
            return "C"
        elif in_flag == "syn+ack":
            return "SA"

        return "N/A"

    def convert_tcp_flag2num(self, in_flag):
        ret = 0x00

        if in_flag == "S":
            ret = self.SYN
        elif in_flag == "F":
            ret = self.FIN
        elif in_flag == "FA":
            ret = self.FIN + self.ACK
        elif in_flag == "R":
            ret = self.RST
        elif in_flag == "A":
            ret = self.ACK
        elif in_flag == "P":
            ret = self.PSH
        elif in_flag == "PA":
            ret = self.PSH + self.ACK
        elif in_flag == "U":
            ret = self.URG
        elif in_flag == "E":
            ret = self.ECE
        elif in_flag == "C":
            ret = self.CWR
        elif in_flag == "SA":
            ret = self.SYN + self.ACK

        return ret
