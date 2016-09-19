# -*- coding: UTF-8 -*-

from scapy.all import *


class PacketInfo:
    ## L2 Layer ##
    _eth_dst = "00:00:00:00:00:00"
    _eth_src = "00:00:00:00:00:00"
    _eth_type = 0x800

    ## L3 Layer ##
    # ipv4
    _ip_ver = 4
    _ip_ihl = None
    _ip_tos = 0
    _ip_len = None
    _ip_id = 1
    _ip_flags = 0
    _ip_frag = 0

    _ip_ttl = 64
    _ip_proto = 6  # tcp
    _ip_chksum = None
    _ip_src = "1.1.1.1"
    _ip_dst = "1.1.1.2"
    _ip_options = []

    ## L4 Layer ##
    # tcp
    _tcp_sport = 80
    _tcp_dport = 80
    _tcp_seq = 0
    _tcp_ack = 0
    _tcp_dataofs = None
    _tcp_reserved = 0
    _tcp_flags = ""
    _tcp_window = 65535
    _tcp_chksum = None
    _tcp_urgptr = 0
    #example => [("MSS", 1460), ("SAck",(20,30)), ("SAckOK", ""), ("SAck",(40,50)), ("SAck", (70,80)), ("SAckOk","ok")]
    _tcp_options = [ ]
    _tcp_mss = ""
    _tcp_sack_perm = ""

    ## L7 Layer ##
    _raw_data = ""
    _file_name = ""
    _file_size = ""

    ## Test Layer ##
    _action = ""
    _step = ""
    _tcp_index = 0
    _tcp_length = 0

    _delay = 0
    _timeo = 0

    #const
    MAX_TCP_SEQUENCE = 4294967295

    ## method ##
    def initialize(self, scapyStrRawData):
        splitLayer = scapyStrRawData.split("/")

        if len(splitLayer) != 3:
            print "Error: scapy raw data is worng format."
            return

        self.init_ether_layer(splitLayer[0])
        self.init_ip_layer(splitLayer[1])
        self.init_tcp_layer(splitLayer[2])

    def is_big_packet(self):
        return True if len(self._raw_data) != 0 else False

    def check_payload(self, payload):
        # REFACT
        payload = payload[10:len(payload) - 2]
        self._raw_data = self._raw_data.replace(payload, "")

    ## set method ##
    def set_packet_action(self, in_action):
        self._action = in_action

    def set_tc_step(self, in_step):
        self._step = in_step

    def set_timeo(self, in_timeo):
        self._timeo = in_timeo

    def set_ether_data(self, in_dst, in_src, in_type):
        self._eth_dst = in_dst
        self._eth_src = in_src
        self._eth_type = in_type

    def set_ether_datas(self, in_src, in_dst):
        self._eth_src = in_src
        self._eth_dst = in_dst

    def set_window_size(self, windsz):
        self._tcp_window = long(windsz)

    def set_tcp_flags(self, in_flag):
        if self._tcp_flags == "" or self._tcp_flags == "N/A":
            self._tcp_flags = self.convert_tcp_flag(in_flag)

    def set_tcp_seq(self, in_seq):
        num = long(in_seq)
        if (num > self.MAX_TCP_SEQUENCE):
            num = num - self.MAX_TCP_SEQUENCE
        self._tcp_seq = num
        return num

    def set_tcp_ack(self, in_ack):
        num = long(in_ack)
        if (num > self.MAX_TCP_SEQUENCE):
            num = num - self.MAX_TCP_SEQUENCE
        self._tcp_ack = num
        return num

    def set_tcp_sack_block(self, in_sle, in_sre):
        sle = long(in_sle)
        sre = long(in_sre)
        self._tcp_options = [("SAck", (sle, sre))]

    def set_tcp_sack_permitted(self):
        self._tcp_options = [("SAckOK", "")]

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

    def set_ip_addr(self, sip, dip):
        self._ip_src = sip
        self._ip_dst = dip

    def set_tcp_port_num(self, sport, dport):
        self._tcp_sport = sport
        self._tcp_dport = dport

    def set_tcp_index(self, index):
        self._tcp_index = long(index)

    def set_tcp_length(self, length):
        self._tcp_length = long(length)

    def set_delay(self, delay):
        self._delay = long(delay)
        print 'set delay\n'

    ## get method ##
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

    def get_tcp_layer_for_proxy(self, _sport, _dport):
        return TCP(sport=int(_sport),
                   dport=int(_dport),
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

    ## inner method ##
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
        elif in_flag == "urg":
            return "U"
        elif in_flag == "push+ack":
            return "PA"
        elif in_flag == "ece":
            return "E"
        elif in_flag == "cwr":
            return "C"
        elif in_flag == "syn+ack":
            return "SA"

        return "N/A"

    def parse_str_value(self, str):
        ret = ""

        try:
            ret = str.split('=')[1].split("'")[1]
        except:
            print "Error: layer string value(%s) parse fail." % str

        return ret

    def parse_int_value(self, str):
        ret = ""

        try:
            ret = str.split('=')[1].split("'")[0]
        except:
            print "Error: layer int value(%s) parse fail." % str

        return ret

    def parse_list_value(self, str):
        ret = ""

        try:
            ret = str.split('=')[1]
        except:
            print "Error: layer list value(%s) parse fail." % str

        return ret

    def init_ether_layer(self, ether_str_raw_data):
        raw_data = ether_str_raw_data.split(',')

        if len(raw_data) != 3:
            print "Error: ether layer raw string."

        self._eth_src = self.parse_str_value(raw_data[0])
        self._eth_dst = self.parse_str_value(raw_data[1])
        self._eth_type = self.parse_int_value(raw_data[2]).split(')')[0]

    def init_ip_layer(self, ip_str_raw_data):
        raw_data = ip_str_raw_data.split(',')

        if len(raw_data) != 13:
            print "Error: ip layer raw string."

        self._ip_frag = self.parse_int_value(raw_data[0])
        self._ip_src = self.parse_str_value(raw_data[1])
        self._ip_proto = self.parse_int_value(raw_data[2])
        self._ip_tos = self.parse_int_value(raw_data[3])
        self._ip_dst = self.parse_str_value(raw_data[4])
        self._ip_chksum = self.parse_int_value(raw_data[5])
        self._ip_len = self.parse_int_value(raw_data[6])
        self._ip_options = self.parse_list_value(raw_data[7])
        self._ip_ver = self.parse_int_value(raw_data[8])
        self._ip_flags = self.parse_int_value(raw_data[9])
        self._ip_ihl = self.parse_int_value(raw_data[10])
        self._ip_ttl = self.parse_int_value(raw_data[11])
        self._ip_id = self.parse_int_value(raw_data[12])

    def init_tcp_layer(self, tcp_str_raw_data):
        tcp_options = tcp_str_raw_data[tcp_str_raw_data.find("options"):len(tcp_str_raw_data) - 1]
        raw_data = tcp_str_raw_data.replace(tcp_options, "").split(',')

        if len(raw_data) != 11:
            print "Error: tcp layer raw string."

        self._tcp_reserved = self.parse_int_value(raw_data[0])
        self._tcp_seq = self.parse_int_value(raw_data[1])
        self._tcp_ack = self.parse_int_value(raw_data[2])
        self._tcp_dataofs = self.parse_int_value(raw_data[3])
        self._tcp_urgptr = self.parse_int_value(raw_data[4])
        self._tcp_window = self.parse_int_value(raw_data[5])
        self._tcp_flags = self.parse_int_value(raw_data[6])
        self._tcp_chksum = self.parse_int_value(raw_data[7])
        self._tcp_dport = self.parse_int_value(raw_data[8])
        self._tcp_sport = self.parse_int_value(raw_data[9])

        #FIXME - tcpOptions scapy 2.1.0 does not support options
        self._tcp_options = self.parse_list_value(raw_data[10])

    ## method for debug ##
    def _print_inner_value(self):
        print "###### start ######"
        print "action : " + self._action
        if self._step == None:
            print "step : None"
        else:
            print "step : " + self._step
        print "ip_src : " + self._ip_src
        print "ip_dst : " + self._ip_dst
        print "tcp_sport : " + str(self._tcp_sport)
        print "tcp_dport : " + str(self._tcp_dport)
        print "tcp_seq : " + str(self._tcp_seq)
        print "tcp_ack : " + str(self._tcp_ack)
        print "tcp_flags : " + str(self._tcp_flags)
        print "tcp_mss : " + self._tcp_mss
        print "tcp options"
        for option in self._tcp_options:
            print option
        print "tcp_sackPerm" + self._tcp_sack_perm
        print "raw_data : "
        print self._raw_data
        print "###### end ######"

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
