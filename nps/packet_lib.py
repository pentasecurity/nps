# -*- coding: UTF-8 -*-


class TcpFlagInfo:
    #global variable define
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


class calcSeqAckNumber:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    establish_s = 0
    establish_sa = 0
    establish_f = 0
    establish_fa = 0

    def parse_flag_len_by_hexa(self, iface, flag):
        if (flag == self.FIN):
            self.establish_f = 1
            return 1
        if (flag == (self.FIN + self.ACK)):
            self.establish = 1
            return 1

        if (self.establish_s == 0):
            if (flag == self.SYN):
                self.establish_s = 1
                return 1
        if (self.establish_sa == 0):
            if (flag == (self.SYN + self.ACK)):
                self.establish_sa = 1
                return 1

        return 0
