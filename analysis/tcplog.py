#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import sys
import pdb
import datetime
import logging
import shutil
import xlsxwriter
from pcap_utils import rtt

TYPE_RECV = 0
TYPE_SEND = 1
TYPE_TIMEOUT = 2
TYPE_SETUP = 3
TYPE_DONE = 4
TYPE_PURGE = 5

POL_DETECT = 0
POL_CLASSIFY = 1
POL_LIMIT = 2

def type2string(rtype):
    switch = {
        0: "RECV",
        1: "SEND",
        2: "TO",
        3: "SETUP",
        4: "DONE",
        5: "PURGE",
    }
    return switch[rtype]


def castate2string(ca_state):
    switch = {
        0: "Open",
        1: "Disorder",
        2: "CWR",
        3: "Recovery",
        4: "Loss",
    }
    return switch[ca_state]


def ipaddr_ntos(ipaddr):
    return "%d.%d.%d.%d" % (
            (ipaddr >> 24) & 0xff,
            (ipaddr >> 16) & 0xff,
            (ipaddr >> 8) & 0xff,
            (ipaddr) & 0xff,
    )


def tcp_inflight_num(record):
    left_out = record["sacked_out"] + record["lost_out"]
    return record["packets_out"] + record["retrans_out"] - left_out


def check_dir(dirname, archive_dir="archive"):
    """ Check whether trace directory exists. If so, move it the archive directory
    """
    cur_path = os.path.abspath("./")
    dir_abs = os.path.abspath(dirname)
    if cur_path.startswith(dir_abs):
        logging.warning(
            "'%s'('%s') is contains current path ('%s'). checking escaped." % (
                dirname, dir_abs, cur_path,
            )
        )
    elif os.path.exists(dir_abs) and os.listdir(dir_abs):
        logging.error("'%s' exists!" % dirname)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        dst_file = "%s/%s_%s" % (archive_dir, os.path.basename(dir_abs), timestamp)
        logging.info("Copy '%s' to '%s'" % (dirname, dst_file))
        if not os.path.exists(archive_dir):
            os.mkdir(archive_dir)
        shutil.move(dirname, dst_file)
        os.mkdir(dirname)
    elif not os.path.exists(dirname):
        os.mkdir(dirname)


def packet_is_lost(record):
    if "is_lost" in record and record["is_lost"] > 0:
        return record["is_lost"] == 1
    return None


class TcpLogReader(object):
    """ Read tcp log from file

    Attributes:
        ifname: A string representing the input file containing tcp logs
        odir: A string representing the directory to put tcp log in
        cname:
            A string representing the output file containing connection
            meta data
        oname: A string representing the file name to put tcp log in
        archive_dir:
            A string representing the archive directory
            hosting history tcp logs
        raw_data: A list of raw data without parsing
        data: A list of parsed data from ifname
        data_ack_inc:
            selected parsed data representing acks with ack increasing
        mss:
            Estimated mss of this connection. (Note that this value is valid
            only when TSO/GSO is turned off)
        instant_speed:
            Instantaneous speed
        irtt_ts:
            A list containing irtt calculated from timestamp; each item has format:
                (timestamp in s, irtt in s)
        rminrtt:
            A list containing the minimum irtt in a rtt; each item has format:
                (timestamp in s, rminrtt in s)
    """
    def __init__(self, ifname, oname="tcp-stat.log"):
        self.ifname = ifname
        self.raw_data = []
        self.data = []
        self.mss = 0
        self.data_ack_inc = []
        self.TYPE_RECV = TYPE_RECV
        self.TYPE_SEND = TYPE_SEND
        self.TYPE_TIMEOUT = TYPE_TIMEOUT
        self.TYPE_SETUP = TYPE_SETUP
        self.TYPE_DONE = TYPE_DONE
        self.TYPE_PURGE = TYPE_PURGE

    def calc_instant_speed(self, intvl_rtt=0, intvl=0):
        """ Calculate instaneous speed (In Bps) and store the result into
        self.instant_speed

        Args:
            intvl_rtt: An integer indicating that the sample interval is
                intv_rtt times longer than rtt. If this argument is specified,
                then argument intvl is never used.
            intvl: A floating number indicating the sample interval (in sec)
                to calculate speed. This argument is used only when intvl_rtt=0
        """
        self.instant_speed = []
        if self.data is None or len(self.data) == 0:
            self.read_and_parse()
        st_record = self.data[0]
        if intvl_rtt != 0:
            intvl = intvl_rtt * self.data[-1]["srtt"] / 8.0 / 1000.0 / 1000.0
        if st_record["type"] == self.TYPE_SETUP and len(self.data) > 1:
            st_record = self.data[1]
        for i in range(1, len(self.data)):
            record = self.data[i]
            if record["timestamp"] > st_record["timestamp"] + intvl:
                tstamp = 0.5 * (record["timestamp"] + st_record["timestamp"])
                deliver_size = record["snd_una"] - st_record["snd_una"]
                deliver_intv = record["timestamp"] - st_record["timestamp"]
                speed = deliver_size / deliver_intv
                self.instant_speed.append((tstamp, speed))
                st_record = record
                if intvl_rtt != 0:
                    intvl = intvl_rtt * st_record["srtt"] / 8.0 / 1000.0 / 1000.0


    def calc_instant_rtt_from_ts(self):
        if self.data is None or len(self.data) == 0:
            self.read_and_parse()
        rtt_cal = rtt.RTTCalculator()
        for line in self.data:
            if line["type"] ==  self.TYPE_SEND and line["length"] > 0:
                rtt_cal.send(line["timestamp"], line["seq_num"], line["length"])
            if line["type"] == self.TYPE_RECV and line["length"] == 0:
                rtt_cal.recv(
                    line["timestamp"],
                    line["ack_num"],
                    line["lost_out"],
                )
        self.irtt_ts = rtt_cal.rtt
        return self.irtt_ts


    def calc_rttmin_in_rtt(self):
        self.calc_instant_rtt_from_ts()
        self.rminrtt = rtt.get_rtt_min_in_rtt(self.irtt_ts)
        return self.rminrtt


    def calc_avg_rtt(self):
        rtts = [item["srtt"] / 8.0 / 1000 for item in self.data]
        self.avg_rtt = 1.0 * sum(rtts) / len(rtts)
        return self.avg_rtt


    def read_and_print(self):
        """ Read data and print on screen
        """
        with open(self.ifname) as ifp:
            while True:
                line = ifp.readline()
                if not line:
                    break
                print line


    def calc_instant_rtt_from_srtt(self):
        """ Calculate instant rtt from self.data
        Note: self.data may contain multiple connections,
        we assume that these connections have been separated.
        Specifically, format of self.data is as follows
            <data of connection 1>
            <data of connection 2>
            ...
            <data of connection n>
        """
        for i in xrange(0, len(self.data)):
            if (i > 0 and
                self.data[i]["srcaddr"] == self.data[i-1]["srcaddr"] and
                self.data[i]["dstaddr"] == self.data[i-1]["dstaddr"] and
                self.data[i]["srcport"] == self.data[i-1]["srcport"] and
                self.data[i]["dstport"] == self.data[i-1]["dstport"] and
                self.data[i]["srtt"] != self.data[i-1]["srtt"]):
                # Old connection
                self.data[i]["irtt_us"] = (self.data[i]["srtt"]
                                           - self.data[i-1]["srtt"]
                                           + self.data[i-1]["srtt_us"])

    def get_mss(self):
        self.mss = 0
        if len(self.data) == 0:
            self.read_and_parse()
        if self.mss > 0:
            return self.mss
        for record in self.data:
            if (record["type"] == TYPE_RECV and
                record["lost_out"] == 0 and
                record["sacked_out"] == 0 and
                record["retrans_out"] == 0 and
                record["packets_out"] > 2):
                # calculate mss
                out_bytes = record["snd_nxt"] - record["snd_una"]
                mss = out_bytes / record["packets_out"]
                self.mss = max(self.mss, mss)
        return self.mss


    def get_retrans_rate(self):
        """ get retransmission rate
        retrans rate = # retrans / # total
        """
        if len(self.data) == 0:
            self.read_and_parse()
        if self.mss <= 0:
            self.get_mss()
        retrans_num = self.data[-1]["retrans"]
        test_num = 0
        sent_num = 0
        for record in self.data:
            if record["type"] == self.TYPE_SEND:
                # send a packet
                if self.mss == 0:
                    sent_num += 1
                else:
                    sent_num += (record["length"] + self.mss - 1) / self.mss
                #if self.is_retrans(record):
                #    test_num += (record["length"] + self.mss - 1) / self.mss
        if sent_num == 0:
            return 0
        return 1.0 * retrans_num / sent_num
        #total_sent = 0
        #for record in self.data:
        #    if record["type"] == self.TYPE_SEND:
        #        total_sent += record["length"]

        #if self.mss != 0:
        #    total_data /= self.mss
        #    total_sent /= self.mss
        #else:
        #    total_data /= 1448
        #    total_sent /= 1448

        #if total_data == 0:
        #    return 0

        #return 1.0 * (total_sent - total_data) / total_data


    def is_retrans(self, record):
        return (record["type"] == self.TYPE_SEND and
                record["seq_num"] < record["snd_nxt"])

    def is_dupack(self, record):
        return (record["type"] == self.TYPE_RECV and
                record["ack_num"] <= record["snd_una"])


    def find_lost_packets_faster(self):
        """ A o(n) algorithm to determine whether a packet is lost
        1. Find all retrans packets that are retransmitted for the 1st time,
           and store them in `retran1_queue`
        2. Find all retrans packets that are retransmitted for the 2nd time,
           3rd time .... and store them in `retrans2_queue`
        3. Sort retrans2_queue according to sequence number
        4. Determine the last retransmission time and is_lost of packets
           in retrans2_queue
        5. Determine the is_lost status of packets in retrans1_queue
        6. Determine the is_lost status of packeets for all non-retrans packets
        """
        def pkt_data_before(record1, record2):
            return record1["seq_num"] + record1["length"] <= record2["seq_num"]

        def pkt_data_after(record1, record2):
            return pkt_data_before(record2, record1)

        def pkt_data_overlap(record1, record2):
            seq_num1 = record1["seq_num"]
            seq_end1 = seq_num1 + record1["length"]
            seq_num2 = record2["seq_num"]
            seq_end2 = seq_num2 + record2["length"]
            return (seq_num1 >= seq_num2 and seq_num1 < seq_end2) \
                    or (seq_end1 > seq_num2 and seq_end1 <= seq_end2)

        def determ_lost(idx_pkts, idx_retrans):
            """ Common algorithm for Step 5 and Step 6 """
            i, j = 0, 0
            while i < len(idx_pkts) and j < len(idx_retrans):
                while (i < len(idx_pkts) and
                        pkt_data_before(self.data[idx_pkts[i]], self.data[idx_retrans[j]])
                      ):
                    i += 1
                while (i < len(idx_pkts) and
                        pkt_data_overlap(self.data[idx_pkts[i]], self.data[idx_retrans[j]])
                      ):
                    self.data[idx_pkts[i]]["is_lost"] = 1
                    i += 1
                j += 1
        # Step 1 & 2
        idx_send, idx_retrans1, idx_retrans2 = [], [], []
        for i in range(0, len(self.data)):
            if self.data[i]["type"] == TYPE_SEND:
                idx_send.append(i)
                record = self.data[i]
                if "is_lost" not in record or record["is_lost"] < 0:
                    record["is_lost"] = 0
        for i in idx_send:
            if self.is_retrans(self.data[i]):
                if len(idx_retrans1) == 0:
                    idx_retrans1.append(i)
                    continue
                pkt = self.data[idx_retrans1[-1]]
                if self.data[i]["seq_num"] < pkt["seq_num"] + pkt["length"]:
                    idx_retrans2.append(i)
                else:
                    idx_retrans1.append(i)
        if len(idx_retrans2) > 0:
            idx_retrans2_new = []
            # Step 3
            idx_retrans2.sort(key=lambda x: self.data[x]["seq_num"])
            # Step 4
            j = len(idx_retrans2) - 1
            while j >= 1:
                pkt_j = self.data[idx_retrans2[j]]
                tidx = idx_retrans2[j]
                k = j-1
                pkt_k = self.data[idx_retrans2[k]]
                # determine last retransmitted packets
                while (k >= 0 and pkt_j["seq_num"] == pkt_k["seq_num"]):
                    if pkt_k["timestamp"] > self.data[tidx]["timestamp"]:
                        tidx = idx_retrans2[k]
                    k -= 1
                    if k < 0:
                        break
                    pkt_k = self.data[idx_retrans2[k]]
                idx_retrans2_new.append(tidx)
                # determine lost status
                k = j
                pkt_k = self.data[idx_retrans2[k]]
                while (k >= 0 and pkt_j["seq_num"] == pkt_k["seq_num"]):
                    if pkt_k["timestamp"] < self.data[tidx]["timestamp"]:
                        self.data[idx_retrans2[k]]["is_lost"] = 1
                    k -= 1
                    if k < 0:
                        break
                    pkt_k = self.data[idx_retrans2[k]]
                j = k
            if j == 0:
                idx_retrans2_new.append(idx_retrans2[0])
            idx_retrans2 = list(reversed(idx_retrans2_new))
            determ_lost(idx_retrans1, idx_retrans2)
        determ_lost(idx_send, idx_retrans1)


    def find_lost_packets(self):
        """ Determine whether a packet is lost
        """
        # TODO: change to an o(n) algorithm
        data_lost = []
        if self.data is None or len(self.data) == 0:
            self.read_and_parse()
        idx_send = []
        for i in range(0, len(self.data)):
            if self.data[i]["type"] == TYPE_SEND:
                idx_send.append(i)
            if "is_lost" not in self.data[i] or self.data[i]["is_lost"] < 0:
                self.data[i]["is_lost"] = 0
        for idx_i in reversed(range(0, len(idx_send))):
            i = idx_send[idx_i]
            record = self.data[i]
            if record["is_lost"]:
                continue
            if self.is_retrans(self.data[i]):
                retrans_seq_num = self.data[i]["seq_num"]
                retrans_seq_end = retrans_seq_num + self.data[i]["length"]
                idx_j = idx_i - 1
                while idx_j > 0:
                    j = idx_send[idx_j]
                    if self.data[j]["snd_nxt"] < retrans_seq_num:
                        break
                    seq_num = self.data[j]["seq_num"]
                    seq_end = self.data[j]["seq_num"] + self.data[j]["length"]
                    if (retrans_seq_num >= seq_num
                        and retrans_seq_num < seq_end):
                        # find the lost packet
                        self.data[j]["is_lost"] = 1
                    if (retrans_seq_end > seq_num
                        and retrans_seq_end <= seq_end):
                        # find the lost packet
                        self.data[j]["is_lost"] = 1
                    idx_j -= 1


    def select_data(self, law):
        """ Select data from raw data

        Args:
            law: A dictionary containing keys and values to match
        """
        result = []
        if len(self.raw_data) == 0:
            self.readfile()
        for line in self.raw_data:
            l_parse = parse_line(line)
            selected = True
            for keyname in law:
                if l_parse[keyname] != law[keyname]:
                    selected = False
                    break
            if selected:
                result.append(line)
        return result


    def readfile(self):
        """ Read data and store into self.raw_data
        """
        self.raw_data = []
        with open(self.ifname) as ifp:
            for line in ifp:
                if line.lstrip()[0] == "#":
                    continue
                self.raw_data.append(line)


    def read_and_parse(self):
        """ Read data and store into self.data
        """
        self.data = []
        with open(self.ifname) as ifp:
            for line in ifp:
                if line.lstrip()[0] == "#":
                    continue
                record = parse_line(line)
                if record is None:
                    break
                self.data.append(record)
                if (record["type"] == TYPE_RECV and
                    record["lost_out"] == 0 and
                    record["sacked_out"] == 0 and
                    record["retrans_out"] == 0 and
                    record["packets_out"] > 2):
                    # calculate mss
                    out_bytes = record["snd_nxt"] - record["snd_una"]
                    mss = out_bytes / record["packets_out"]
                    self.mss = max(self.mss, mss)
                #if (record["type"] == self.TYPE_SEND
                #    and record["length"] > self.mss):
                #    # mss = maximum packet size
                #    self.mss = record["length"]

    def store_to_excel(self, ofname, col_names=None):
        if len(self.data) == 0:
            self.read_and_parse()
        if len(self.data) == 0:
            logging.error("No valid data in %s" % self.ifname)
            return
        book = xlsxwriter.Workbook(ofname)
        sheet = book.add_worksheet()
        if col_names is not None:
            headname = col_names
        else:
            headname = [
                "type", "timestamp", "srcaddr",
                "srcport", "dstaddr", "dstport",
                "length", "tcp_flags", "seq_num",
                "ack_num", "ca_state", "snd_nxt",
                "snd_una", "write_seq", "wqueue",
                "snd_cwnd", "ssthreshold", "snd_wnd",
                "srtt", "mdev", "rttvar", "rto",
                "packets_out", "lost_out", "sacked_out",
                "retrans_out", "retrans", "frto_counter",
                "rto_num", "sk_pacing_rate",
            ]
        sheet.write_row(0, 0, headname)
        for i in range(0, len(headname)):
            if headname[i] == "type":
                data = [type2string(record["type"]) for record in self.data]
            elif headname[i] == "dstaddr" or headname[i] == "srcaddr":
                data = [ipaddr_ntos(record[headname[i]]) for record in self.data]
            elif (headname[i] == "tcp_flags"):
                data = [("0x%x" % record[headname[i]]) for record in self.data]
            elif headname[i] == "ca_state":
                data = [castate2string(record["ca_state"]) for record in self.data]
            elif headname[i] == "srtt":
                data = [record["srtt_us"]/1000.0 for record in self.data]
            elif (headname[i] == "irtt_us"
                  or headname[i] == "min_rtt_us"
                  or headname[i] == "rminrtt_us"
                  or headname[i] == "max_rminrtt_us"):
                data = [("%.3fms" % (record[headname[i]]/1000.0)) for record in self.data]
            elif (headname[i] == "ibw"
                  or headname[i] == "maxbw"
                  or headname[i] == "lt_bw"
                  or headname[i] == "pol_max_bw"
                  or headname[i] == "pol_global_max_bw"):
                data = [
                    ("%.3fMbps" % (self.bw_to_bps(record[headname[i]])/1e6)) \
                     for record in self.data
                ]
            elif headname[i] == "sk_pacing_rate":
                data = [("%.3fMbps" % (8.0*record[headname[i]]/1e6)) for record in self.data]
            elif headname[i] in self.data[0]:
                data = [record[headname[i]] for record in self.data]
            else:
                logging.error("There is no value named '%s'" % headname[i])
                continue
            sheet.write_column(1, i, data)
        sheet.freeze_panes(1, 0)
        book.close()


    def select_ack_inc(self):
        """ Select ack packets that acknowledgements new data
        """
        if len(self.data) == 0:
            self.read_and_parse()
        self.data_ack_inc = []
        prev_ack = 0
        for i in range(0, len(self.data)):
            record = self.data[i]
            if record["type"] != self.TYPE_RECV:
                continue
            if record["ack_num"] <= prev_ack:
                continue
            prev_ack = record["ack_num"]
            record["index"] = i
            self.data_ack_inc.append(record)


    def split_connection(self, odir, oname, cname, human_readable=False):
        """ Split connections from initial tcp log file

        Args:
            odir: Directory to put connection information into
            oname: A string representing the result file containing tcp log
                with connection separated
            cname: File name contains connections meta data
            human_readable: A boolean value indicating whether the result
                should be human readable. If ture, speed will be presented in
                KBps and ip address will be presented as "a.b.c.d"
        """
        cname = os.path.join(odir, cname)
        oname = os.path.join(odir, oname)
        with open(cname, "w") as cfp, open(oname, "w") as ofp:
            conns = {}
            conn_stat = {}
            cfp.write(
                "# <%s> <%s> <%s> <%s> <%s> <%s>" % (
                    "srcip", "srcport", "dstip", "dstport",
                    "from_line", "to_line",
                ),
            )
            cfp.write(
                " <%s> <%s> <%s> <%s>" % (
                    "retrans #", "timeout #",
                    "send size (B)", "duration (s)"
                ),
            )
            if human_readable:
                cfp.write(" <%s>" % "Speed (KBps)")
            else:
                cfp.write(" <%s>" % "Speed (Bps)")

            cfp.write("\n")
            lnum = 0  # the number of lines in ofp

            def dump_connection(conn, lnum):
                l_parse_first = parse_line(conns[conn][0])
                l_parse_last = parse_line(conns[conn][-1])
                start_ts = l_parse_first["timestamp"]
                end_ts = l_parse_last["timestamp"]
                if (len(conns[conn]) == 2 and
                    l_parse_first["type"] == self.TYPE_SETUP and (
                        l_parse_last["type"] == self.TYPE_DONE or
                        l_parse_last["type"] == self.TYPE_PURGE)
                    ):
                    logging.warn(
                        "Connection (%s:%d - %s:%d) has no data, skip it." % (
                            ipaddr_ntos(conn[0]), conn[1],
                            ipaddr_ntos(conn[2]), conn[3],
                        )
                    )
                    return 0
                if l_parse_first["type"] == self.TYPE_SETUP:
                    # use second item
                    if len(conns[conn]) >= 2:
                        l_parse_first = parse_line(conns[conn][1])
                    else:
                        return 0
                if (l_parse_last["type"] == self.TYPE_DONE or
                    l_parse_last["type"] == self.TYPE_PURGE):
                    # use the previous one
                    if len(conns[conn]) >= 2:
                        l_parse_last = parse_line(conns[conn][-2])
                    else:
                        return 0
                if human_readable:
                    meta = "%s:%d %s:%d" % (
                        ipaddr_ntos(conn[0]), conn[1],
                        ipaddr_ntos(conn[2]), conn[3],
                    )
                    meta += " [%.3f,%.3f)" % (start_ts, end_ts)
                    meta += " [%d,%d)" % (lnum, lnum+len(conns[conn]))
                else:
                    meta = "%d %d %d %d" % conn
                    meta += " %.3f %.3f" % (start_ts, end_ts)
                    meta += " %d %d" % (lnum, lnum+len(conns[conn]))
                # sent_size = l_parse_last["snd_nxt"] - l_parse_first["snd_nxt"]
                sent_size = l_parse_last["snd_una"] - l_parse_first["snd_una"]
                duration = l_parse_last["timestamp"] - l_parse_first["timestamp"]
                if duration == 0:
                    sent_size, duration = 0, 1
                if human_readable:
                    meta += " %d %d %dB %.6fs" % (
                        l_parse_last["retrans"], l_parse_last["rto_num"],
                        sent_size, duration
                    )
                    meta += " %.3fKBps" % (sent_size / duration / 1000)
                else:
                    meta += " %d %d %d %.6f" % (
                        l_parse_last["retrans"], l_parse_last["rto_num"],
                        sent_size, duration
                    )
                    meta += " %d" % int(sent_size / duration)
                cfp.write(meta + "\n")
                for record in conns[conn]:
                    ofp.write(record)
                return len(conns[conn])

            with open(self.ifname) as ifp:
                for line in ifp:
                    if line.lstrip()[0] == "#":
                        continue
                    l_parse = parse_line(line)
                    if l_parse is None:
                        continue
                    conn = (
                        l_parse["srcaddr"], l_parse["srcport"],
                        l_parse["dstaddr"], l_parse["dstport"],
                    )
                    if conn in conns:
                        conns[conn].append(line)
                        # conn_stat[conn]["send_size"] += l_parse["length"]
                    else:
                        conns[conn] = [line, ]
                        # conn_stat[conn] = {
                        #     "send_size": l_parse["length"],
                        # }
                    if (l_parse["type"] == self.TYPE_DONE or
                        l_parse["type"] == self.TYPE_PURGE):
                        # dump connections into file
                        lnum += dump_connection(conn, lnum)
                        # lnum += len(conns[conn])
                        del conns[conn]
                for conn in conns:
                    l_parse = parse_line(conns[conn][-1])
                    lnum += dump_connection(conn, lnum)
                    #lnum += len(conns[conn])


    def get_deliver_size(self):
        """ Get the size of successfully deliverred data (in Bytes).

        Return:
            Data size in Bytes
        """
        return self.data[-1]["snd_una"] - self.data[0]["snd_una"]


    def bw_to_bps(self, ibw):
        return (int(ibw * (self.mss+40) * 1e6) >> 24) * 8

    def get_maxbw_bps(self):
        for record in self.data:
            record["maxbw_bps"] = self.bw_to_bps(record["maxbw"])



def parse_line(line, num_base=16):
    """ Parse a line into dictionary.

    line: A string containing line to be parsed
    num_base: Base of all numbers

    Returns:
        A dictionary containing the data
    """
    result = {}
    line = line.split()
    result = {}
    if len(line) < 31:
        return None
    result["type"] = int(line[0], base=num_base)
    result["timestamp"] = (
            int(line[1], base=num_base) +
            int(line[2], base=num_base) / 1000 / 1000.0 / 1000.0)
    result["srcaddr"] = int(line[3], base=num_base)
    result["srcport"] = int(line[4], base=num_base)
    result["dstaddr"] = int(line[5], base=num_base)
    result["dstport"] = int(line[6], base=num_base)
    # packet size in Bytes
    result["length"] = int(line[7], base=num_base)
    result["tcp_flags"] = int(line[8], base=num_base)
    result["seq_num"] = int(line[9], base=num_base)
    result["ack_num"] = int(line[10], base=num_base)
    result["ca_state"] = int(line[11], base=num_base)
    result["snd_nxt"] = long(line[12], base=num_base)
    result["snd_una"] = int(line[13], base=num_base)
    result["write_seq"] = int(line[14], base=num_base)
    result["wqueue"] = int(line[15], base=num_base)
    result["snd_cwnd"] = int(line[16], base=num_base)
    result["ssthreshold"] = int(line[17], base=num_base)
    result["snd_wnd"] = int(line[18], base=num_base)
    result["srtt"] = int(line[19], base=num_base)
    result["srtt_us"] = result["srtt"] >> 3;
    result["mdev"] = int(line[20], base=num_base)
    result["rttvar"] = int(line[21], base=num_base)
    result["rto"] = int(line[22], base=num_base)
    result["packets_out"] = int(line[23], base=num_base)
    result["lost_out"] = int(line[24], base=num_base)
    result["sacked_out"] = int(line[25], base=num_base)
    result["retrans_out"] = int(line[26], base=num_base)
    result["retrans"] = int(line[27], base=num_base)
    result["frto_counter"] = int(line[28], base=num_base)
    result["rto_num"] = int(line[29], base=num_base)
    result["is_lost"] = -1
    # Bytes per second
    result["sk_pacing_rate"] = int(line[30], base=num_base)
    #result["user-agent"] = ""
    #if len(line) >= 36:
    #    result["user-agent"] = " ".join(line[35:])
    return result


def tostring_readable(record, *keys):
    result = ""
    for keyname in keys:
        if keyname == "type":
            if record["type"] == TYPE_SEND:
                result += "s "
            elif record["type"] == TYPE_RECV:
                result += "r "
            else:
                result += "%d " % record["type"]
        elif keyname == "timestamp":
            result += "%5.3fs " % record["timestamp"]
        elif keyname == "srcaddr" or keyname == "dstaddr":
            result += ipaddr_ntos(record[keyname]) + " "
        elif keyname == "srcport" or keyname == "dstport":
            result += ":%d " % record[keyname]
        elif keyname == "length":
            result += "%dB " % record[keyname]
        elif keyname == "srtt":
            result += "%.3fms " % record[keyname] / 8.0 / 1000.0
        elif keyname == "rto":
            result += "%dms " % record[keyname]
        elif keyname == "ca_state":
            state_name = [
                "TCP_CA_Open",
                "TCP_CA_Disorder",
                "TCP_CA_CWR",
                "TCP_CA_Recovery",
                "TCP_CA_Loss",
            ]
            result += state_name[record[keyname]] + " "
        elif keyname == "tcp_flags":
            result += "%x " % record[keyname]
        else:
            result += "%d " % record[keyname]
    return result


def tostring_connection(connection, human_readable=False):
    if human_readable:
        result = "%s:%d %s:%d [%.3fs,%.3fs) [%d,%d) %d %d " % (
            ipaddr_ntos(connection["srcaddr"]),
            connection["srcport"],
            ipaddr_ntos(connection["dstaddr"]),
            connection["dstport"],
            connection["stime"],
            connection["etime"],
            connection["from"],
            connection["to"],
            connection["retrans"],
            connection["rto_num"],
        )
        if connection["size"] < 1024:
            result += "%dB " % connection["size"]
        elif connection["size"] < 1024 * 1024:
            result += "%.3fKB " % (connection["size"] / 1024.0)
        elif connection["size"] < 1024 * 1024 * 1024:
            result += "%.3fMB " % (connection["size"] / 1024.0 / 1024.0)
        else:
            result += "%.3fGB " % (connection["size"] / 1024.0 / 1024.0 / 1024.0)
        result = result + "%.6fs %.3fKBps" % (
            connection["duration"],
            connection["speed"] / 1000.0,
        )
        return result
    else:
        return "%d %d %d %d %.3f %.3f %d %d %d %d %d %.6f %d" % (
            connection["srcaddr"],
            connection["srcport"],
            connection["dstaddr"],
            connection["dstport"],
            connection["stime"],
            connection["etime"],
            connection["from"],
            connection["to"],
            connection["retrans"],
            connection["rto_num"],
            connection["size"],
            connection["duration"],
            connection["speed"]
        )


def parse_line_connection(line):
    line = line.split()
    result = {
        "srcaddr": int(line[0]),
        "srcport": int(line[1]),
        "dstaddr": int(line[2]),
        "dstport": int(line[3]),
        "stime": float(line[4]),
        "etime": float(line[5]),
        "from": int(line[6]),
        "to": int(line[7]),
        "retrans": int(line[8]),
        "rto_num": int(line[9]),
        "size": int(line[10]),
        "duration": float(line[11]),
        "speed": int(line[12]),
    }
    return result


def main():
    pass

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-5s %(levelname)-6s %(message)s "
        "(in %(filename)s function '%(funcName)s' line %(lineno)s)",
        datefmt="%m-%d %H:%M",
    )
    main()
