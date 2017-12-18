#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import dpkt
import logging
import socket
import numpy as np
from matplotlib import pyplot as plt
import pdb


class BasicQueue(object):
    def __init__(self, size=10000):
        self._size = size
        self._length = 0
        self._que = [None] * size
        self._head = 0
        self._tail = 0

    def get_head(self):
        if self._length <= 0:
            return None
        else:
            return self._que[self._head]

    def get_tail(self):
        if self._length <= 0:
            return None
        else:
            return self._que[self._tail-1]

    def enqueue(self, element):
        if self._length == self._size:
            return None
        else:
            self._que[self._tail] = element
            self._tail = (self._tail + 1) % self._size
            self._length += 1
            return element

    def dequeue(self):
        if self._length == 0:
            return None
        else:
            element = self._que[self._head]
            self._head = (self._head + 1) % self._size
            self._length -= 1
            return element

    def length(self):
        return self._length


class RTTCalculator(object):
    """ Calculate rtt according to data packets and ack packets

    Attributes:
        rtt: A list containing the calculated rtt in s
        send_que: The send queue containing packets sent
            but not acknowledgemented.
    """

    def __init__(self):
        self.CA_OPEN = 0
        self.CA_LOSS = 1
        self.rtt = []
        self.send_que = BasicQueue()
        self._ca_state = self.CA_OPEN
        self._high_seq = 0


    def get_snd_una(self):
        head_pkt = self.send_que.get_head()
        return head_pkt["seq_num"]

    def get_snd_nxt(self):
        tail_pkt = self.send_que.get_tail()
        return tail_pkt["seq_num"] + tail_pkt["size"]

    def send(self, ts, seq_num, data_size):
        """ A data packet is sent

        Args:
            ts: A floating number representing
                the timestamp of when packet is sent.
            seq_num: An integer representing
                the sequence number of the packet.
            data_size: An integer representing
                the tcp payload size (in Byte) of sent packet.
        """
        if self.send_que.length() == 0:
            pkt = {
                "timestamp": ts,
                "seq_num": seq_num,
                "size": data_size,
            }
            if self.send_que.enqueue(pkt) is None:
                logging.error("send queue is full")
        head_pkt = self.send_que.get_head()
        tail_pkt = self.send_que.get_tail()
        snd_nxt = tail_pkt["seq_num"] + tail_pkt["size"]
        # if it is a retransmit
        if seq_num < snd_nxt:
            if self._ca_state == self.CA_OPEN:
                self._ca_state = self.CA_LOSS
                self._high_seq = snd_nxt
        else:
            pkt = {
                "timestamp": ts,
                "seq_num": seq_num,
                "size": data_size,
            }
            if self.send_que.enqueue(pkt) is None:
                logging.error("send queue is full")

    def recv(self, ts, ack_num, lost_out=-1):
        """ An ack packet is received

        Args:
            ts: A floating number representing
                the timestamp of when packet is sent.
            ack_num: An integer representing
                the ack number of the packet.
        """
        # calculate rtt
        head_pkt = self.send_que.get_head()
        if head_pkt is None:
            return
        send_ts = -1
        ack_pkt_num = 0
        while head_pkt is not None and head_pkt["seq_num"] < ack_num:
            ack_pkt_num += 1
            send_ts = head_pkt["timestamp"]
            self.send_que.dequeue()
            head_pkt = self.send_que.get_head()
        # duplicate ACK
        if ack_pkt_num == 0:
            return
        if self._ca_state == self.CA_LOSS:
            if ack_num >= self._high_seq:
                self._ca_state = self.CA_OPEN
            return
        #if lost_out == 0 and ack_pkt_num <= 1:
        if lost_out == 0:
            ack_rtt = ts - send_ts
            self.rtt.append((ts, ack_rtt))


# packet type
PKT_NOT_TCP = 0
PKT_SYN = 1
PKT_SYN_ACK = 2
PKT_ACK = 3
PKT_DATA = 4
PKT_FIN = 5
PKT_RST = 6
PKT_UNKNOWN = 7

def classify_pkt(buf):
    """ Classify packet into different catagories
    """
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        return PKT_NOT_TCP
    ip = eth.data
    if not isinstance(ip.data, dpkt.tcp.TCP):
        return PKT_NOT_TCP
    tcp = ip.data
    if tcp.flags == dpkt.tcp.TH_SYN:
        return PKT_SYN
    elif tcp.flags == (dpkt.tcp.TH_ACK | dpkt.tcp.TH_SYN):
        return PKT_SYN_ACK
    elif (tcp.flags & dpkt.tcp.TH_RST):
        return PKT_RST
    elif (tcp.flags & dpkt.tcp.TH_FIN):
        return PKT_FIN
    elif len(tcp.data) > 0:
        return PKT_DATA
    elif (tcp.flags & dpkt.tcp.TH_ACK) != 0:
        return PKT_ACK
    else:
        return PKT_UNKNOWN


class PcapRTTCalculator(object):
    """ Calculate rtt a tcp flow from pcap file.
    We assume that the pcap file contains only one flows
    We assume that the remote will proactively connect the local.
    We assume that the local will send data to the remote

    Attributes:
        pcap_fp: File object of the opened pcap file.
        pcap: dpkt pcap reader
        listen:
            whether the server is listen. If the server is not listen, then
            the syn packet is sent by server.
    """
    def __init__(self, pcap_fp, listen=False, self_ip=None):
        self.pcap_fp = pcap_fp
        self.pcap = dpkt.pcap.Reader(self.pcap_fp)
        self.self_ip = self_ip
        self.listen = listen
        self._rtt_calculator = RTTCalculator()

    def calc_rtt(self):
        #pdb.set_trace()
        for timestamp, buf in self.pcap:
            # pdb.set_trace()
            pkt_type = classify_pkt(buf)
            # ignore packet
            if pkt_type == PKT_NOT_TCP:
                logging.warning(
                    "Not a valid tcp packet received at %.9f" % timestamp)
                continue
            if pkt_type == PKT_SYN_ACK:
                logging.debug("Skip syn ack packet.")
                continue

            # end of a connection
            if pkt_type == PKT_FIN or pkt_type == PKT_RST:
                logging.debug("Receive fin or rst packet, connection end.")
                break

            ip = dpkt.ethernet.Ethernet(buf).data
            tcp = ip.data

            if pkt_type == PKT_SYN:
                # syn packet
                if self.self_ip is None:
                    self.self_ip = ip.dst if self.listen else ip.src
                elif self.listen and ip.dst != self.self_ip:
                    continue
                elif (not self.listen) and ip.src != self.self_ip:
                    continue
                self.local_ip = self.self_ip
                if self.listen:
                    self.local_port = tcp.dport
                    self.remote_ip = ip.src
                    self.remote_port = tcp.sport
                else:
                    self.local_port = tcp.sport
                    self.remote_ip = ip.dst
                    self.remote_port = tcp.dport
                logging.debug("Receive syn packet")
            elif pkt_type == PKT_DATA and ip.dst == self.remote_ip:
                # data packet
                hint = "Not a valid data packet "
                hint += "(%s:%d-->%s:%s %dB): " % (
                    socket.inet_ntop(socket.AF_INET, ip.src),
                    tcp.sport,
                    socket.inet_ntop(socket.AF_INET, ip.dst),
                    tcp.dport,
                    len(tcp.data))

                # check whether the packet is valid
                if ip.src != self.local_ip:
                    hint += "expected src ip %s" % self.local_ip
                    logging.warning(hint)
                elif tcp.sport != self.local_port:
                    hint += "expected src port %s" % self.local_port
                    logging.warning(hint)
                elif tcp.dport != self.remote_port:
                    hint += "expected dst port %s" % self.remote_port
                    logging.warning(hint)
                else:
                    # a valid packet, send it
                    logging.debug(
                        "Send a %dB data packet at time %.9f" % (
                            len(tcp.data), timestamp
                        )
                    )
                    self._rtt_calculator.send(
                        timestamp, tcp.seq,
                        len(tcp.data),
                    )
            elif pkt_type == PKT_ACK and ip.dst == self.local_ip:
                # receive an ack
                hint = "Not a valid ack packet "
                hint += "(%s:%d-->%s:%s %dB): " % (
                    socket.inet_ntop(socket.AF_INET, ip.src),
                    tcp.sport,
                    socket.inet_ntop(socket.AF_INET, ip.dst),
                    tcp.dport,
                    len(tcp.data))
                # send a data packet
                if ip.src != self.remote_ip:
                    hint += "expected src ip %s" % self.remote_ip
                    logging.warning(hint)
                elif tcp.sport != self.remote_port:
                    hint += "expected src port %s" % self.remote_port
                    logging.warning(hint)
                elif tcp.dport != self.local_port:
                    hint += "expected dst port %s" % self.local_port
                    logging.warning(hint)
                else:
                    logging.debug(
                        "Receive an ack packet at time %.9f" % timestamp
                    )
                    self._rtt_calculator.recv(timestamp, tcp.ack)
            else:
                pass
        # end of for

    def get_rtt(self):
        return self._rtt_calculator.rtt


def get_rtt_min_in_rtt(rtts):
    """ Get the minimum rtt during a rtt

    Args:
        rtts: a list of rtts. Each item has the format:
            (timestamp in s, rtt in s)

    Returns:
        A list of rtt_mins. Each item has the format:
            (timestamp in s, rtt_min in s)
    """
    result = []
    st_time, st_rtt = rtts[0]
    rttmin = st_rtt
    prev_ts = st_time
    for (tstamp, rtt) in rtts:
        if tstamp > st_time + st_rtt:
            result.append(((st_time + prev_ts) / 2.0, rttmin))
            st_time, st_rtt = tstamp, rtt
            rttmin = rtt
        else:
            rttmin = min(rttmin, rtt)
        prev_ts = tstamp
    return result


def plot_rtt(rtt_data):
    times = [item[0] for item in rtt_data]
    rtts = [item[1] for item in rtt_data]
    plt.plot(times, rtts, "bo", times, rtts, "k")
    plt.xlabel("Time (s)")
    plt.ylabel("rtt (s)")
    plt.show()


def dump_rtt(ofname, rtt_data):
    rtt_data = [(item[0], item[1] * 1000) for item in rtt_data]
    np.savetxt(
        ofname, rtt_data, fmt="%10.6f %10.6fms",
        header="<timestamp in s> <rtt>",
    )


def test():
    parser = argparse.ArgumentParser(
        description="Get rtt of a tcp flow",
    )
    parser.add_argument(
        "pcap_file",
        help="The pcap file name.",
    )
    args = parser.parse_args()
    with open(args.pcap_file) as ifp:
        rtt_cal = PcapRTTCalculator(ifp)
        rtt_cal.calc_rtt()
        dump_rtt("rtt.dat", rtt_cal.get_rtt())
    plot_rtt(rtt_cal.get_rtt())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test()
