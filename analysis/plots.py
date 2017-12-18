#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import pdb
import logging
import argparse
import matplotlib
#matplotlib.use('Agg')
from matplotlib import pyplot as plt
import numpy as np
import progressbar
import tcplog
from pcap_utils import rtt


def cmd_parse():
    parser = argparse.ArgumentParser(
        description=("Plot connections from a log file"
                     "(containing only one connection)."),
    )
    parser.add_argument(
        "iname", help="The original log file containing tcp log.",
    )
    parser.add_argument(
        "-o", "--oname", default="result.png", help="The output figure name."
    )
    return parser.parse_args()

def get_percentile(data, per=0.99):
    return sorted(data)[int(len(data) * per)]


def cmd_parse_dir():
    parser = argparse.ArgumentParser(
        description=("Plot connections from log files in a directory"
                     "(Each log file containing only one connection)."),
    )
    parser.add_argument(
        "dir", help="The directory containing tcp log file.",
    )
    parser.add_argument(
        "-o", "--odir",
        default="tcp_evolution_figs",
        help="The output directory to put figure name.",
    )
    return parser.parse_args()


def template(reader, axis):
    for record in reader.data:
        tstamp.append(record["timestamp"])
        yvals.append(record[keyname])
    axis.plot(tstamp, yvals, linewidth=1)


def plot_seqnum(reader, axis):
    reader.find_lost_packets()
    newsend, retrans, lost_pkt = [], [], []
    for record in reader.data:
        if record["type"] != reader.TYPE_SEND:
            continue
        if reader.is_retrans(record):
            retrans.append((record["timestamp"], record["seq_num"]))
        else:
            newsend.append((record["timestamp"], record["seq_num"]))
        if record["is_lost"] == 1:
            lost_pkt.append((record["timestamp"], record["seq_num"]))
    tstamp, newsend = zip(*newsend)
    axis.plot(tstamp, newsend, "o", markersize=3, color="grey")
    if len(lost_pkt) > 0:
        tstamp, lostpkt = zip(*lost_pkt)
        axis.plot(tstamp, lostpkt, "bx", markersize=3, label="lost")
    if len(retrans) > 0:
        tstamp, retrans = zip(*retrans)
        axis.plot(tstamp, retrans, "ro", markersize=4, label="retrans")
    axis.set_ylabel("seq num")
    axis.legend(loc='best')


def plot_acknum(reader, axis):
    newack = []
    dupack = []
    for record in reader.data:
        if record["type"] != reader.TYPE_RECV:
            continue
        if reader.is_dupack(record):
            dupack.append((record["timestamp"], record["ack_num"]))
        else:
            newack.append((record["timestamp"], record["ack_num"]))
    if len(newack) == 0:
        return None
    tstamp, newack = zip(*newack)
    axis.plot(tstamp, newack, "bo", markersize=3, color="grey")
    if len(dupack) > 0:
        tstamp, dupack = zip(*dupack)
        axis.plot(tstamp, dupack, "ro", markersize=5, label="duplicate ACK")
    axis.set_ylabel("ack num")
    axis.legend(loc='best')


def plot_wnd_related(reader, axis):
    """ Plot snd_cwnd (main), snd_wnd, inflight_num, send_buffer
    """
    tcp_mss = reader.mss if reader.mss > 0 and reader.mss < 1600 else 1448
    tstamp = [item["timestamp"] for item in reader.data]
    snd_cwnd = [item["snd_cwnd"] for item in reader.data]
    snd_wnd = [item["snd_wnd"]/tcp_mss for item in reader.data]
    inflight = [tcplog.tcp_inflight_num(item) for item in reader.data]
    send_buff = [item["wqueue"]/tcp_mss for item in reader.data]


    axis.plot(tstamp, snd_cwnd, "b-", linewidth=1.5, label="cwnd")
    axis.plot(tstamp, inflight, "r-", label="inflight")
    axis.plot(tstamp, send_buff, "y-", label="send buff")
    axis.plot(tstamp, snd_wnd, "g-", linewidth=1.5, label="rwnd")

    y_max = get_percentile(snd_cwnd, 0.95)
    y_min, y_max = get_range_center_jitter(snd_cwnd)
    y_min2, y_max2 = get_range_center_jitter(inflight)
    y_min = min(y_min, y_min2)
    y_max = max(y_max, y_max2)
    axis.set_ylim([y_min, y_max])
    axis.legend(loc='lower right', bbox_to_anchor=(1.0, 1.0), ncol=4)
    axis.set_ylabel("Pkts")


def plot_cwnd(reader, axis, color, label=""):
    tstamp = [item["timestamp"] for item in reader.data]
    snd_cwnd = [item["snd_cwnd"] for item in reader.data]

    axis.plot(tstamp, snd_cwnd, linewidth=1, label=label, color=color,)
    axis.set_ylabel("cwnd (pkt)")



def plot_lost_related(reader, axis):
    tstamp = [item["timestamp"] for item in reader.data]
    retrans = [item["retrans_out"] for item in reader.data]
    losts = [item["lost_out"] for item in reader.data]
    sacks = [item["sacked_out"] for item in reader.data]

    axis.plot(tstamp, retrans, "b-", label="retrans\_out", linewidth=2)
    axis.plot(tstamp, losts, "g-", label="lost\_out")
    axis.plot(tstamp, sacks, "r-", label="sacked\_out")

    axis.legend(loc='upper right')
    axis.set_ylabel("Pkts")



def plot_srtt(reader, axis):
    tstamp = [item["timestamp"] for item in reader.data]
    srtt = [item["srtt_us"]/1000.0 for item in reader.data]

    axis.plot(tstamp, srtt, label="srtt", linewidth=3)
    axis.set_ylabel("RTT (ms)")


def plot_irtt(reader, axis):
    rtts = reader.calc_instant_rtt_from_ts()
    if len(rtts) == 0:
        return None
    tstamp, irtt = zip(*rtts)
    irtt = map(lambda item: item * 1000.0, irtt)
    axis.plot(tstamp, irtt, label="irtt")
    axis.set_ylabel("RTT (ms)")


def plot_rtt_related(reader, axis):
    if len(reader.data) == 0:
        return
    if "irtt_us" in reader.data[0]:
        irtt = [item["irtt_us"]/1000.0 for item in reader.data]
        axis.plot(tstamp, irtt, "b-o", label="irtt", markersize=2)
        if "rminrtt_us" in reader.data[0]:
            tstamp = [item["timestamp"] for item in reader.data \
                      if item["rminrtt_us"] != ((1<<32)-1)]
            rminrtt = [item["rminrtt_us"]/1000.0 for item in reader.data \
                      if item["rminrtt_us"] != ((1<<32)-1)]
            axis.plot(
                tstamp, rminrtt, "g-o", label="rminrtt",
                linewidth=1.2, markersize=1.2,
            )
    else:
        rtts = reader.calc_instant_rtt_from_ts()
        y_max = 0
        if len(rtts) > 0:
            tstamp, irtt = zip(*rtts)
            irtt = map(lambda item: item * 1000.0, irtt)
            #axis.plot(tstamp, irtt, label="irtt", linewidth=1.2)
            axis.plot(tstamp, irtt, "b-o", label="irtt", markersize=2)
            rtt_mins = rtt.get_rtt_min_in_rtt(rtts)
            tsstamp, rtt_min = zip(*rtt_mins)
            rtt_min = map(lambda rtt: rtt*1000, rtt_min)
            axis.plot(tsstamp, rtt_min, "m-o", label="rtt\_min", markersize=2)
            rtt_mins = rtt.get_rtt_min_in_rtt([(tstamp[i], irtt[i]/1000.0) \
                                              for i in range(0, len(irtt))])
            tsstamp, rtt_min = zip(*rtt_mins)
            rtt_min = map(lambda rtt: rtt*1000, rtt_min)
            axis.plot(tsstamp, rtt_min, "m-o", label="rtt\_min", markersize=2)
        else:
            irtt=[0, ]

    if "min_rtt_us" in reader.data[0]:
        minrtt = [item["min_rtt_us"]/1000.0 for item in reader.data]
        axis.plot(tstamp, minrtt, "m-", label="minrtt", linewidth=1.2)

    tstamp = [item["timestamp"] for item in reader.data]
    rto = [item["rto"] for item in reader.data]
    srtt = [item["srtt_us"]/1000.0 for item in reader.data]
    axis.plot(tstamp, rto, "r-", label="rto", linewidth=1.5)
    axis.plot(tstamp, srtt, "g-", label="srtt", linewidth=1.2)


    axis.set_ylabel("RTT (ms)")
    y_min, y_max = get_range_center_jitter(irtt)
    axis.set_ylim([y_min, y_max])
    axis.legend(loc='lower right', ncol=3)



def plot_speed(reader, axis):
    reader.calc_instant_speed(intvl_rtt=2)
    tstamp, speed = zip(*reader.instant_speed)
    speed = map(lambda item: item*8.0/(1e6), speed)
    axis.plot(tstamp, speed, linewidth=1.5)
    axis.set_ylabel("Speed (Mbps)")



def get_range_center_jitter(data):
    dlen = len(data)
    data_center = data[int(dlen*0.1):int(dlen*0.9)]
    return [get_percentile(data_center,0.02), get_percentile(data_center,0.98)]

def plot_speed_related(reader, axis):
    if reader.mss == 0:
        reader.get_mss()
    if len(reader.data) == 0:
        return
    if "ibw_bps" in reader.data[0]:
        tstamp = [item["timestamp"] for item in reader.data]
        speed= [item["ibw_bps"]/(1e6) for item in reader.data]
    else:
        reader.calc_instant_speed(intvl_rtt=2)
        if reader.instant_speed is None:
            logging.error("Instant speed is None.")
            return
        if len(reader.instant_speed) == 0:
            return
        tstamp, speed = zip(*reader.instant_speed)
        speed = map(lambda item: item*8.0/(1e6), speed)

    ymin, ymax = get_range_center_jitter(speed)
    axis.plot(tstamp, speed, "b-", label="speed", linewidth=1.5)

    if "maxbw_bps" in reader.data[0]:
        maxbw = [item["maxbw_bps"]/(1e6) for item in reader.data]
        axis.plot(tstamp, maxbw, "g-", label="maxbw", linewidth=1.5)

    # plot sk_pacing_rate
    if "sk_pacing_rate" in reader.data[0]:
        tstamp = [item["timestamp"] for item in reader.data]
        pacing_rate = \
            [item["sk_pacing_rate"]*8.0/(1e6) for item in reader.data]
        axis.plot(
            tstamp, pacing_rate, "r-",
            label="pacing\_rate", linewidth=1.5,
        )
        tymin, tymax = get_range_center_jitter(pacing_rate)
        ymin = min(ymin, tymin)
        ymax = max(ymax, tymax)

    axis.set_ylabel("Speed (Mbps)")
    axis.legend(loc='upper center', ncol=3)
    axis.set_ylim([ymin, ymax])


def plot_connection(reader):
    if reader.get_deliver_size() < 10 * 1024:
        return None
    plt.rc('font',**{'family':'sans-serif','sans-serif':['Helvetica'],
                 'serif':['Helvetica'],'size':9})
    ########plt.rc('text', usetex=True)
    plt.rc("ytick", labelsize=8)
    plt.rc("axes", labelsize=8)
    plt.rc("legend", fontsize=8)
    plt.rc('lines', linewidth=0.5)
    plt.rc('grid', color="#a0a0a0", linewidth=0.8)
    subplt_num = 6
    subpltidx = 0
    fig, subplts = plt.subplots(subplt_num, sharex=True)
    for ax in subplts:
        ax.grid(True)
        gridlines = ax.get_xgridlines() + ax.get_ygridlines()
        for line in gridlines:
            line.set_linestyle(":")
            line.set_dash_capstyle("round")
    plot_wnd_related(reader, subplts[subpltidx])
    subpltidx += 1
    plot_lost_related(reader, subplts[subpltidx])
    subpltidx += 1
    plot_speed_related(reader, subplts[subpltidx])
    subpltidx += 1
    plot_rtt_related(reader, subplts[subpltidx])
    subpltidx += 1
    plot_seqnum(reader, subplts[subpltidx])
    subpltidx += 1
    plot_acknum(reader, subplts[subpltidx])
    plt.xlabel("Time (s)")
    xmin, xmax = 0.0, 0.0
    for line in reader.data:
        if line["length"] > 0:
            xmin = line["timestamp"]
            break
    for line in reversed(reader.data):
        if line["length"] > 0:
            xmax = line["timestamp"]
            break
    plt.xlim(xmin, xmax)
    return fig


def plot_conn_and_save(reader, oname=None):
    if oname is None:
        oname = os.path.splitext(reader.ifname)[0] + ".png"
    if plot_connection(reader) is not None:
        plt.savefig(oname, dpi=200)
    plt.close("all")




def example_one_connection():
    args = cmd_parse()
    reader = tcplog.TcpLogReader(args.iname)
    reader.read_and_parse()
    if plot_connection(reader) is not None:
        plt.show()
        plt.savefig(args.oname, dpi=200)


def plot_dir(idir, odir):
    matplotlib.use('Agg')
    tcplog.check_dir(odir)
    log_fnames = os.listdir(idir)
    pbar_widgets=[
        "Plot: ",
        progressbar.Percentage(),
        progressbar.Bar(),
        progressbar.AdaptiveETA()
    ]
    pbar = progressbar.ProgressBar(
        max_value=len(log_fnames),
        widgets=pbar_widgets,
    )
    pbar.start()
    for i in range(0, len(log_fnames)):
        pbar.update(i)
        log_fname = log_fnames[i]
        reader = tcplog.TcpLogReader(os.path.join(idir, log_fname))
        reader.read_and_parse()
        ofname = os.path.splitext(log_fname)[0] + ".png"
        if plot_connection(reader) is not None:
            plt.savefig(os.path.join(odir, ofname), dpi=200)
        plt.close("all")


def example_whole_dir():
    args = cmd_parse_dir()
    plot_dir(args.dir, args.odir)




if __name__ == "__main__":
    example_one_connection()
    #example_whole_dir()
    #plot_speed_cdf()
    #plot_ack_intvl_cdf()
    #plot_speed_cdf_stall(0.200)
