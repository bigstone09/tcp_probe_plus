#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import shutil
import argparse
import progressbar
import tcplog

def cmd_parse():
    parser = argparse.ArgumentParser(
        description=("Plot connections from a log file"
                     "(containing only one connection)."),
    )
    parser.add_argument(
        "dir", help="The directory containing separated tcp logs to be analyzed.",
    )
    parser.add_argument(
        "-o", "--odir", default="tcp-log-classified", help="The output directory name."
    )
    return parser.parse_args()


DROP_LOW = 0
DROP_NORMAL = 1
DROP_HIGH = 2
def classify_dropping_rate(reader, thresh1 = 0.1 * 0.01, thresh2 = 5 * 0.01):
    """ Classify flows according to dropping rate
    Args:
        reader: instance of TcpLogReader
        thresh1:
            A floating number. The flow is considerred as DROP_LOW if the
            dropping rate lower than thresh1
        thresh2:
            A floating number. The flow is considerred as DROP_HIGH if the
            dropping rate is larger than thesh2

    Returns:
        DROP_LOW or DROP_NORMAL or DROP_HIGH
    """
    retrans_rate = reader.get_retrans_rate()
    if retrans_rate < thresh1:
        return DROP_LOW
    elif retrans_rate < thresh2:
        return DROP_NORMAL
    else:
        return DROP_HIGH


def calc_rttinc_dropping(reader):
    """ Calculate the increment of rtt when packet dropping occurs
    """
    w_inc = 0.125
    avg_inc = 0
    increment = 0
    prev_rtt = 0
    i, rtt_idx = 0, 1
    all_incrs = []
    cur_sndnxt = 0
    #irtts = reader.calc_instant_rtt_from_ts()
    #irtts = [(item["timestamp"], item["srtt_us"] / 1000.0 / 1000.0) for item in reader.data]
    rminrtts = reader.calc_rttmin_in_rtt()
    while i < len(reader.data) and rtt_idx < len(rminrtts):
        # find the retransmit timestamp
        while i < len(reader.data) and not reader.is_retrans(reader.data[i]):
            i += 1
        if i < len(reader.data):
            retrans_time = reader.data[i]["timestamp"]
            cur_sndnxt = reader.data[i]["snd_nxt"]
            i += 1
        else:
            break
        # calculate increment
        while rtt_idx < len(rminrtts) and rminrtts[rtt_idx][0] <= retrans_time:
            rtt_inc = rminrtts[rtt_idx][1] - rminrtts[rtt_idx-1][1]
            if ((rtt_inc >= 0 and increment >= 0) or
                (rtt_inc <=0 and increment <= 0)):
                increment += rtt_inc
            else:
                increment = 0
            # avg_inc = w_inc * rtt_inc + (1 - w_inc) * avg_inc
            # if ((increment >= 0 and avg_inc >= 0) or
            #     (increment <= 0 and avg_inc <= 0)):
            #     # the rtt is increasing or decreasing
            #     increment += rtt_inc
            # else:
            #     increment = 0
            rtt_idx += 1
        all_incrs.append((retrans_time, increment))
        # ignore following retransmissions
        while i < len(reader.data):
            if (reader.data[i]["type"] == reader.TYPE_RECV
                and reader.data[i]["ack_num"] >= cur_sndnxt):
                # sucessfully retransmit all packets
                break;
            i += 1

    return all_incrs


def calc_rtt_inc(rtts, gran=1, min_intv=5):
    """ Calculate the increment of irtt in each rtts

    Args:
        rtts: a list of tuples with format:
            <timestamp in s, rtt in s>

        gran: an integer (in RTTs) indicating the granularity
        min_intv: an integer indicating the minimum # of irtts in a interval

    Returns:
        A list of tuples. Format of each tuple:
            (timestamp, increment (may be negative) in s)
    """
    st_time, st_rtt = rtts[0]
    prev_rtt, prev_ts = st_rtt, st_time
    incrs = []
    irtt_num = 0
    for tstamp, rtt in rtts:
        if irtt_num >= min_intv and tstamp > st_time + st_rtt * gran:
            incrs.append(((st_time+prev_ts)/2.0, prev_rtt-st_rtt))
            st_time, st_rtt = tstamp, rtt
            irtt_num = 0
        prev_ts, prev_rtt = tstamp, rtt
        irtt_num += 1
    return incrs


def calc_jitter_amps(rtts, gran=1, min_intv=5):
    """ Calculate amplitude of jitter of RTT

    Args:
        rtts: a list of tuples with format:
            <timestamp in s, rtt in s>

        gran: an integer (in RTTs) indicating the granularity
        min_intv: an integer indicating the minimum # of irtts in a interval

    Returns:
        A list of tuples. Format of each tuple:
            (timestamp, amplitude of jitter in s)
    """
    max_inc, max_dec = 0, 0
    cur_inc, cur_dec = 0, 0
    st_time, st_rtt = rtts[0]
    prev_rtt, prev_ts = st_rtt, st_time
    amps = []
    irtt_num = 0
    for tstamp, rtt in rtts:
        if irtt_num >= min_intv and tstamp > st_time + st_rtt * gran:
            amp = min(max_inc, max_dec)
            amps.append(((st_time + prev_ts) / 2.0, amp))
            max_inc, max_dec = 0, 0
            cur_inc, cur_dec = 0, 0
            st_time, st_rtt = tstamp, rtt
            irtt_num = 0
        else:
            if rtt > prev_rtt:
                cur_inc += rtt - prev_rtt
                max_dec = max(max_dec, cur_dec)
                cur_dec = 0
            elif rtt < prev_rtt:
                cur_dec += prev_rtt - rtt
                max_inc = max(max_inc, cur_inc)
                cur_inc = 0
        irtt_num += 1
        prev_ts, prev_rtt = tstamp, rtt
    return amps


def calc_jitter_values(rtts, gran=1, min_intv=5):
    """ Calculate amplitude of jitter of RTT

    Args:
        rtts: a list of tuples with format:
            <timestamp in s, rtt in s>

        gran: an integer (in RTTs) indicating the granularity
        min_intv: an integer indicating the minimum # of irtts in a interval

    Returns:
        A dict. Just read the code.
    """
    amps = zip(*calc_jitter_amps(rtts, gran=gran, min_intv=min_intv))[1]
    incrs = zip(*calc_rtt_inc(rtts, gran=gran, min_intv=min_intv))[1]
    def calc_ratio(amp, incr):
        return 1.0 * amp / abs(incr) if incr != 0 else amp
    amp_incr_ratios = map(calc_ratio, amps, incrs)
    irtts = zip(*rtts)[1]
    avg_rtt = 1.0 * sum(irtts) / len(irtts)
    min_rtt = min(irtts)
    avg_amp = 1.0 * sum(amps) / len(amps)
    return {
        "avg_amp": avg_amp,
        "avg_amp_incr_ratio": 1.0 * sum(amp_incr_ratios) / len(amp_incr_ratios),
        "jitter_cv": avg_amp / (avg_rtt - min_rtt),
    }


JITTER_HIGH=0
JITTER_LOW=1
def classify_jitter(reader, amp_thresh=5*0.001, cv_thresh=0.3):
    """ Classify flows according to whether irtt jitters

    Args:
        reader: instance of TcpLogReader
        amp_thresh:
            A floating number. The irtt may have high jitter
            if the amplitude of jitter is higher than thresh.
        cv_thresh:
            A floating number. The irtt may have high jitter
            if the cv of jitter is higher than cv_thresh.
    Returns:
        JITTER_HIGH or JITTER_LOW
    """
    irtts = reader.calc_instant_rtt_from_ts()
    if len(irtts) == 0:
        return JITTER_LOW
    jv = calc_jitter_values(irtts)
    if jv["avg_amp"] >= amp_thresh and jv["jitter_cv"] >= cv_thresh:
        return JITTER_HIGH
    else:
        return JITTER_LOW


def test():
    log_dir = "/Volumes/NT/tcplog/tcplog1/tcp-log-separate"
    fig_dir = "/Volumes/NT/tcplog/tcplog1/figs"
    fig_odir = "tcp-log-classified/jitter-test"
    tcplog.check_dir(fig_odir)
    total_len = len(os.listdir(log_dir))
    proce_num = 0
    pbar_widgets=[
        "Classify: ",
        progressbar.Percentage(),
        progressbar.Bar(),
        progressbar.AdaptiveETA()
    ]
    pbar = progressbar.ProgressBar(
        max_value=total_len,
        widgets=pbar_widgets,
    )
    for log_fname in os.listdir(log_dir):
        proce_num += 1
        pbar.update(proce_num)
        fname_root = os.path.splitext(log_fname)[0]
        iname = os.path.join(fig_dir, fname_root + ".png")
        if not os.path.exists(iname):
            continue
        log_fname = os.path.join(log_dir, log_fname)
        reader = tcplog.TcpLogReader(log_fname)
        irtts = reader.calc_instant_rtt_from_ts()
        if len(irtts) == 0:
            continue
        jv = calc_jitter_values(irtts)
        oname = "jitter-%d-%dms-%d-%s.png" % (
            int(jv["jitter_cv"]*1000),
            int(jv["avg_amp"]*1000),
            int(jv["avg_amp_incr_ratio"]*1000),
            fname_root,
        )
        #oname = "jitter-%dms-%d-%s.png" % (
        #    int(jv["avg_amp"]*1000),
        #    int(jv["avg_amp_incr_ratio"]*1000),
        #    fname_root,
        #)
        oname = os.path.join(fig_odir, oname)
        shutil.copyfile(iname, oname)

def test_classify():
    log_dir = "/Volumes/NT/tcplog/tcplog1/tcp-log-separate"
    fig_dir = "/Volumes/NT/tcplog/tcplog1/figs"
    fig_odir_high = "tcp-log-classified/jitter-high"
    fig_odir_low = "tcp-log-classified/jitter-low"
    tcplog.check_dir(fig_odir_high)
    tcplog.check_dir(fig_odir_low)
    total_len = len(os.listdir(log_dir))
    proce_num = 0
    pbar_widgets=[
        "Classify: ",
        progressbar.Percentage(),
        progressbar.Bar(),
        progressbar.AdaptiveETA()
    ]
    pbar = progressbar.ProgressBar(
        max_value=total_len,
        widgets=pbar_widgets,
    )
    for log_fname in os.listdir(log_dir):
        proce_num += 1
        pbar.update(proce_num)
        fname_root = os.path.splitext(log_fname)[0]
        iname = os.path.join(fig_dir, fname_root + ".png")
        if not os.path.exists(iname):
            continue
        log_fname = os.path.join(log_dir, log_fname)
        reader = tcplog.TcpLogReader(log_fname)
        irtts = reader.calc_instant_rtt_from_ts()
        jv = calc_jitter_values(irtts)
        oname = "jitter-%d-%dms-%d-%s.png" % (
            int(jv["jitter_cv"]*1000),
            int(jv["avg_amp"]*1000),
            int(jv["avg_amp_incr_ratio"]*1000),
            fname_root,
        )
        if classify_jitter(reader) == JITTER_HIGH:
            oname = os.path.join(fig_odir_high, oname)
        else:
            oname = os.path.join(fig_odir_low, oname)
        shutil.copyfile(iname, oname)

if __name__ == "__main__":
    test_classify()
