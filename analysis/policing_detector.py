import os
import sys
import pdb
import argparse
import progressbar
import numpy as np
import tcplog

# Minimum number of samples (data points) for each loss/pass category
# to enable detection of policing with confidence
MIN_NUM_SAMPLES = 15

# Minimum number of RTT slices seeing loss to enable detection
# of policing with confidence
MIN_NUM_SLICES_WITH_LOSS = 3

# Maximum relative sequence number acceptable for the first loss
LATE_LOSS_THRESHOLD = 2E6

# Number of RTTs used to compute the number of tokens allowed in the bucket when observing
# packet loss to infer policing. The allowed fill level is computed by multiplying the
# estimated policing rate with a multiple of the median RTT. The
# multiplier is specified here.
ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER = 2.00
ZERO_THRESHOLD_PASS_RTT_MULTIPLIER = 0.75

# Fraction of cases allowed to have a number of tokens available on loss
# larger than the computed zero threshold
ZERO_THRESHOLD_LOSS_OUT_OF_RANGE = 0.10
ZERO_THRESHOLD_PASS_OUT_OF_RANGE = 0.03

# Percentile of the RTT samples used to compute the inflation threshold
INFLATED_RTT_PERCENTILE = 10

# Fraction of the Xth percentile RTT beyond which an RTT sample is
# considered inflated
INFLATED_RTT_THRESHOLD = 1.3

# Fraction of cases allowed to have inflated RTTs without ruling out
# a policer presence
INFLATED_RTT_TOLERANCE = 0.2

# Detection return codes
# All conditions for policing detection were met
RESULT_OK = 0

# Trace does not have enough loss (either absolute number of loss samples, or
# RTT slices with loss)
RESULT_INSUFFICIENT_LOSS = 1

# First loss appeared too late in the connection
RESULT_LATE_LOSS = 2

# Estimated token bucket fill would be negative at the beginning of the
# connection
RESULT_NEGATIVE_FILL = 3

# Estimated token bucket fill was higher when packets are lost compared to when
# packets passed through
RESULT_HIGHER_FILL_ON_LOSS = 4

# Estimated token bucket fill was out of range too often.
# For lost packets, the token bucket is estimated to be empty
# For passing packets, the token bucket is estimated to be filled
RESULT_LOSS_FILL_OUT_OF_RANGE = 5
RESULT_PASS_FILL_OUT_OF_RANGE = 6

# A significant fraction of losses is preceded by inflated RTTs (indicating other
# potential causes for loss, e.g. congestion)
RESULT_INFLATED_RTT = 7


class PolicingParams():

    def __init__(self, result_code, policing_rate_bps=0, burst_size=0):
        self.result_code = result_code
        self.policing_rate_bps = policing_rate_bps
        self.burst_size = burst_size

    def __repr__(self):
        if self.result_code == RESULT_OK:
            return "[code %d, %d bps, %d bytes burst]" % (
                self.result_code, self.policing_rate_bps, self.burst_size)
        else:
            return "[code %d, null, null]" % (self.result_code)



def get_policing_params_for_records(records, cutoff=0):
    """Computes parameters of the policer affecting the flow data
    coming from these records. Returns None if no traffic policing
    is detected

    :type cutoff: int
    :param cutoff: number of lost packets to ignore at the beginning and end when determining the
    boundaries for policing rate computation and detection

    :returns: policing parameters (including return code, policing rate, and burst size)
    """
    # Methodology:
    # 1. Detect first and last loss
    first_packet = first_loss = last_loss = first_loss_no_skip = None
    skipped = 0
    for idx in xrange(0, len(records)):
        if not is_sent_data_packet(records[idx]):
            continue
        first_packet = idx
        if tcplog.packet_is_lost(records[idx]):
            if first_loss_no_skip is None:
                first_loss_no_skip = idx
            if cutoff == skipped:
                first_loss = idx
                break
            else:
                skipped += 1
    if first_loss is None:
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)

    skipped = 0
    for idx in reversed(xrange(0, len(records))):
        if not is_sent_data_packet(records[idx]):
            continue
        if idx == first_loss:
            break
        if tcplog.packet_is_lost(records[idx]):
            if cutoff == skipped:
                last_loss = idx
                break
            else:
                skipped += 1
    if last_loss is None:
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)
    if records[first_loss]["seq_num"] - records[first_packet]["seq_num"] > LATE_LOSS_THRESHOLD:
        return PolicingParams(RESULT_LATE_LOSS)

    # 2. Compute goodput between first and last loss (policing rate)
    policing_rate_bps = goodput_for_range(records, first_loss, last_loss)

    # 2a. Compute the y-intercept for the policing rate slope, i.e. the initial number of tokens
    #    in the bucket. This value should not be negative, indicating that the connection starts
    #    with either an empty or (partially) filled bucket.
    all_rtt_us = [item["irtt_us"] for item in records]
    median_rtt_us = np.median(all_rtt_us)
    loss_zero_threshold = ZERO_THRESHOLD_LOSS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6
    pass_zero_threshold = ZERO_THRESHOLD_PASS_RTT_MULTIPLIER * \
        median_rtt_us * policing_rate_bps / 8E6
    y_intercept = records[first_loss]["seq_num"] - (policing_rate_bps * \
        (records[first_loss]["timestamp"] - records[first_packet]["timestamp"]) / 8)
    if y_intercept < -pass_zero_threshold:
        return PolicingParams(RESULT_NEGATIVE_FILL)

    # 3. Iterate through packets starting with the first loss and simulate a policer
    # starting with an empty token bucket. Tokens are inserted at the policing
    # rate
    tokens_available = 0
    tokens_used = 0
    tokens_on_loss = []
    tokens_on_pass = []

    seen_first = seen_first_no_skip = False
    burst_size = 0
    inflated_rtt_count = 0
    all_rtt_count = 0
    rtts = []

    slices_with_loss = 1
    slice_end = records[first_loss]["timestamp"] + 1.0 * median_rtt_us / 1e6

    ignore_index = -1
    tokens_on_loss_out_of_range = 0

    for idx in xrange(0, len(records)):
        if not is_sent_data_packet(records[idx]):
            continue
        if idx == first_loss:
            seen_first = True
        if idx == first_loss_no_skip:
            seen_first_no_skip = True
        if not seen_first_no_skip:
            burst_size += records[idx]["length"]
        if not seen_first:
            continue

        tokens_produced = policing_rate_bps * \
            (records[idx]["timestamp"] - records[first_loss]["timestamp"]) / 8
        tokens_available = tokens_produced - tokens_used

        if tcplog.packet_is_lost(records[idx]):
            tokens_on_loss.append(tokens_available)
            if (records[idx]["irtt_us"] >= np.percentile(all_rtt_us, 50)
                and records[idx]["irtt_us"] > INFLATED_RTT_THRESHOLD *
                        np.percentile(all_rtt_us, INFLATED_RTT_PERCENTILE)
                and records[idx]["irtt_us"] >= 20 * 1000):
                # rtt inflate
                inflated_rtt_count += 1
            all_rtt_count += 1
            if records[idx]["timestamp"] > slice_end:
                slice_end = records[idx]["timestamp"] + median_rtt_us / 1e6
                slices_with_loss += 1
        else:
            tokens_on_pass.append(tokens_available)
            tokens_used += records[idx]["length"]

    if slices_with_loss < MIN_NUM_SLICES_WITH_LOSS:
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)

    if (len(tokens_on_loss) < MIN_NUM_SAMPLES or
        len(tokens_on_pass) < MIN_NUM_SAMPLES):
        return PolicingParams(RESULT_INSUFFICIENT_LOSS)

    # 4. Match observations to expected policing behavior
    #    (loss iff exceeding policing rate)
    # a. There are more tokens available when packets pass through compared to
    # loss
    if np.mean(tokens_on_loss) >= np.mean(tokens_on_pass) or \
       np.median(tokens_on_loss) >= np.median(tokens_on_pass):
        return PolicingParams(RESULT_HIGHER_FILL_ON_LOSS)

    # b. Token bucket is (roughly) empty when experiencing loss, i.e.
    #    packets are dropped due to a lack of tokens.
    #    To account for possible imprecisions regarding the timestamps when the token bucket
    # was empty, we subtract the median fill level on loss from all token
    # count samples.
    median_tokens_on_loss = np.median(tokens_on_loss)
    out_of_range = 0
    for tokens in tokens_on_loss:
        if abs(tokens - median_tokens_on_loss) > loss_zero_threshold:
            out_of_range += 1
    if len(tokens_on_loss) * ZERO_THRESHOLD_LOSS_OUT_OF_RANGE < out_of_range:
        return PolicingParams(RESULT_LOSS_FILL_OUT_OF_RANGE)

    # c. Token bucket is NOT empty when packets go through, i.e.
    #    the number of estimated tokens in the bucket should not be overly negative
    #    To account for possible imprecisions regarding the timestamps when the token bucket
    # was empty, we subtract the median fill level on loss from all token
    # count samples.
    out_of_range = 0
    for tokens in tokens_on_pass:
        if tokens - median_tokens_on_loss < -pass_zero_threshold:
            out_of_range += 1
    if len(tokens_on_pass) * ZERO_THRESHOLD_PASS_OUT_OF_RANGE < out_of_range:
        return PolicingParams(RESULT_PASS_FILL_OUT_OF_RANGE)

    # d. RTT did not inflate before loss events
    rtt_threshold = INFLATED_RTT_TOLERANCE * all_rtt_count
    # print "threshold: %d, count: %d" % (rtt_threshold, inflated_rtt_count)
    if inflated_rtt_count > rtt_threshold:
        return PolicingParams(RESULT_INFLATED_RTT)

    return PolicingParams(RESULT_OK, policing_rate_bps, burst_size)


def goodput_for_range(records, first_idx, last_idx):
    """Computes the goodput (in bps) achieved between observing two specific packets"""
    time = records[last_idx]["timestamp"] - records[first_idx]["timestamp"]
    if first_idx == last_idx or int(time*1000) == 0:
        return 0

    byte_count = 0
    for idx in xrange(first_idx, last_idx):
        # Packet contributes to goodput if it was not retransmitted
        if not is_sent_data_packet(records[idx]):
            continue
        if not tcplog.packet_is_lost(records[idx]):
            byte_count += records[idx]["length"]

    return byte_count * 8.0 / time


def is_sent_data_packet(record):
        return (record["type"] == tcplog.TYPE_SEND and
                record["length"] > 200)



def cmd_parse():
    parser = argparse.ArgumentParser(
        description=("Process a connection from a log file"
                     "(containing only one connection)."),
    )
    parser.add_argument(
        "iname", help="The original log file containing tcp log.",
    )
    parser.add_argument(
        "-o", "--oname", default="result.png", help="The output figure name."
    )
    return parser.parse_args()


def cmd_parse_dir():
    parser = argparse.ArgumentParser(
        description=("Process connections from log files in a directory"
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


def process_connection(ifname):
    reader = tcplog.TcpLogReader(ifname)
    reader.read_and_parse()
    reader.find_lost_packets()
    data_pkts = [item for item in reader.data if is_sent_data_packet(item)]
    data_num = len(data_pkts)
    lost_num = len([item for item in data_pkts \
                    if tcplog.packet_is_lost(item)])
    results = {
        "data_num": data_num,
        "lost_num": lost_num,
        "policing": [],
    }
    for cutoff in [0, 2]:
        policing_params = get_policing_params_for_records(data_pkts, cutoff=cutoff)
        results["policing"].append({
            "cutoff": cutoff,
            "is_policed": policing_params.result_code == RESULT_OK,
            "policing_rate": policing_params.policing_rate_bps,
            "burst_size": policing_params.burst_size,
        })
    return results


def result2string(res):
    res_str = "%d %d" % (res["data_num"], res["lost_num"])
    is_policed = False
    for policing in res["policing"]:
        if policing["is_policed"]:
            is_policed = True
        res_str += " [%d %s %dKbps %dKB]" % (
            policing["cutoff"],
            str(policing["is_policed"]),
            policing["policing_rate"]/1024,
            policing["burst_size"]/1024,
        )
    res_str = str(is_policed) + " " + res_str
    return res_str


def process_connection_cmd():
    args = cmd_parse()
    print result2string(process_connection(args.iname))


def process_dir():
    args = cmd_parse_dir()
    log_fnames = os.listdir(args.dir)
    pbar_widgets=[
        "Process Dir: ",
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
        fname = log_fnames[i]
        log_fname = os.path.join(args.dir, fname)
        print fname + " " + result2string(process_connection(log_fname))


if __name__ == "__main__":
    #process_dir()
    process_connection_cmd()
