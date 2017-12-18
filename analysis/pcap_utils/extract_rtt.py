#!/usr/bin/env python
# -*- coding: utf-8 -*-
import rtt
import argparse
import pdb


def parse_args():
    parser = argparse.ArgumentParser(
        description="Get rtt from pcap file",
    )
    parser.add_argument(
        "pcap_file", help="The pcap file name.",
    )
    parser.add_argument(
        "-o", "--oname", default="rtt.dat",
        help="The output file containing rtt.",
    )
    parser.add_argument(
        "-d", "--odir", default="./",
        help="The directory to put result files"
    )
    parser.add_argument(
        "-p", "--plot", action="store_true",
        help="Whether plot result"
    )
    return parser.parse_args()


def check_output_dir(dirname):
    """ Check whether output directory exists. If so, move it the archive directory
    """
    cur_path = os.path.abspath("./")
    odir_path = os.path.abspath(dirname)
    if cur_path.startswith(odir_path):
        print "'%s'('%s') is contains current path ('%s'). checking escaped." % (
            self.odir, odir_path, cur_path,
        )
    if not os.path.exists(odir_path):
        os.mkdir(odir_path)


def main():
    args = parse_args()
    with open(args.pcap_file) as ifp:
        rtt_cal = rtt.PcapRTTCalculator(ifp)
        rtt_cal.calc_rtt()
        rtt.dump_rtt(args.oname, rtt_cal.get_rtt())
    if args.plot:
        rtt.plot_rtt(rtt_cal.get_rtt())


if __name__ == "__main__":
    main()
