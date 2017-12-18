#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import logging
import argparse


sys.path.insert(0, "..")
from analysis import tcplog


def cmd_parse():
    parser = argparse.ArgumentParser(
        description=("Test rtt increment"),
    )
    parser.add_argument(
        "iname", default="output/tcp-log-separate", help="dirname",
    )
    return parser.parse_args()


def convert_connection(iname, oname):
    reader = tcplog.TcpLogReader(iname)
    reader.read_and_parse()
    reader.find_lost_packets()
    reader.store_to_excel(
        os.path.join(oname),
        col_names= [],
    )


def main():
    args = cmd_parse()
    iname = os.path.abspath(args.iname)
    if os.path.isfile(iname):
        convert_connection(args.iname, "connection.xlsx")
    elif os.path.isdir(iname):
        odir = os.path.dirname(iname)
        odir = os.path.join(odir, "tcplog-excel")
        tcplog.check_dir(odir)
        for ifname in os.listdir(iname):
            oname = os.path.splitext(ifname)[0] + ".xlsx"
            convert_connection(
                os.path.join(iname, ifname),
                os.path.join(odir, oname),
            )
    else:
        logging.error(
            "ERROR: '%s' is neither a regular file nor a directory" % args.iname,
        )



if __name__ == "__main__":
    main()
