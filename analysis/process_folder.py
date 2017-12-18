#!/usr/bin/env python
# -*- coding: utf-8 -*-
import matplotlib
matplotlib.use('Agg')
import os
import conn_utils
import argparse
import logging
import pdb
import plots


def main():
    parser = argparse.ArgumentParser(
        description="Break down flows according to flow size",
    )
    parser.add_argument(
        "dir", help="The directory to be processed."
    )
    args = parser.parse_args()
    # split connections
    logging.info("split connections")
    conn_utils.split_connections(
        iname=os.path.join(args.dir, "tcp-stat.log"),
        oname=os.path.join("tcp-sep.log"),
        cname=os.path.join("connections.dat"),
        odir=args.dir,
    )
    logging.info("Split connections into separate file")
    conn_utils.split_connections_sep_file(
        tname=os.path.join(args.dir, "tcp-sep.log"),
        cname=os.path.join(args.dir, "connections.dat"),
        odir=os.path.join(args.dir, "tcp-log-separate")
    )
    logging.info("breakdown flows")
    #pdb.set_trace()
    #conn_utils.flow_size_breakdown(
    #    bound=10*1024,
    #    sname="tiny",
    #    iname=os.path.join(args.dir, "tcp-sep.log"),
    #    cname=os.path.join(args.dir, "connections.dat"),
    #    odir=args.dir,
    #)
    ##pdb.set_trace()
    #conn_utils.flow_size_breakdown(
    #    bound=100*1024,
    #    sname="small",
    #    iname=os.path.join(args.dir, "tcp-large.log"),
    #    cname=os.path.join(args.dir, "conn-large.dat"),
    #    odir=args.dir,
    #)
    ##pdb.set_trace()
    #conn_utils.flow_size_breakdown(
    #    bound=1024*1024,
    #    iname=os.path.join(args.dir, "tcp-large.log"),
    #    cname=os.path.join(args.dir, "conn-large.dat"),
    #    sname="medium",
    #    odir=args.dir,
    #)
    #pdb.set_trace()
    logging.info("convert connection meta data to readable version")
    conn_utils.convert_to_readable(
        os.path.join(args.dir, "connections.dat"),
        os.path.join(args.dir, "conn-readable.dat"),
    )
    #conn_utils.convert_to_readable(
    #    os.path.join(args.dir, "conn-tiny.dat"),
    #    os.path.join(args.dir, "conn-tiny-readable.dat"),
    #)
    #conn_utils.convert_to_readable(
    #    os.path.join(args.dir, "conn-small.dat"),
    #    os.path.join(args.dir, "conn-small-readable.dat"),
    #)
    #conn_utils.convert_to_readable(
    #    os.path.join(args.dir, "conn-medium.dat"),
    #    os.path.join(args.dir, "conn-medium-readable.dat"),
    #)
    #conn_utils.convert_to_readable(
    #    os.path.join(args.dir, "conn-large.dat"),
    #    os.path.join(args.dir, "conn-large-readable.dat"),
    #)
    #logging.info("plot data")
    #plots.plot_dir(
    #    os.path.join(args.dir, "tcp-log-separate"),
    #    os.path.join(args.dir, "figs"),
    #)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-5s %(levelname)-6s %(message)s "
        "(in %(filename)s function '%(funcName)s' line %(lineno)s)",
        datefmt="%m-%d %H:%M",
    )
    main()
