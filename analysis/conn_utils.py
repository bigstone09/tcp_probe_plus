#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import logging
import argparse
import datetime
import shutil

import tcplog


def cmd_parse():
    parser = argparse.ArgumentParser(
        description="Extract connections from a mixed log file.",
    )
    parser.add_argument(
        "-i", "--iname",
        default="tcp-stat.log",
        help="The original log file containing mixed tcp log.",
    )
    parser.add_argument(
        "-c", "--cname",
        default="connections.dat",
        help="The output file containing connection meta data.",
    )
    parser.add_argument(
        "-o", "--oname", default="tcp-sep.log",
        help="The result file containing tcp log with connection separated."
    )
    parser.add_argument(
        "-d", "--odir", default="./",
        help="The directory to put result files"
    )
    return parser.parse_args()


def flow_size_breakdown(
    bound,
    sname="small",
    lname="large",
    odir="./",
    cname="connections.dat",
    iname="tcp-sep.log",
):
    """ Breakdown flows by flow size

    Args:
        bound: A integer indicating breakdown boundary in Bytes.
            Breakdown flows into two category:
                small (0, bound], large (bound, infty)
        sname: A string indicating the name of small flows
        lname: A string indicating the name of large flows
    """
    conn_sname = os.path.join(odir, "conn-%s.dat" % sname)
    conn_lname = os.path.join(odir, "conn-%s.dat" % lname)
    tlog_sname = os.path.join(odir, "tcp-%s.log" % sname)
    tlog_lname = os.path.join(odir, "tcp-%s.log" % lname)
    slnum, llnum = 0, 0
    with open(iname) as ifp:
        data_all = ifp.readlines()
    with open(cname) as cfp:
        conn_all = [tcplog.parse_line_connection(line) for line in cfp \
                        if line.lstrip()[0] != '#']
        conn_all.sort(key=lambda item:item["size"])
    with open(conn_sname, "w") as conn_sfp, open(conn_lname, "w") as conn_lfp,\
            open(tlog_sname, "w") as log_sfp, open(tlog_lname, "w") as log_lfp:
        for conn in conn_all:
            conn_dat = data_all[conn["from"]:conn["to"]]
            ofp = log_sfp if conn["size"] <= bound else log_lfp
            for line in conn_dat:
                ofp.write(line)
            if conn["size"] <= bound:
                ofp = conn_sfp
                conn["from"] = slnum
                slnum += len(conn_dat)
                conn["to"] = slnum
            else:
                ofp = conn_lfp
                conn["from"] = llnum
                llnum += len(conn_dat)
                conn["to"] = llnum
            ofp.write(tcplog.tostring_connection(conn) + "\n")

def convert_to_readable(iname, oname):
    with open(iname) as ifp, open(oname, "w") as ofp:
        for line in ifp:
            if line.lstrip()[0] == "#":
                continue
            readable_str = tcplog.tostring_connection(
                tcplog.parse_line_connection(line),
                human_readable=True,
            )
            ofp.write(readable_str + "\n")

def split_connections(
    iname="tcp-stat.log", oname="tcp-sep.log",
    cname="connections.dat", odir="./",
):
    reader = tcplog.TcpLogReader(iname)
    #reader.check_trace_dir()
    #reader.oname = oname
    #reader.cname = cname
    reader.split_connection(
        odir=odir,
        cname=cname,
        oname=oname,
        human_readable=False,
    )

def check_dir(dirname, archive_dir="archive"):
    """ Check whether directory exists. If so, move it the archive directory
    """
    cur_path = os.path.abspath("./")
    odir_path = os.path.abspath(dirname)
    if cur_path.startswith(odir_path):
        logging.warning(
            "'%s'('%s') is contains current path ('%s'). checking escaped." % (
                dirname, odir_path, cur_path,
            )
        )
    elif os.path.exists(dirname) and os.listdir(dirname):
        logging.error("'%s' exists!" % dirname)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        dst_file = "%s/%s_%s" % (archive_dir, dirname, timestamp)
        logging.info("Copy '%s' to '%s'" % (dirname, dst_file))
        if not os.path.exists(archive_dir):
            os.mkdir(archive_dir)
        shutil.move(dirname, dst_file)
        os.mkdir(dirname)
    elif not os.path.exists(dirname):
        os.mkdir(dirname)


def append_retrans_rate(ifname):
    """ Append retransmission rate into file name
    """
    reader = tcplog.TcpLogReader(ifname)
    retrans_rate = reader.get_retrans_rate()
    ofname = "%s_retrans_%.3f.log" % (ifname[:-4], retrans_rate * 100.0)
    shutil.move(ifname, ofname)


def append_retrans_rate_dir(dirname):
    """ Append retransmission rate to all file names in the directory
    """
    for ifname in os.listdir(dirname):
        append_retrans_rate(os.path.join(dirname, ifname))


def split_connections_sep_file(
    tname="tcp-sep.log",
    cname="connections.dat",
    odir="tcp-log-separate",
):
    check_dir(odir)
    lnum = 0
    reader = tcplog.TcpLogReader("/dev/null")
    with open(tname) as tfp, open(cname) as cfp:
        for line in cfp:
            if line.lstrip()[0] == "#":
                continue
            conn = tcplog.parse_line_connection(line)
            if lnum > conn["from"]:
                logging.error(
                    "Connection data invalid:"
                    + "line number is from %d " % conn["from"]
                    + "but in previous connection, line number is to %d " % lnum
                )
            while lnum < conn["from"]:
                tfp.readline()
                lnum += 1
            conn_data, reader.data = [], []
            while lnum < conn["to"]:
                line = tfp.readline()
                conn_data.append(line)
                reader.data.append(tcplog.parse_line(line))
                lnum += 1
            retrans_rate = reader.get_retrans_rate()
            ofname = "%s_%d_%s_%d_dur_%.3f-%.3f_retrans_%.3f.log" % (
                tcplog.ipaddr_ntos(conn["srcaddr"]),
                conn["srcport"],
                tcplog.ipaddr_ntos(conn["dstaddr"]),
                conn["dstport"],
                conn["stime"],
                conn["etime"],
                retrans_rate * 100,
            )
            ofname = os.path.join(odir, ofname)
            with open(ofname, "w") as ofp:
                for line in conn_data:
                    ofp.write(line)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-5s %(levelname)-6s %(message)s "
        "(in %(filename)s function '%(funcName)s' line %(lineno)s)",
        datefmt="%m-%d %H:%M",
    )
    #main()
    split_connections_sep_file()
    #flow_size_b
