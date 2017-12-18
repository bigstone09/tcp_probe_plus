#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import shutil
import datetime


archive_dir = "archive"
ifname = "/proc/net/tcpprobe_data"
stat_file = "/proc/net/stat/tcpprobe_plus"


def check_trace_dir(odir):
    """ Check whether trace directory exists. If so, move it the archive directory
    """
    cur_path = os.path.abspath("./")
    odir_path = os.path.abspath(odir)
    if cur_path.startswith(odir_path):
        sys.stderr.write(
            "'%s'('%s') is contains current path ('%s'). checking escaped.\n" % (
                odir, odir_path, cur_path,
            )
        )
    elif os.path.exists(odir) and os.listdir(odir):
        sys.stderr.write("'%s' exists!\n" % odir)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        dst_file = "%s/%s_%s" % (archive_dir, odir, timestamp)
        print ("Copy '%s' to '%s'" % (odir, dst_file))
        if not os.path.exists(archive_dir):
            os.mkdir(archive_dir)
        shutil.move(odir, dst_file)
        os.mkdir(odir)
    elif not os.path.exists(odir):
        os.mkdir(odir)


def read_and_store(
    fname,
    odir="output",
    log_fname="tcp-stat.log",
    file_size_max=(1<<30),
    flush_max=30,
):
    """ just read data and store it into file
    Args:
        fname: file name to read
        odir: directory name to store data into
        log_fname: file name to store data into
        file_size_max: A number contaning the maximum bytes of a log file. When
            the log file size is larger than file_size_max, a new file will
            be created.
        flush_max: A number representing the maximum number of flush lines.
            when # of lines in buffer are larger than flush_max, all lines
            will be flushed into disk.
    """
    check_trace_dir(odir)
    file_num = 1
    with open(fname) as ifp:
        open_time = datetime.datetime.now()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            print "Press <Ctrl-C> to stop reading!"
            while True:
                ofname = log_fname + (".%d" % file_num)
                ofname = os.path.join(odir, ofname)
                ofp = open(ofname, "w")
                ofp.write("# %s\n" % timestamp)
                flush_num, file_size = 0, 0
                while True:
                    line = ifp.readline()
                    if not line:
                        break
                    ofp.write(line)
                    file_size += len(line)
                    flush_num += 1
                    if flush_num > flush_max:
                        ofp.flush()
                        flush_num = 0
                    if file_size > file_size_max:
                        break
                ofp.close()
                if not line:
                    break
                file_num += 1
        except KeyboardInterrupt:
            print "Receive Interrupt Signal."
        finally:
            shutil.move(ofname, os.path.join(odir, log_fname))
            if not ofp.closed:
                ofp.close()
            oname = os.path.join(
                odir,
                os.path.basename(stat_file) + ".stat",
            )
            shutil.copyfile(stat_file, oname)
            with open(oname) as fp:
                for line in fp:
                    if line.lower().startswith('total'):
                        line = line.split()
                        line = ' '.join(line)
                        print line
                        break
            # with open
        # try
    # with open


def main():
    read_and_store(ifname)


if __name__ == "__main__":
    main()
