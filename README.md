# tcp_probe_plus Linux Kernel Module

## TODO

- [x] Detect Timeout
- [x] Get `User Agent` for received packets
- [x] Detect Retransmissions
- [x] Probe packets on connection setup
- [x] Calculate RTT using packet's timestamp
- [x] Flags in the tcp header
- [x] Verify of send buffer and receive buffer
- [x] Use relative sequence number and ack number
- [x] Use relative timestamp
- [x] Test rto

## License
Please review the:
- "LICENSE" file that is part of this distribution and in the same directory as this file
- The header in the "tcp_probe_plus.c" file

## Description
- Based on the "tcp_probe.c" Linux Kernel Module (LKM) by Stephen Hemminger
- More statistics added by Lyatiss, Inc.
	- rttvar: The Round-Trip Time Variation as per RFC 2988
	- rto: The current retransmit timeout in milliseconds
	- lost: The number of packets currently considered to be lost
	- retrans: The number of packet retransmitted since the connection was established
	- inflight: The number of packets sent but not acknowledged yet
	- frto_counter: A counter to track the Forward RTO-Recovery algorithm as described in RFC 4138
	- rqueue: The number of bytes currently waiting to be read in the socket buffer a.ka. recvq
	- wqueue: The number of bytes currently waiting to be sent in the socket buffer a.k.a. sendq
	- socket_idf: The first sequence number seen for the connection to identify it. It can be used to detect that the connection has been reset and avoid reporting incorrect throughput. 

- More sampling options added by Lyatiss, Inc.
	- There are two options
		- Sample an ACK every sampling period (controlled by the Probe time setting as described below), or
		- Sample an ACK only if the congestion window has changed every sampling period
	- Sampling is done by maintaining a connections table (see the Connection hash table section below for details)
- Add connection termination detection (reported as a magic value in the length field)
	- The support for this functionnality is only available for kernel versions >= 2.6.22. Before that, the instrumented method (tcp_done) was defined as an inline method that can't be instrumented through jprobe. 

## Contents
This repository contains:
- `dkms.conf` Config file for dkms
- `Makefile` Makefile 
- `tcp_probe_plus.c` Modified tcp_probe that does the sampling and collects more statistics (NOTE: Works on Linux kernel versions 2.6 and higher)
- `LICENSE` GPLv2 license

## How to use
### Note
I recommend to close segmentation offload

```shell
$ sudo ethtool -K eth0 tso off gso off gro off lro off
```


### Clone this repository

``` shell
$ git clone --recursive <git path>uan
```

### Install Requirements
Including python requirements in `analysis/requirements.txt` and `python-tk` package

``` shell
$ sudo pip install -r analysis/requirements.txt
# In Ubuntu
$ sudo apt-get install python-tk
# In CentOS
$ sudo yum install tkinter
```

### Building the module
1. Install Linux kernel headers

```shell
$ uname -a
Linux ubuntu 3.2.0-4-686-pae #1 SMP Ubuntu i686 GNU/Linux
$ sudo apt-get install linux-headers-3.2-0-4-686-pae
```

2. Compile the source code

```shell
$ make
```

### Loading the module

```shell
$ sudo insmod tcp_probe_plus.ko
```


### Read data
```shell
$ sudo python read_data.py
```


## Exported Data

The data collected by the LKM is exported through `/proc/net/tcpprobe` and is formatted using the following code (all numbers are hexadecimal to reduce the volumn of output data):

```c
copied += scnprintf(tbuf+copied, n-copied, "%x %lx %lx %x %x %x %x ",
	p->type, (unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
	ntohl(p->saddr), ntohs(p->sport), ntohl(p->daddr), ntohs(p->dport)
);
copied += scnprintf(tbuf+copied, n-copied, "%x %x %x %x ",
	p->length, p->tcp_flags, p->seq_num, p->ack_num
);
copied += scnprintf(tbuf+copied, n-copied, "%x %llx %x %x %x ",
	p->ca_state, p->snd_nxt, p->snd_una, p->write_seq, p->wqueue
);
copied += scnprintf(tbuf+copied, n-copied, "%x %x %x %x %x %x %x ",
	p->snd_cwnd, p->ssthresh, p->snd_wnd, p->srtt, p->mdev, p->rttvar, p->rto
);
copied += scnprintf(tbuf+copied, n-copied, "%x %x %x %x %x %x %x ",
	p->packets_out, p->lost_out, p->sacked_out, p->retrans_out, p->retrans,
	p->frto_counter, p->rto_num
);
copied += scnprintf(tbuf+copied, n-copied, "%x %lx %lx",
		p->sk_pacing_rate, (unsigned long) tv_nxt.tv_sec, (unsigned long) tv_nxt.tv_nsec
);
if (p->user_agent[0] != '\0') {
	copied += scnprintf(tbuf+copied, n-copied, " %s", p->user_agent);
}
copied += scnprintf(tbuf+copied, n-copied, "\n");
```

| Field | Description |
| ----- | ------------|
| type | Record type: 0 (recv), 1 (send), 2 (timeout), 3 (conn setup), 4 (tcp done), 5 (purge)|
| tv.tv_sec | Seconds since tcp probe data is read |
| tv.tv_nsec | Extra milliseconds(nanoseconds?) since tcp probe data is read |
| saddr | Source Address |
| sport | Source Port |
| daddr | Destination Address |
| dport | Destination Port |
| length | Length (in Bytes) of the sampled packet (65535 when this is last sample of a connection)|
| tcp_flags | The flags in tcp header |
| seq_num | Relative sequence number in the tcp header |
| ack_num | Relative ack number in the tcp header |
| ca_state | Congestion Avoidance state |
| snd_nxt | Sequence number of next packet to be sent (relative to the first seen sequence number)|
| snd_una | Sequence number of last unacknowledged packet (relative) |
| write_seq | Tail(+1) of data held in tcp send buffer (relative) |
| wqueue | Send buffer occupancy (in Bytes) |
| snd_cwnd | Current congestion window size (in number of packets) |
| ssthresh | Slow-start threshold (in number of packets) |
| snd_wnd | Receive window size (in number of packets) |
| srtt | Smoothed rtt (in 8us) |
| mdev | Medium deviation of rtt (in 4us) |
| rttvar | Standard deviation of the rtt (in 4us) |
| rto | duration of retransmit timeout (in ms) |
| packets_out | Packets which are "in flight" (actually, in_flight = packets_out + retrans_out - sack_out - lost_out) |
| lost_out | (estimated) Number of lost packets currently (not total). |
| sacked_out | # of packets sacked |
| retrans_out | # of retransmitted but not acked packets |
| retrans | Total # of retransmitted packets |
| frto_counter | Number of spurious RTO events (After linux 3.10.0, this value is never a counter) |
| rto_num | Number of retransmit timeout events |
| sk_pacing_rate | Pacing rate in Bytes per second |
| user_agent | User-Agent in the HTTP header |

## Sysctl interface

This LKM offers a sysctl interface to configure it. 

### Configuration

The following configuration parameters are available:

	ubuntu@host:~$ ls -al /proc/sys/net/tcpprobe_plus/
	total 0
	dr-xr-xr-x 1 root root 0 Mar  6 00:18 .
	dr-xr-xr-x 1 root root 0 Mar  5 18:55 ..
	-r--r--r-- 1 root root 0 Mar  6 00:18 bufsize
	-rw-r--r-- 1 root root 0 Mar  6 00:18 debug
	-rw-r--r-- 1 root root 0 Mar  6 00:18 full
	-r--r--r-- 1 root root 0 Mar  6 00:18 hashsize
	-rw-r--r-- 1 root root 0 Mar  6 00:18 maxflows
	-rw-r--r-- 1 root root 0 Mar  6 00:18 port
	-rw-r--r-- 1 root root 0 Mar  6 00:18 probetime
	-rw-r--r-- 1 root root 0 Mar  6 00:18 purgetime

#### Buffer size

This parameter controls the number of probes bufferred in memory.


- default is 4096 packets
- x: number of sampled packets the buffer can store

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/bufsize
	4096
	ubuntu@host:~$ sudo sh -c 'echo 1024 > /proc/sys/net/tcpprobe_plus/bufsize'


#### Read number

This parameter controls the minimum number of sampled packets that will be read from the `/proc/net/tcpprobe` buffer.

NOTE: The read will block until the specified number of packets are available.


- default is 10 packets
- x: number of packets to be read at a time

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/readnum
	4096
	ubuntu@host:~$ sudo sh -c 'echo 1024 > /proc/sys/net/tcpprobe_plus/readnum'


#### Enable/Disable debug information in kernel messages

This parameter controls the debug level.

- 0: no debug
- 1: debug enabled
- 2: trace enabled

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/debug
	1
	ubuntu@host:~$ sudo sh -c 'echo 0 > /proc/sys/net/tcpprobe_plus/debug'


#### Sample every ACK packet or only on Congestion Window change

This parameter determines how ACK packets are sampled.

- 0: only sample on cwnd changes
- 1: sample on every ack packet received

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/full
	1
	ubuntu@host:~$ sudo sh -c 'echo 0 > /proc/sys/net/tcpprobe_plus/full'

#### Connection hash table (maxflows/hashsize)

The memory used by the flow table is controlled by two parameters:

- maxflows: Maximum number of flows tracked by this module.
- hashsize: Size of the hashtable.

##### hashsize

This parameter defines the size of the hashtable.

- default size: automatically calculated - similar to the netfilter connection tracker
- x: size of the hashtable - number of slots that the hashtable has

A linked list is used to track flows that hash to the same slot in the hashtable.

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/hashsize
	0
	ubuntu@host:~$ sudo sh -c 'echo 16384 > /proc/sys/net/tcpprobe_plus/hashsize'

Max flow (see maxflows) has a default value of 2 million flows (2000000).

The minimum hashtable size is 32 slots. If you explicitly set a lower value, it will be reset to 32.

If you leave the hashtable size to be auto-calculated, then it is based on system memory availability, as coded below, and capped at 16,384 slots.

    /* determine hash size (idea from nf_conntrack_core.c) */
    if (!hashsize) {
      hashsize = (((totalram_pages << PAGE_SHIFT) / 16384)
                    / sizeof(struct hlist_head));
      if (totalram_pages > (1024 * 1024 * 1024 / PAGE_SIZE)) {
        hashsize = 16384;
      }
    }
    if (hashsize < 32) {
      hashsize = 32;
    }
    pr_info("Hashtable initialized with %u buckets\n", hashsize);

##### maxflows

This parameter controls the maximum number of flows that this module will track.

- default: 1,000 flows
- x: maximum number of flows to track

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/maxflows
	2000000
	ubuntu@host:~$ sudo sh -c 'echo 1000000 > /proc/sys/net/tcpprobe_plus/maxflows'

#### Port filtering

This parameter controls the port-based filtering of the flows to track.

- 0: no filtering
- x: port to match. This is a single port number. If it matches any of the send or receive port, then the flow will be tracked.

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/port
	0
	ubuntu@host:~$ sudo sh -c 'echo 5001 > /proc/sys/net/tcpprobe_plus/port'


#### Probe time

Upon receiving an ACK, the receive time of the ACK is compared with the receive time of the previous ACK for the connection. If the time difference is equal to or more than the probe time, then this ACK is eligible to be written to `/proc/net/tcpprobe`. The probe time is configurable from user space. The default probe time is 500 ms. This value could be passed as a module initialization parameter or changed using this parameter.

- default is 0 ms
- x: sampling interval

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/probetime
	500
	ubuntu@host:~$ sudo sh -c 'echo 200 > /proc/sys/net/tcpprobe_plus/probetime'


#### Purge time

Every `purgetime` the flows that are not active anymore are removed from the flow table. The purge time is configurable from user space. The default purge time is 300 s. This value could be passed as a module initialization parameter or changed using this parameter.

- default is 300 s
- x: purge time interval

Example:

	ubuntu@host:~$ more /proc/sys/net/tcpprobe_plus/purgetime
	500
	ubuntu@host:~$ sudo sh -c 'echo 200 > /proc/sys/net/tcpprobe_plus/purgetime'


### Statistics

This module offers several statistics about its internal behavior.

	ubuntu@host:~$ more /proc/net/stat/tcpprobe_plus
	Flows: active 4 mem 0K
	Hash: size 4721 mem 36K
	cpu# hash_stat: <search_flows found new reset>, ack_drop: <purge_in_progress ring_full>, 
	conn_drop: <maxflow_reached memory_alloc_failed>, err: <multiple_reader copy_failed>
	Total: hash_stat:      0  25877    151    147, ack_drop:      0      0, 
	conn_drop:      0      0, err:      0      0

Description:

- Flows
	- active: Number of active flows being monitored by the module at present.
	- mem: Total memory used by the flow table to monitor the current set of flows.
- Hash
	- size: Number of slots in the hash table (hashtable size).
	- mem: Total memory used by the hash table.
- hash_stat
	- search_flows: Number of flows looked up so far in the hash table.
	- found: Number of flows found in the hash table.
	- new: Number of new flow entries created so far.
	- reset: Number of flows entries that have been invalidated because the flows have been closed/reset. 
- ack_drop
	- purge_in_progress: Number of ACK packets skipped by this module because flow purging was in progress (NOTE: this requires locking the flow table).
	- ring_full: Number of ACK packets dropped because of a slow reader (NOTE: User space process reading `/proc/net/tcpprobe`)
- conn_drop
	- maxlfow_reached: New flow was skipped because maximum number of flows (2 million by default) has already been reached.
	- memory_alloc_failed: New flow was skipped because module was unable to allocate memory for the new flow entry.
- err
	- multiple_reader: Module detected multiple readers while writing to `/proc/net/tcpprobe`. Note that multiple readers are not supported. Each reader will see only part of the flow.
	- copy_failed: Unable to copy the data to the user-space.
