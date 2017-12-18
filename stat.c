#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/swap.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <net/tcp.h>

#include "tcp_probe_plus.h"

static int tcpprobe_open(struct inode * inode, struct file * file)
{
	struct timespec ts;

	/* Reset (empty) log */
	spin_lock_bh(&tcp_probe.lock);
	tcp_probe.head = tcp_probe.tail = 0;

	getnstimeofday(&ts);
	tcp_probe.start_datetime = timespec_to_ktime(ts);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	tcp_probe.start = tcp_probe.start_datetime;
#else
	tcp_probe.start = ktime_get();
#endif
	spin_unlock_bh(&tcp_probe.lock);

	return 0;
}

static int tcpprobe_sprint(char *tbuf, int n)
{
	const struct tcp_log *p = tcp_probe.log + tcp_probe.tail;
	struct timespec tv = ktime_to_timespec(ktime_sub(p->tstamp, tcp_probe.start));
	int copied = 0;

	/*copied += scnprintf(tbuf+copied, n-copied, "%x %lu.%09lu %pI4:%u %pI4:%u ",
		p->type, (unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
		&p->saddr, ntohs(p->sport), &p->daddr, ntohs(p->dport)
	);*/
	copied += scnprintf(tbuf+copied, n-copied, "%x %lx %lx %x %x %x %x ",
		p->type, (unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec,
		ntohl(p->saddr), ntohs(p->sport), ntohl(p->daddr), ntohs(p->dport)
	);
	copied += scnprintf(tbuf+copied, n-copied, "%x %x %x %x ",
		p->length, p->tcp_flags, p->seq_num, p->ack_num
	);
	copied += scnprintf(tbuf+copied, n-copied, "%x %x %x %x %x ",
		p->ca_state, p->snd_nxt, p->snd_una, p->write_seq, p->wqueue
	);
	copied += scnprintf(tbuf+copied, n-copied, "%x %x %x %x %x %x %x ",
		p->snd_cwnd, p->ssthresh, p->snd_wnd, p->srtt, p->mdev, p->rttvar, p->rto
	);
	copied += scnprintf(tbuf+copied, n-copied, "%x %x %x %x %x %x %x ",
		p->packets_out, p->lost_out, p->sacked_out, p->retrans_out, p->retrans,
		p->frto_counter, p->rto_num
	);
	copied += scnprintf(tbuf+copied, n-copied, "%x",
			p->sk_pacing_rate
	);
	copied += sprint_cc_data(tbuf+copied, n-copied, &(p->cc_data));
#if GET_USER_AGENT != 0
	if (p->user_agent[0] != '\0') {
		copied += scnprintf(tbuf+copied, n-copied, " %s", p->user_agent);
	}
#endif
	copied += scnprintf(tbuf+copied, n-copied, "\n");
	return copied;
}

static ssize_t tcpprobe_read(struct file *file, char __user *buf,
						size_t len, loff_t *ppos)
{
	int error = 0;
	size_t cnt = 0;
	int toread = readnum;

	if (!buf)
		return -EINVAL;
	PRINT_TRACE("Page size is %lu. Buffer len is %zu.\n", PAGE_SIZE, len);

	while (toread && cnt < len) {
		char tbuf[512];
		int width;

		/* Wait for data in buffer */
		error = wait_event_interruptible(tcp_probe.wait, tcp_probe_used() > 0);
		if (error)
			break;

		spin_lock_bh(&tcp_probe.lock);
		if (tcp_probe.head == tcp_probe.tail) {
			/* multiple readers race? */
			TCPPROBE_STAT_INC(multiple_readers);
			spin_unlock_bh(&tcp_probe.lock);
			continue;
		}

		width = tcpprobe_sprint(tbuf, sizeof(tbuf));

		if (cnt + width < len) {
			tcp_probe.tail = (tcp_probe.tail + 1) & (bufsize - 1);
		}

		spin_unlock_bh(&tcp_probe.lock);

		/* if record greater than space available
		return partial buffer (so far) */
		if (cnt + width >= len) {
			break;
		}
		if (copy_to_user(buf + cnt, tbuf, width)) {
			TCPPROBE_STAT_INC(copy_error);
			return -EFAULT;
		}
		cnt += width;
		toread--;
	}

	return cnt == 0 ? error : cnt;
}

/* procfs statistics /proc/net/stat/tcpprobe */
static int tcpprobe_seq_show(struct seq_file *seq, void *v)
{
	unsigned int nr_flows = atomic_read(&flow_count);
	struct tcpprobe_stat stat;
	int cpu;

	memset(&stat, 0, sizeof(struct tcpprobe_stat));

	for_each_present_cpu(cpu) {
		struct tcpprobe_stat *cpu_stat = &per_cpu(tcpprobe_stat, cpu);

		stat.ack_drop_purge += cpu_stat->ack_drop_purge;
		stat.ack_drop_ring_full += cpu_stat->ack_drop_ring_full;
		stat.conn_maxflow_limit += cpu_stat->conn_maxflow_limit;
		stat.conn_memory_limit += cpu_stat->conn_memory_limit;
		stat.searched += cpu_stat->searched;
		stat.found += cpu_stat->found;
		stat.notfound += cpu_stat->notfound;
		stat.multiple_readers += cpu_stat->multiple_readers;
		stat.copy_error += cpu_stat->copy_error;
		stat.reset_flows += cpu_stat->reset_flows;
	}
	seq_printf(seq, "Flows: active %u mem %uK\n", nr_flows,
	(unsigned int)((nr_flows * sizeof(struct tcp_hash_flow)) >> 10));
	seq_printf(seq, "Hash: size %u mem %uK\n",
	hashsize, (unsigned int)((hashsize * sizeof(struct hlist_head)) >> 10));
	seq_printf(seq, "cpu# hash_stat: <search_flows found new reset>, ack_drop: <purge_in_progress ring_full>, conn_drop: <maxflow_reached memory_alloc_failed>, err: <multiple_reader copy_failed>\n");
	seq_printf(seq, "Total: hash_stat: %6llu %6llu %6llu %6llu, ack_drop: %6llu %6llu, conn_drop: %6llu %6llu, err: %6llu %6llu\n",
	stat.searched, stat.found, stat.notfound, stat.reset_flows,
	stat.ack_drop_purge, stat.ack_drop_ring_full,
	stat.conn_maxflow_limit, stat.conn_memory_limit,
	stat.multiple_readers, stat.copy_error);
	if (num_present_cpus() > 1) {
		for_each_present_cpu(cpu) {
			struct tcpprobe_stat *cpu_stat = &per_cpu(tcpprobe_stat, cpu);
			seq_printf(seq, "cpu%u: hash_stat: %6llu %6llu %6llu %6llu, ack_drop: %6llu %6llu, conn_drop: %6llu %6llu, err: %6llu %6llu\n",
			cpu,
			cpu_stat->searched, cpu_stat->found, stat.notfound, stat.reset_flows,
			cpu_stat->ack_drop_purge, cpu_stat->ack_drop_ring_full,
			cpu_stat->conn_maxflow_limit, cpu_stat->conn_memory_limit,
			cpu_stat->multiple_readers, cpu_stat->copy_error);
		}
	}
	return 0;
}

static int tcpprobe_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tcpprobe_seq_show, NULL);
}

const struct file_operations tcpprobe_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tcpprobe_open,
	.read    = tcpprobe_read,
	.llseek  = noop_llseek,
};

const struct file_operations tcpprobe_stat_fops = {
	.owner = THIS_MODULE,
	.open  = tcpprobe_seq_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

