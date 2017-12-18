#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/swap.h>
#include <linux/random.h>
#include <linux/vmalloc.h>

#include <net/tcp.h>

#include "tcp_probe_plus.h"

ktime_t start_time;

static struct ctl_table_header *tcpprobe_sysctl_header;

static struct jprobe tcp_jprobe_recv = {
	.kp = {
		.symbol_name = "tcp_v4_do_rcv",
	},
	.entry = (kprobe_opcode_t *) jtcp_v4_do_rcv,
};


static struct jprobe tcp_jprobe_done = {
	.kp = {
		.symbol_name = "tcp_done",
	},
	.entry = (kprobe_opcode_t *) jtcp_done,
};

static struct jprobe tcp_jprobe_send = {
	.kp = {
		.symbol_name = "tcp_transmit_skb",
	},
	.entry = (kprobe_opcode_t *) jtcp_transmit_skb,
};
static struct jprobe tcp_jprobe_rto_timeout = {
	.kp = {
		.symbol_name = "tcp_retransmit_timer",
	},
	.entry = (kprobe_opcode_t *) jtcp_retransmit_timer,
};
static struct jprobe tcp_jprobe_syn_recv = {
	.kp = {
		.symbol_name = "tcp_v4_syn_recv_sock",
	},
	.entry = (kprobe_opcode_t *) jtcp_v4_syn_recv_sock,
};
static struct jprobe tcp_jprobe_test= {
	.kp = {
		.symbol_name = "tcp_rcv_established",
	},
	.entry	= (kprobe_opcode_t *) jtcp_rcv_established,
};


static struct hlist_head * alloc_hashtable(int size)
{
	struct hlist_head *hash;
	hash = vmalloc(sizeof(struct hlist_head) * size);
	if (hash) {
		int i;
		for (i = 0; i < size; i++) {
			INIT_HLIST_HEAD(&hash[i]);
		}
	} else {
		pr_err("Unable to vmalloc hash table size = %d\n", size);
	}
	return hash;
}

static __init int tcpprobe_init(void)
{
	int ret = -ENOMEM;
	struct proc_dir_entry *proc_stat;
	struct timespec ct_ts;
	struct rtc_time ct_tm;

	init_waitqueue_head(&tcp_probe.wait);
	spin_lock_init(&tcp_probe.lock);

	if (bufsize == 0) {
		pr_err("Bufsize is 0\n");
		return -EINVAL;
	}

	/* Hashtable initialization */
	get_random_bytes(&tcp_hash_rnd, 4);

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

	tcp_hash_size = hashsize;
	tcp_hash = alloc_hashtable(tcp_hash_size);
	if (!tcp_hash) {
		pr_err("Unable to create tcp hashtable\n");
		goto err;
	}
	tcp_flow_cachep = kmem_cache_create("tcp_flow",
	sizeof(struct tcp_hash_flow), 0, 0, NULL
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
		, NULL
#endif
	);
	if (!tcp_flow_cachep) {
		pr_err("Unable to create tcp_flow slab cache\n");
		goto err_free_hash;
	}
	setup_timer(&purge_timer, purge_timer_run, 0);
	mod_timer(&purge_timer, jiffies + (HZ * purgetime));


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	tcpprobe_sysctl_header = register_sysctl_table(tcpprobe_net_table
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
		,0 /* insert_at_head */
#endif
	);
#else /* 2.6.25 */
	tcpprobe_sysctl_header = register_sysctl_paths(tcpprobe_sysctl_path, tcpprobe_sysctl_table);
#endif
	if (!tcpprobe_sysctl_header) {
		pr_err("tcpprobe_plus: can't register to sysctl\n");
		goto err0;
	} else {
		pr_info("tcpprobe_plus: registered: sysclt net.%s\n", PROC_SYSCTL_TCPPROBE);
	}

	//create_proc_entry has been deprecated by proc_create since 3.10
	proc_stat = proc_create(PROC_STAT_TCPPROBE, S_IRUGO, INIT_NET(proc_net_stat), &tcpprobe_stat_fops);

	if (!proc_stat) {
		pr_err("Unable to create /proc/net/stat/%s entry \n", PROC_STAT_TCPPROBE);
		goto err_free_sysctl;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
	proc_stat->owner = THIS_MODULE;
#endif
	pr_info("tcpprobe_plus: registered: /proc/net/stat/%s\n", PROC_STAT_TCPPROBE);


	bufsize = roundup_pow_of_two(bufsize);
	tcp_probe.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
	if (!tcp_probe.log) {
		pr_err("Unable to allocate tcp_log memory.\n");
		goto err_free_proc_stat;
	}

	//proc_net_fops_create has been deprecated by proc_create since 3.10
	if (!proc_create(PROC_TCPPROBE, S_IRUSR, INIT_NET(proc_net), &tcpprobe_fops)) {
		pr_err("Unable to create /proc/net/tcpprobe_data\n");
		goto err_free_proc_stat;
	}

	ret = register_jprobe(&tcp_jprobe_recv);
	if (ret) {
		pr_err("Unable to register jprobe on tcp_v4_do_rcv.\n");
		goto err1;
	}

	ret = register_jprobe(&tcp_jprobe_send);
	if (ret) {
		pr_err("Unable to register jprobe on tcp_transmit_skb.\n");
		goto err1;
	}

	ret = register_jprobe(&tcp_jprobe_rto_timeout);
	if (ret) {
		pr_err("Unable to register jprobe on tcp_retransmit_timer.\n");
		goto err_tcpdone;
	}

	ret = register_jprobe(&tcp_jprobe_syn_recv);
	if (ret) {
		pr_err("Unable to register jprobe on tcp_v4_syn_recv_sock.\n");
		goto err_tcpdone;
	}

	/*ret = register_jprobe(&tcp_jprobe_test);
	if (ret) {
		pr_err("Unable to register jprobe on tcp_v4_syn_recv_sock.\n");
		goto err_tcpdone;
	}*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	pr_info("Not registering jprobe on tcp_done as it is an inline method in this kernel version.\n");
#else
	ret = register_jprobe(&tcp_jprobe_done);
	if (ret) {
		pr_err("Unable to register jprobe on tcp_done.\n");
		goto err_tcpdone;
	}
#endif

	getnstimeofday(&ct_ts);
	start_time = timespec_to_ktime(ct_ts);

	/*UTC +8 time*/
	ct_ts.tv_sec += 28800;
	rtc_time_to_tm((unsigned long) ct_ts.tv_sec, &ct_tm);


	pr_info("(%04d-%02d-%02d %02d:%02d:%02d) TCP probe plus registered (port=%d) bufsize=%u probetime=%d maxflows=%u\n",
		ct_tm.tm_year + 1900, ct_tm.tm_mon + 1, ct_tm.tm_mday,
		ct_tm.tm_hour, ct_tm.tm_min, ct_tm.tm_sec,
		port, bufsize, probetime, maxflows);
	PRINT_DEBUG("Sizes tcp_hash_flow: %zu, hlist_head = %zu tcp_hash = %zu\n",
	sizeof(struct tcp_hash_flow), sizeof(struct hlist_head), sizeof(tcp_hash));
	PRINT_DEBUG("Sizes hlist_node = %zu list_head = %zu, ktime_t = %zu tcp_tuple = %zu\n",
	sizeof(struct hlist_node), sizeof(struct list_head), sizeof(ktime_t), sizeof(struct tcp_tuple));
	PRINT_DEBUG("Sizes tcp_log = %zu\n", sizeof (struct tcp_log));

	return 0;

err_tcpdone:
	unregister_jprobe(&tcp_jprobe_recv);
	unregister_jprobe(&tcp_jprobe_send);
	unregister_jprobe(&tcp_jprobe_rto_timeout);
	unregister_jprobe(&tcp_jprobe_syn_recv);
	/*unregister_jprobe(&tcp_jprobe_test);*/
err1:
	remove_proc_entry(PROC_TCPPROBE, INIT_NET(proc_net));
err_free_proc_stat:
	remove_proc_entry(PROC_STAT_TCPPROBE, INIT_NET(proc_net_stat));
err_free_sysctl:
	unregister_sysctl_table(tcpprobe_sysctl_header);
err0:
	del_timer_sync(&purge_timer);
	kfree(tcp_probe.log);
	kmem_cache_destroy(tcp_flow_cachep);
err_free_hash:
	vfree(tcp_hash);
err:
	return ret;
}

static __exit void tcpprobe_exit(void)
{
	struct timespec ct_ts;
	struct rtc_time ct_tm;

	getnstimeofday(&ct_ts);
	/*UTC +8 time*/
	ct_ts.tv_sec += 28800;
	rtc_time_to_tm((unsigned long) ct_ts.tv_sec, &ct_tm);

	remove_proc_entry(PROC_TCPPROBE, INIT_NET(proc_net));
	remove_proc_entry(PROC_STAT_TCPPROBE, INIT_NET(proc_net_stat));
	unregister_sysctl_table(tcpprobe_sysctl_header);
	unregister_jprobe(&tcp_jprobe_recv);
	unregister_jprobe(&tcp_jprobe_send);
	unregister_jprobe(&tcp_jprobe_rto_timeout);
	unregister_jprobe(&tcp_jprobe_syn_recv);
	/*unregister_jprobe(&tcp_jprobe_test);*/

#if LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,22)
	unregister_jprobe(&tcp_jprobe_done);
#endif

	kfree(tcp_probe.log);
	del_timer_sync(&purge_timer);
	/* tcp flow table memory */
	purge_all_flows();
	kmem_cache_destroy(tcp_flow_cachep);
	vfree(tcp_hash);
	pr_info("(%04d-%02d-%02d %02d:%02d:%02d) TCP probe plus unregistered.\n",
		ct_tm.tm_year + 1900, ct_tm.tm_mon + 1, ct_tm.tm_mday,
		ct_tm.tm_hour, ct_tm.tm_min, ct_tm.tm_sec);
}

module_init(tcpprobe_init);
module_exit(tcpprobe_exit);

MODULE_AUTHOR("Stephen Hemminger <shemminger@linux-foundation.org>");
MODULE_DESCRIPTION("TCP cwnd snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.2");
