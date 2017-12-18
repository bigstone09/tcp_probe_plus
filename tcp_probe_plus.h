#ifndef TCP_PROBE_PLUS_H
#define TCP_PROBE_PLUS_H
#include "tcp_cubic.h"

#define PROC_TCPPROBE "tcpprobe_data"

#define PROC_SYSCTL_TCPPROBE  "tcpprobe_plus"
#define PROC_STAT_TCPPROBE "tcpprobe_plus"

#define UINT32_MAX                 (u32)(~((u32) 0)) /* 0xFFFFFFFF         */
#define UINT16_MAX                 (u16)(~((u16) 0)) /* 0xFFFF         */
#define GET_USER_AGENT 0
#define DEBUG_DISABLE 0
#define DEBUG_ENABLE  1
#define TRACE_ENABLE  2
#define PRINT_DEBUG(fmt, arg...)				\
  do {											\
	if (debug == DEBUG_ENABLE) {				\
	  pr_info(fmt, ##arg);						\
	}											\
  } while(0)

#define PRINT_TRACE(fmt, arg...)							\
  do {														\
	if (debug == DEBUG_ENABLE || debug == TRACE_ENABLE) {	\
	  pr_info(fmt, ##arg);									\
	}														\
  } while(0)

#ifndef pr_err
#define pr_err(fmt, arg...) pr_info(fmt, ##arg)
#endif

#define TCP_FLAGS(th) \
	(th->cwr << 7) | (th->ece << 6) | (th->urg << 5) | (th->ack << 4) | \
		(th->psh << 3) | (th->rst << 2) | (th->syn << 1) | (th->fin);

#define MAX_AGENT_LEN 128

struct tcp_tuple {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
};

/* tuple size is rounded to u32s */
#define TCP_TUPLE_SIZE (sizeof(struct tcp_tuple) / 4)

struct tcp_hash_flow {
	struct hlist_node hlist; // hashtable search chain
	struct list_head list; // all flows chain

	/* unique per flow data (hashed, TCP_TUPLE_SIZE) */
	struct tcp_tuple tuple;

	/* enable(0), disable(1), unknown(2) */
	u8 sack_enable;
	/* Last ACK Timestamp */
	ktime_t tstamp;
	u32 first_ack_num;
	/* remember last sequence number */
	u32 last_seq_num;
	u64 first_seq_num;
	unsigned rto_num; /* # of retransmit timeout */
#if GET_USER_AGENT != 0
	char user_agent[MAX_AGENT_LEN];
#endif
};

/* statistics */
struct tcpprobe_stat {
	u64 ack_drop_purge;      /* ACK dropped due to purge in progress */
	u64 ack_drop_ring_full;  /* ACK dropped due to slow reader */
	u64 conn_maxflow_limit;  /* Connection skipped due maxflow limit */
	u64 conn_memory_limit;   /* Connection skipped because memory was unavailable */
	u64 searched;            /* hash stat - searched */
	u64 found;		 /* hash stat - found */
	u64 notfound;            /* hash stat - not found */
	u64 multiple_readers;    /* Multiple readers for /proc/net/tcpprobe */
	u64 copy_error;          /* Userspace copy error */
	u64 reset_flows; /* Number of FIN/RST received that caused to purge the flow */
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define TCPPROBE_STAT_INC(count) (__get_cpu_var(tcpprobe_stat).count++)
#else
#define TCPPROBE_STAT_INC(count) __this_cpu_add(tcpprobe_stat.count, 1)
#endif

enum {
	LOG_RECV = 0,
	LOG_SEND,
	LOG_TIMEOUT,
	LOG_SETUP,
	LOG_DONE,
	LOG_PURGE,
};

enum {
	SACK_UNKNOWN,
	SACK_DISABLE,
	SACK_ENABLE,
};

struct tcp_log {
	/* log type: recv(0), send(1), timeout(2), connection setup(3), tcp_done(4), RTO timeout(5)*/
	u8 type;
	u8 ca_state;
	u8 frto_counter;
	u8 tcp_flags;
	/* enable(0), disable(1), unknown(2) */
	u8 sack_enable;
	ktime_t tstamp;
	__be32	saddr, daddr;
	__be16	sport, dport;
	u16 rto_num;
	u16 length;
	u32 seq_num;
	u32 ack_num;
	u32 snd_nxt;
	u32 snd_una;
	u32 snd_wnd;
	u32 snd_cwnd;
	u32 rcv_wnd;
	u32 ssthresh;
	u32 srtt;
	u32 mdev;
	u32 rttvar;
	u32 rto;
	u32 packets_out;
	u32 lost_out;
	u32 sacked_out;
	u32 retrans_out;
	u32 retrans;
	u32 write_seq;
	u32 rqueue;
	u32 wqueue;
	u32 sk_pacing_rate;
	u32 socket_idf;
	/* seq_rtt_us < 0 means parse timestamp option failed, because
	 *	1. no timestamp option
	 *	2. there are other options than timestamp
	 */
	/*long seq_rtt_us_tsecr;
	long seq_rtt_us_skb_mstamp;*/
	long seq_rtt;
#if GET_USER_AGENT != 0
	char user_agent[MAX_AGENT_LEN];
#endif
	/*Congestion control specified data*/
	struct cc_block cc_data;
};

struct tcp_probe_list {
	spinlock_t lock;
	wait_queue_head_t wait;
	ktime_t start;
	ktime_t start_datetime;
	u32 lastcwnd;

	unsigned long head, tail;
	struct tcp_log *log;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define INIT_NET(x) x
#else
#define INIT_NET(x) init_net.x
#endif

extern ktime_t start_time;

extern struct tcpprobe_stat tcpprobe_stat;

extern int port;
extern unsigned int bufsize;
extern unsigned int readnum;
extern int full;
extern int probetime;
extern int hashsize;
extern int maxflows;
extern int debug;
extern int purgetime;

extern struct tcp_probe_list tcp_probe;

extern unsigned int tcp_hash_rnd;
extern unsigned int tcp_hash_size; /* buckets */
extern struct hlist_head *tcp_hash; /* hash table memory */
extern struct kmem_cache *tcp_flow_cachep; /* tcp flow memory */

extern struct timer_list purge_timer;
extern atomic_t flow_count;
extern struct list_head tcp_flow_list;


extern const struct file_operations tcpprobe_fops;
extern const struct file_operations tcpprobe_stat_fops;

extern struct ctl_table tcpprobe_sysctl_table[];
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
extern struct ctl_table tcpprobe_net_table[];
#else
extern struct ctl_path tcpprobe_sysctl_path[];
#endif

static inline int tcp_probe_used(void) {
	return (tcp_probe.head - tcp_probe.tail) & (bufsize - 1);
}

static inline int tcp_probe_avail(void) {
	return bufsize - tcp_probe_used() - 1;
}

static inline int tcp_tuple_equal(
	const struct tcp_tuple *t1,
	const struct tcp_tuple *t2
) {
	return (!memcmp(t1, t2, sizeof(struct tcp_tuple)));
}

u_int32_t hash_tcp_flow(const struct tcp_tuple *tuple);

void jtcp_done(struct sock *sk);
int jtcp_rcv_established(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th, unsigned len);
void jtcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
				gfp_t gfp_mask);
void jtcp_retransmit_timer(struct sock *sk);
void jtcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb, struct request_sock *req, struct dst_entry *dst);
void jtcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb);

void purge_timer_run(unsigned long dummy);
void purge_all_flows(void);

void tcp_hash_flow_free(struct tcp_hash_flow *flow);
struct tcp_hash_flow* tcp_flow_find(const struct tcp_tuple *tuple,
		unsigned int hash);
struct tcp_hash_flow* init_tcp_hash_flow(struct tcp_tuple *tuple,
		ktime_t tstamp, unsigned int hash);
#endif
