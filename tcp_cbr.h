#ifndef TCPPROBE_TCP_CBR_H
#define TCPPROBE_TCP_CBR_H
#include <linux/module.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>

struct cc_block {
	u32 irtt;
	u32 ibw;
	u32 maxbw;
	u32 rtt_cnt;
	u32 min_rtt_us;
	u32 round_start:1,
		lt_is_sampling:1,
		lt_use_bw:1,
		mode:3,
		cycle_idx:3,
		lt_rtt_cnt:7,
		pacing_gain:10,
		unused:6;
	u32 lt_bw;
};

/* CBR congestion control block */
struct cbr {
	u32 ibw; /*in pkts/us << 24*/
	u32 irtt; /*in us*/
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32	probe_rtt_done_stamp;   /* end time for CBR_PROBE_RTT mode */
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	struct skb_mstamp cycle_mstamp;  /* time of this cycle phase start */
	u32     mode:3,		     /* current cbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
		restore_cwnd:1,	     /* decided to revert cwnd to old value */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		tso_segs_goal:7,     /* segments we want in each skb we send */
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a CBR_PROBE_RTT round at 4 pkts? */
		unused:5,
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
		cwnd_gain:10,	/* current gain for setting cwnd */
		full_bw_cnt:3,	/* number of rounds without large bw gains */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		unused_b:6;
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */
};


static char cc_name[10] = "cbr";
static ssize_t cc_len = 3;
static inline int check_cc_name(const struct inet_connection_sock *icsk) {
	size_t get_cclen = strlen(icsk->icsk_ca_ops->name);
	size_t want_cclen = cc_len;
	int ret = (get_cclen != want_cclen);
	if (ret == 0)
		ret = strnicmp(icsk->icsk_ca_ops->name, cc_name, want_cclen);
	if (ret) {
		pr_err("Wrong congestion control (Want: %s; Get: %s).\n", cc_name, icsk->icsk_ca_ops->name);
	}
	return ret;
}
static inline void fill_cc_data(struct cc_block *cc_data, struct sock *sk, struct sk_buff *skb) {
	struct cbr *ca = inet_csk_ca(sk);
	//struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	if (check_cc_name(icsk)) {
		memset(cc_data, 0, sizeof(struct cc_block));
		return ;
	}
	cc_data->irtt = ca->irtt;
	cc_data->ibw = ca->ibw;
	cc_data->maxbw =  minmax_get(&ca->bw);
	cc_data->min_rtt_us = ca->min_rtt_us;
	cc_data->rtt_cnt = ca->rtt_cnt;
	cc_data->round_start = ca->round_start;
	cc_data->lt_is_sampling = ca->lt_is_sampling;
	cc_data->lt_use_bw = ca->lt_use_bw;
	cc_data->mode = ca->mode;
	cc_data->cycle_idx = ca->cycle_idx;
	cc_data->lt_rtt_cnt = ca->lt_rtt_cnt;
	cc_data->pacing_gain = ca->pacing_gain;
	cc_data->lt_bw = ca->lt_bw;
}

static inline int sprint_cc_data(char *tbuf,  int n, const struct cc_block *cc_data) {
	int copied = 0;
	copied += scnprintf(tbuf+copied, n-copied, " %x %x", cc_data->irtt, cc_data->ibw);
	copied += scnprintf(tbuf+copied, n-copied, " %x %x", cc_data->maxbw, cc_data->pacing_gain);
	copied += scnprintf(tbuf+copied, n-copied, " %x", cc_data->min_rtt_us);
	copied += scnprintf(tbuf+copied, n-copied, " %x %x", cc_data->round_start, cc_data->rtt_cnt);
	copied += scnprintf(tbuf+copied, n-copied, " %x %x", cc_data->mode, cc_data->cycle_idx);
	copied += scnprintf(tbuf+copied, n-copied, " %x %x", cc_data->lt_is_sampling, cc_data->lt_rtt_cnt);
	copied += scnprintf(tbuf+copied, n-copied, " %x %x", cc_data->lt_use_bw, cc_data->lt_bw);
	return copied;
}
#endif
