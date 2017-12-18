#ifndef TCPPROBE_TCP_CBR_H
#define TCPPROBE_TCP_CBR_H
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

struct cc_block {
	u32 test;
};

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	u32	delay_min;	/* min delay (msec << 3) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
	u16	unused;
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
};

static char cc_name[6] = "cubic";
static ssize_t cc_len = 5;
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
	/* Uncomment these before write your own code */
	/*struct cbr *ca = inet_csk_ca(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	if (check_cc_name(icsk)) {
		memset(cc_data, 0, sizeof(struct cc_block));
		return ;
	}*/
}

static inline int sprint_cc_data(char *tbuf,  int n, const struct cc_block *cc_data) {
	int copied = 0;
	return copied;
}
#endif
