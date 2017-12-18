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

unsigned int tcp_hash_rnd;
struct hlist_head *tcp_hash __read_mostly; /* hash table memory */
unsigned int tcp_hash_size __read_mostly = 0; /* buckets */
struct kmem_cache *tcp_flow_cachep __read_mostly; /* tcp flow memory */

void tcp_hash_flow_free(struct tcp_hash_flow *flow)
{
	atomic_dec(&flow_count);
	kmem_cache_free(tcp_flow_cachep, flow);
}

struct tcp_hash_flow*
tcp_flow_find(const struct tcp_tuple *tuple, unsigned int hash)
{
	struct tcp_hash_flow *flow;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
	hlist_for_each_entry(flow, pos, &tcp_hash[hash], hlist) {
#else
	//Second argument was removed
	hlist_for_each_entry(flow, &tcp_hash[hash], hlist) {
#endif
		if (tcp_tuple_equal(tuple, &flow->tuple)) {
			TCPPROBE_STAT_INC(found);
			return flow;
		}
		TCPPROBE_STAT_INC(searched);
	}
	TCPPROBE_STAT_INC(notfound);
	return NULL;
}

static struct tcp_hash_flow*
tcp_hash_flow_alloc(struct tcp_tuple *tuple)
{
	struct tcp_hash_flow *flow;
	flow = kmem_cache_alloc(tcp_flow_cachep, GFP_ATOMIC);
	if (!flow) {
		pr_err("Cannot allocate tcp_hash_flow.\n");
		TCPPROBE_STAT_INC(conn_memory_limit);
		return NULL;
	}
	memset(flow, 0, sizeof(struct tcp_hash_flow));
	flow->tuple = *tuple;
	atomic_inc(&flow_count);
	return flow;
}

struct tcp_hash_flow* init_tcp_hash_flow(struct tcp_tuple *tuple,
		ktime_t tstamp, unsigned int hash)
{
	struct tcp_hash_flow *flow;
	flow = tcp_hash_flow_alloc(tuple);
	if (!flow) {
		return NULL;
	}
	flow->tstamp = tstamp;
	flow->rto_num = 0;
#if GET_USER_AGENT != 0
	flow->user_agent[0] = '\0';
#endif
	flow->sack_enable = SACK_UNKNOWN;
	hlist_add_head(&flow->hlist, &tcp_hash[hash]);
	INIT_LIST_HEAD(&flow->list);
	list_add(&flow->list, &tcp_flow_list);

	return flow;
}

inline u_int32_t hash_tcp_flow(const struct tcp_tuple *tuple) {
	/* tuple is rounded to u32s */
	return jhash2((u32 *)tuple, TCP_TUPLE_SIZE, tcp_hash_rnd) % tcp_hash_size;
}
