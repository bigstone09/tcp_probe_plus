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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	#define _CTL_NAME(x) .ctl_name = x,
#else
	#define _CTL_NAME(x)
#endif

int port __read_mostly = 0;
MODULE_PARM_DESC(port, "Port to match (0=all)");
module_param(port, int, 0);

unsigned int bufsize __read_mostly = 4096;
MODULE_PARM_DESC(bufsize, "Log buffer size in packets (4096)");
module_param(bufsize, uint, 0);

unsigned int readnum __read_mostly = 1;
MODULE_PARM_DESC(readnum, "The number of probes to be read each time (10)");
module_param(readnum, uint, 0);

int full __read_mostly = 1;
MODULE_PARM_DESC(full, "Full log (1=every ack packet received,  0=only cwnd changes)");
module_param(full, int, 0);

int probetime __read_mostly = 0;
MODULE_PARM_DESC(probetime, "Probe time to write flows in milliseconds (500 milliseconds)");
module_param(probetime, int, 0);

int hashsize __read_mostly = 0;
MODULE_PARM_DESC(hashsize, "hash table size");
module_param(hashsize, int, 0);

int maxflows __read_mostly = 1000;
MODULE_PARM_DESC(maxflows, "Maximum number of flows");
module_param(maxflows, int, 0);

int debug __read_mostly = 0;
MODULE_PARM_DESC(debug, "Enable debug messages (Default 0) debug=1, trace=2");
module_param(debug, int , 0);

int purgetime __read_mostly = 300;
MODULE_PARM_DESC(purgetime, "Max inactivity in seconds before purging a flow (Default 300 seconds)");

struct ctl_table tcpprobe_sysctl_table[] = {
	{
		_CTL_NAME(1)
		.procname = "debug",
		.mode = 0644,
		.data = &debug,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(2)
		.procname = "probetime",
		.mode = 0644,
		.data = &probetime,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(3)
		.procname = "maxflows",
		.mode = 0644,
		.data = &maxflows,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(4)
		.procname = "full",
		.mode = 0644,
		.data = &full,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(5)
		.procname = "port",
		.mode = 0644,
		.data = &port,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(6)
		.procname = "hashsize",
		.mode = 0444, /* readonly */
		.data = &hashsize,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(7)
		.procname = "bufsize",
		.mode = 0444, /* readonly */
		.data = &bufsize,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(8)
		.procname = "purge_time",
		.mode = 0644,
		.data = &purgetime,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{
		_CTL_NAME(9)
		.procname = "readnum",
		.mode = 0644,
		.data = &readnum,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec,
	},
	{}
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static struct ctl_table tcpprobe_sysctl_root[] = {
	{
		_CTL_NAME(33)
		.procname = PROC_SYSCTL_TCPPROBE,
		.mode = 0555,
		.child = tcpprobe_sysctl_table,
	},
	{ }
};

struct ctl_table tcpprobe_net_table[] = {
{
	.ctl_name = CTL_NET,
	.procname = "net",
	.mode = 0555,
	.child = tcpprobe_sysctl_root,
},
{ }
};
#else /* >= 2.6.25 */
struct ctl_path tcpprobe_sysctl_path[] = {
	{
		.procname = "net",
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name = CTL_NET
#endif
	},
	{ .procname = PROC_SYSCTL_TCPPROBE },
	{ }
};
#endif /* 2.6.25 */
