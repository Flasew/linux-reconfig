// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2008, Intel Corporation.
 *
 * Author: Alexander Duyck <alexander.h.duyck@intel.com>
 *         Weiyang Wang <weiyangw@mit.edu>
 *	       Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *         Jamal Hadi Salim, <hadi@cyberus.ca> 990601
 * Reconfigurable network aware qdisc, inspired by the design in Mordia.
 * Implementation based on the multiq and pfifo
 */

#include <linux/module.h>
#include <linux/skb_array.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

#define RECONFIG_BANDS 32

static inline bool is_ipv4_packet(struct sk_buff *skb) {
	printk("is_ipv4_packet, skb->protocol=%hu\n", skb->protocol);
    return skb->protocol == htons(ETH_P_IP);
}

static inline struct skb_array *band2list(struct reconfig_sched_data *priv,
					  int band)
{
	return &priv->queues[band];
}

// static struct Qdisc *
// reconfig_classify(struct sk_buff *skb, struct Qdisc *qdisc, int *qerr)
// {
// 	struct reconfig_sched_data *q = qdisc_priv(sch);
// 	u32 band;

// 	band = skb_get_queue_mapping(skb);
// 	printk("[reconfig] band %hu\n", band);
// 	if (is_ipv4_packet(skb)) {
// 		struct iphdr * iphdr = ip_hdr(skb);
// 		printk("[reconfig] ip dst %x\n", iphdr->daddr);
// 	} else {
// 		printk("Dropped packet not IPV4\n");
// 		return NULL;
// 	}

// 	if (band >= q->bands)
// 		return q->queues[0];

// 	return q->queues[band];
// }

static int
reconfig_enqueue(struct sk_buff *skb, struct Qdisc *qdisc,
	       struct sk_buff **to_free)
{
	struct reconfig_sched_data *priv = qdisc_priv(qdisc);
	struct skb_array *q;
	unsigned int pkt_len = qdisc_pkt_len(skb);
	int err;
	int band;
	struct iphdr * iphdr = ip_hdr(skb);
	u32 ip_daddr;
	
	if (is_ipv4_packet(skb)) {
		ip_daddr = ntohl(iphdr->daddr);
		printk("[reconfig] ip dst %x\n", ip_daddr);
	} else {
		printk("[reconfig] Dropped packet not IPV4\n");
		if (qdisc_is_percpu_stats(qdisc))
			return qdisc_drop_cpu(skb, qdisc, to_free);
		else
			return qdisc_drop(skb, qdisc, to_free);
	}
	band = ((ip_daddr & 0x0000ff00u) >> 8);
	if (band >= RECONFIG_BANDS)  {
		printk("[reconfig] Dropped packet not exceeding band count\n");
		if (qdisc_is_percpu_stats(qdisc))
			return qdisc_drop_cpu(skb, qdisc, to_free);
		else
			return qdisc_drop(skb, qdisc, to_free);
	}
	q = band2list(priv, band);
	printk("[reconfig] Find bind %u\n", band);

	err = skb_array_produce(q, skb);

	if (unlikely(err)) {
		if (qdisc_is_percpu_stats(qdisc))
			return qdisc_drop_cpu(skb, qdisc, to_free);
		else
			return qdisc_drop(skb, qdisc, to_free);
	}

	qdisc_update_stats_at_enqueue(qdisc, pkt_len);
	return NET_XMIT_SUCCESS;

	// struct Qdisc *qdisc;
	// int ret;

	// qdisc = reconfig_classify(skb, sch, &ret);

	// ret = qdisc_enqueue(skb, qdisc, to_free);
	// if (ret == NET_XMIT_SUCCESS) {
	// 	sch->q.qlen++;
	// 	return NET_XMIT_SUCCESS;
	// }
	// if (net_xmit_drop_count(ret))
	// 	qdisc_qstats_drop(sch);
	// return ret;
}

static struct sk_buff *reconfig_dequeue(struct Qdisc *qdisc)
{
	struct reconfig_sched_data *priv = qdisc_priv(qdisc);
	struct sk_buff *skb = NULL;
	bool need_retry = true;
	int band = READ_ONCE(priv->curband);
	bool stopped = READ_ONCE(priv->stopped);

	if (stopped) {
		printk("[reconfig] TX paused when attempting dequeue\n");
		return NULL;
	}
	// if (netif_xmit_stopped(
	// 	netdev_get_tx_queue(qdisc_dev(qdisc), 0))) {
	// 		printk("TX Queue paused when attempting dequeue\n");
	// 		return NULL;
	// }

retry:
	struct skb_array *q = band2list(priv, band);
	if (__skb_array_empty(q))
		return NULL;
	skb = __skb_array_consume(q);

	if (likely(skb)) {
		qdisc_update_stats_at_dequeue(qdisc, skb);
	} else if (need_retry &&
		   READ_ONCE(qdisc->state) & QDISC_STATE_NON_EMPTY) {
		/* Delay clearing the STATE_MISSED here to reduce
		 * the overhead of the second spin_trylock() in
		 * qdisc_run_begin() and __netif_schedule() calling
		 * in qdisc_run_end().
		 */
		clear_bit(__QDISC_STATE_MISSED, &qdisc->state);
		clear_bit(__QDISC_STATE_DRAINING, &qdisc->state);

		/* Make sure dequeuing happens after clearing
		 * STATE_MISSED.
		 */
		smp_mb__after_atomic();

		need_retry = false;

		goto retry;
	}

	return skb;
	// struct reconfig_sched_data *q = qdisc_priv(sch);
	// struct Qdisc *qdisc;
	// struct sk_buff *skb;
	// int band;

	// band = READ_ONCE(q->curband);

	// if (!netif_xmit_stopped(
	// 	netdev_get_tx_queue(qdisc_dev(sch), band))) {
	// 	qdisc = q->queues[band];
	// 	skb = qdisc->dequeue(qdisc);
	// 	if (skb) {
	// 		qdisc_bstats_update(sch, skb);
	// 		sch->q.qlen--;
	// 		return skb;
	// 	}
	// }
	// return NULL;
}

static struct sk_buff *reconfig_peek(struct Qdisc *qdisc)
{
	struct reconfig_sched_data *priv = qdisc_priv(qdisc);
	struct sk_buff *skb = NULL;
	int band = READ_ONCE(priv->curband);

	struct skb_array *q = band2list(priv, band);
	skb = __skb_array_peek(q);

	return skb;
	// struct reconfig_sched_data *q = qdisc_priv(sch);
	// unsigned int curband = q->curband;
	// struct Qdisc *qdisc;
	// struct sk_buff *skb;
	// int band;

	// for (band = 0; band < q->bands; band++) {
	// 	/* cycle through bands to ensure fairness */
	// 	curband++;
	// 	if (curband >= q->bands)
	// 		curband = 0;

	// 	/* Check that target subqueue is available before
	// 	 * pulling an skb to avoid head-of-line blocking.
	// 	 */
	// 	if (!netif_xmit_stopped(
	// 	    netdev_get_tx_queue(qdisc_dev(sch), curband))) {
	// 		qdisc = q->queues[curband];
	// 		skb = qdisc->ops->peek(qdisc);
	// 		if (skb)
	// 			return skb;
	// 	}
	// }
	// return NULL;
	// struct reconfig_sched_data *q = qdisc_priv(sch);
	// struct Qdisc *qdisc;
	// struct sk_buff *skb;
	// int band;

	// band = READ_ONCE(q->curband);

	// if (!netif_xmit_stopped(
	// 	netdev_get_tx_queue(qdisc_dev(sch), band))) {
	// 	qdisc = q->queues[band];
	// 	skb = qdisc->ops->peek(qdisc);
	// 	if (skb)
	// 		return skb;
	// }
	// return NULL;

}

static void
reconfig_reset(struct Qdisc *qdisc)
{
	int i, band;
	struct reconfig_sched_data *priv = qdisc_priv(qdisc);

	for (band = 0; band < RECONFIG_BANDS; band++) {
		struct skb_array *q = band2list(priv, band);
		struct sk_buff *skb;

		/* NULL ring is possible if destroy path is due to a failed
		 * skb_array_init() in pfifo_fast_init() case.
		 */
		if (!q->ring.queue)
			continue;

		while ((skb = __skb_array_consume(q)) != NULL)
			kfree_skb(skb);
	}

	if (qdisc_is_percpu_stats(qdisc)) {
		for_each_possible_cpu(i) {
			struct gnet_stats_queue *q;

			q = per_cpu_ptr(qdisc->cpu_qstats, i);
			q->backlog = 0;
			q->qlen = 0;
		}
	}
}

static void
reconfig_destroy(struct Qdisc *qdisc)
{
	struct reconfig_sched_data *priv = qdisc_priv(qdisc);
	int band;

	for (band = 0; band < RECONFIG_BANDS; band++) {
		struct skb_array *q = band2list(priv, band);

		/* NULL ring is possible if destroy path is due to a failed
		 * skb_array_init() in pfifo_fast_init() case.
		 */
		if (!q->ring.queue)
			continue;
		/* Destroy ring but no need to kfree_skb because a call to
		 * pfifo_fast_reset() has already done that work.
		 */
		ptr_ring_cleanup(&q->ring, NULL);
	}
	kfree(priv->queues);
}

static int reconfig_init(struct Qdisc *qdisc, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	unsigned int qlen = qdisc_dev(qdisc)->tx_queue_len;
	struct reconfig_sched_data *priv = qdisc_priv(qdisc);
	int band;

	/* guard against zero length rings */
	if (!qlen)
		return -EINVAL;

	priv->max_bands = RECONFIG_BANDS;
	priv->curband = 0;
	priv->queues = kmalloc(sizeof(struct skb_array) * (priv->max_bands),
			  GFP_KERNEL);
	priv->stopped = false;
	if (!priv->queues) {
		return -ENOMEM;
	}

	for (band = 0; band < RECONFIG_BANDS; band++) {
		struct skb_array *q = band2list(priv, band);
		int err;

		err = skb_array_init(q, qlen, GFP_KERNEL);
		if (err) {
			kfree(priv->queues);
			return -ENOMEM;
		}
	}

	return 0;
}

static int reconfig_dump(struct Qdisc *qdisc, struct sk_buff *skb)
{
	struct reconfig_sched_data *q = qdisc_priv(qdisc);
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_reconfig_qopt opt;

	opt.max_bands = q->max_bands;
	opt.curband = q->curband;

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int reconfig_change_tx_queue_len(struct Qdisc *qdisc,
					  unsigned int new_len)
{
	struct reconfig_sched_data *priv = qdisc_priv(qdisc);
	struct skb_array *bands[RECONFIG_BANDS];
	int prio;

	for (prio = 0; prio < RECONFIG_BANDS; prio++) {
		struct skb_array *q = band2list(priv, prio);

		bands[prio] = q;
	}

	return skb_array_resize_multiple(bands, RECONFIG_BANDS, new_len,
					 GFP_KERNEL);
}


static struct Qdisc_ops reconfig_qdisc_ops __read_mostly = {
	.id		=	"reconfig",
	.priv_size	=	sizeof(struct reconfig_sched_data),
	.enqueue	=	reconfig_enqueue,
	.dequeue	=	reconfig_dequeue,
	.peek		=	reconfig_peek,
	.init		=	reconfig_init,
	.reset		=	reconfig_reset,
	.destroy	=	reconfig_destroy,
	.dump		=	reconfig_dump,
	.change_tx_queue_len =  reconfig_change_tx_queue_len,
	.owner		=	THIS_MODULE,
	.static_flags	=	TCQ_F_NOLOCK | TCQ_F_CPUSTATS,
};

static int __init reconfig_module_init(void)
{
	return register_qdisc(&reconfig_qdisc_ops);
}

static void __exit reconfig_module_exit(void)
{
	unregister_qdisc(&reconfig_qdisc_ops);
}

module_init(reconfig_module_init)
module_exit(reconfig_module_exit)

MODULE_LICENSE("GPL");
