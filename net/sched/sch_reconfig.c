// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2008, Intel Corporation.
 *
 * Author: Alexander Duyck <alexander.h.duyck@intel.com>
 *         Weiyang Wang <weiyangw@mit.edu>
 * Reconfigurable network aware qdisc, inspired by the design in Mordia.
 * Implementation based on the multiq qdisc
 */

#include <linux/module.h>
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

static inline bool is_ipv4_packet(struct sk_buff *skb) {
	printk("is_ipv4_packet, skb->protocol=%hu\n", skb->protocol);
    return skb->protocol == htons(ETH_P_IP);
}

static struct Qdisc *
reconfig_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
	struct reconfig_sched_data *q = qdisc_priv(sch);
	u32 band;

	band = skb_get_queue_mapping(skb);
	printk("[reconfig] band %hu\n", band);
	if (is_ipv4_packet(skb)) {
		struct iphdr * iphdr = ip_hdr(skb);
		printk("[reconfig] ip dst %x\n", iphdr->daddr);
	} else {
		printk("Dropped packet not IPV4\n");
		return NULL;
	}

	if (band >= q->bands)
		return q->queues[0];

	return q->queues[band];
}

static int
reconfig_enqueue(struct sk_buff *skb, struct Qdisc *sch,
	       struct sk_buff **to_free)
{
	struct Qdisc *qdisc;
	int ret;

	qdisc = reconfig_classify(skb, sch, &ret);

	ret = qdisc_enqueue(skb, qdisc, to_free);
	if (ret == NET_XMIT_SUCCESS) {
		sch->q.qlen++;
		return NET_XMIT_SUCCESS;
	}
	if (net_xmit_drop_count(ret))
		qdisc_qstats_drop(sch);
	return ret;
}

static struct sk_buff *reconfig_dequeue(struct Qdisc *sch)
{
	struct reconfig_sched_data *q = qdisc_priv(sch);
	struct Qdisc *qdisc;
	struct sk_buff *skb;
	int band;

	band = READ_ONCE(q->curband);

	if (!netif_xmit_stopped(
		netdev_get_tx_queue(qdisc_dev(sch), band))) {
		qdisc = q->queues[band];
		skb = qdisc->dequeue(qdisc);
		if (skb) {
			qdisc_bstats_update(sch, skb);
			sch->q.qlen--;
			return skb;
		}
	}
	return NULL;
}

static struct sk_buff *reconfig_peek(struct Qdisc *sch)
{
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
	struct reconfig_sched_data *q = qdisc_priv(sch);
	struct Qdisc *qdisc;
	struct sk_buff *skb;
	int band;

	band = READ_ONCE(q->curband);

	if (!netif_xmit_stopped(
		netdev_get_tx_queue(qdisc_dev(sch), band))) {
		qdisc = q->queues[band];
		skb = qdisc->ops->peek(qdisc);
		if (skb)
			return skb;
	}
	return NULL;

}

static void
reconfig_reset(struct Qdisc *sch)
{
	u16 band;
	struct reconfig_sched_data *q = qdisc_priv(sch);

	for (band = 0; band < q->bands; band++)
		qdisc_reset(q->queues[band]);
}

static void
reconfig_destroy(struct Qdisc *sch)
{
	int band;
	struct reconfig_sched_data *q = qdisc_priv(sch);

	for (band = 0; band < q->bands; band++)
		qdisc_put(q->queues[band]);

	kfree(q->queues);
}

static int reconfig_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct reconfig_sched_data *q = qdisc_priv(sch);
	int i;
	struct Qdisc *child, *old;

	q->queues = NULL;

	if (!opt)
		return -EINVAL;

	q->max_bands = qdisc_dev(sch)->num_tx_queues;
	q->bands = q->max_bands;

	q->queues = kcalloc(q->max_bands, sizeof(struct Qdisc *), GFP_KERNEL);
	if (!q->queues)
		return -ENOBUFS;
	// for (i = 0; i < q->max_bands; i++)
	// 	q->queues[i] = &noop_qdisc;
	// for (i = 0; i < q->bands; i++) {
	// if (q->queues[i] == &noop_qdisc) {
	child = qdisc_create_dflt(sch->dev_queue,
					&pfifo_qdisc_ops,
					TC_H_MAKE(sch->handle,
						i + 1), extack);
	if (child) {
		sch_tree_lock(sch);
		old = q->queues[i];
		q->queues[i] = child;
		if (child != &noop_qdisc)
			qdisc_hash_add(child, true);

		if (old != &noop_qdisc)
			qdisc_purge_queue(old);
		sch_tree_unlock(sch);
		qdisc_put(old);
		// }
		// }
	}
	return 0;
}

static int reconfig_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct reconfig_sched_data *q = qdisc_priv(sch);
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_reconfig_qopt opt;

	opt.bands = q->bands;
	opt.max_bands = q->max_bands;

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}


static struct Qdisc_ops reconfig_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.id		=	"reconfig",
	.priv_size	=	sizeof(struct reconfig_sched_data),
	.enqueue	=	reconfig_enqueue,
	.dequeue	=	reconfig_dequeue,
	.peek		=	reconfig_peek,
	.init		=	reconfig_init,
	.reset		=	reconfig_reset,
	.destroy	=	reconfig_destroy,
	.change		=	reconfig_init,
	.dump		=	reconfig_dump,
	.owner		=	THIS_MODULE,
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
