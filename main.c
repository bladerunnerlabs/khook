#include <linux/kernel.h>
#include <linux/module.h>

#include "khook/engine.c"

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/profile.h>

#include "interceptor/api/process_interceptor.h"

/*******************************************************************************
* Hooking wake_up_new_task
*
* We want to know when a new task begin to run
*
*******************************************************************************/
KHOOK_EXT(void, wake_up_new_task, struct task_struct *p);
static void khook_wake_up_new_task(struct task_struct *p) {
	pid_t pid = task_pid_nr(p);

	printk("%s: pid %d is going to start running, mm 0x%px, active_mm 0x%px\n",
		__func__, pid, p->mm, p->active_mm);
	KHOOK_ORIGIN(wake_up_new_task, p);
	printk("%s: pid %d is running\n", __func__, pid);
}

static void print_clone_flags(const char * prefix, long pid,
								unsigned long flags) {

	printk("%s: pid %ld clone flags: 0x%lx\n", prefix, pid, flags);

	printk("%s: pid %ld clone flag - SIGNAL MASK: 0x%lx\n",
		prefix, pid, flags & CSIGNAL);

	if (flags & CLONE_VM) {
		printk("%s: pid %ld clone flag: CLONE_VM\n",
			prefix, pid);
	}
	if (flags & CLONE_FS) {
		printk("%s: pid %ld clone flag: CLONE_FS\n",
			prefix, pid);
	}
	if (flags & CLONE_FILES) {
		printk("%s: pid %ld clone flag: CLONE_FILES\n",
			prefix, pid);
	}
	if (flags & CLONE_SIGHAND) {
		printk("%s: pid %ld clone flag: CLONE_SIGHAND\n",
			prefix, pid);
	}
	if (flags & CLONE_PTRACE) {
		printk("%s: pid %ld clone flag: CLONE_PTRACE\n",
			prefix, pid);
	}
	if (flags & CLONE_VFORK) {
		printk("%s: pid %ld clone flag: CLONE_VFORK\n",
			prefix, pid);
	}
	if (flags & CLONE_PARENT) {
		printk("%s: pid %ld clone flag: CLONE_PARENT\n",
			prefix, pid);
	}
	if (flags & CLONE_THREAD) {
		printk("%s: pid %ld clone flag: CLONE_THREAD\n",
			prefix, pid);
	}
	if (flags & CLONE_NEWNS) {
		printk("%s: pid %ld clone flag: CLONE_NEWNS\n",
			prefix, pid);
	}
	if (flags & CLONE_SYSVSEM) {
		printk("%s: pid %ld clone flag: CLONE_SYSVSEM\n",
			prefix, pid);
	}
	if (flags & CLONE_SETTLS) {
		printk("%s: pid %ld clone flag: CLONE_SETTLS\n",
			prefix, pid);
	}
	if (flags & CLONE_PARENT_SETTID) {
		printk("%s: pid %ld clone flag: CLONE_PARENT_SETTID\n",
			prefix, pid);
	}
	if (flags & CLONE_CHILD_CLEARTID) {
		printk("%s: pid %ld clone flag: CLONE_CHILD_CLEARTID\n",
			prefix, pid);
	}
	if (flags & CLONE_DETACHED) {
		printk("%s: pid %ld clone flag: CLONE_DETACHED\n",
			prefix, pid);
	}
	if (flags & CLONE_UNTRACED) {
		printk("%s: pid %ld clone flag: CLONE_UNTRACED\n",
			prefix, pid);
	}
	if (flags & CLONE_CHILD_SETTID) {
		printk("%s: pid %ld clone flag: CLONE_CHILD_SETTID\n",
			prefix, pid);
	}
	if (flags & CLONE_NEWCGROUP) {
		printk("%s: pid %ld clone flag: CLONE_NEWCGROUP\n",
			prefix, pid);
	}
	if (flags & CLONE_NEWUTS) {
		printk("%s: pid %ld clone flag: CLONE_NEWUTS\n",
			prefix, pid);
	}
	if (flags & CLONE_NEWIPC) {
		printk("%s: pid %ld clone flag: CLONE_NEWIPC\n",
			prefix, pid);
	}
	if (flags & CLONE_NEWUSER) {
		printk("%s: pid %ld clone flag: CLONE_NEWUSER\n",
			prefix, pid);
	}
	if (flags & CLONE_NEWPID) {
		printk("%s: pid %ld clone flag: CLONE_NEWPID\n",
			prefix, pid);
	}
	if (flags & CLONE_NEWNET) {
		printk("%s: pid %ld clone flag: CLONE_NEWNET\n",
			prefix, pid);
	}
	if (flags & CLONE_IO) {
		printk("%s: pid %ld clone flag: CLONE_IO\n",
			prefix, pid);
	}
}

/*******************************************************************************
* Hooking _do_fork
*
* It looks that several syscalls related to process creation eventually call
* __do_fork. Therefore it is better to hook it rather than individual syscalls.
*
*******************************************************************************/

KHOOK_EXT(long, _do_fork, unsigned long clone_flags,
							unsigned long stack_start,
							unsigned long stack_size,
							int __user *parent_tidptr,
							int __user *child_tidptr,
							unsigned long tls);
static long khook__do_fork(unsigned long clone_flags,
							unsigned long stack_start, unsigned long stack_size,
							int __user *parent_tidptr, int __user *child_tidptr,
							unsigned long tls) {
	long ret = 0;
	unsigned long flags = clone_flags;

	printk("%s: new pid will be created with flags 0x%lx\n", __func__, flags);

	ret = KHOOK_ORIGIN(_do_fork, clone_flags, stack_start, stack_size,
		parent_tidptr, child_tidptr, tls);

	printk("%s: parent executable %s, pid %ld\n", __func__, current->comm, ret);
	if (ret) {
		print_clone_flags(__func__, ret, flags);
	}

	return ret;
}

/*******************************************************************************
* Hooking profile_task_exit
*
* Hooking process termination. Hooking do_exit is problematic, therefore hooking
* profile_task_exit that is called from do_exit looks like a better solution.
*******************************************************************************/
KHOOK_EXT(void, profile_task_exit, struct task_struct *task);
static void khook_profile_task_exit(struct task_struct *task) {
	pid_t pid = task_pid_nr(task);

	printk("%s: pid %d is going to die...\n", __func__, pid);
	KHOOK_ORIGIN(profile_task_exit, task);
}

/*******************************************************************************
* Hooking load_elf_binary
*
* We are going to get executable name and additional information here after elf
* is loaded. Some of this useful info can be VM_AREAs of the task.
*******************************************************************************/

#include <linux/binfmts.h>

KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
	int ret = 0;
	pid_t pid = task_pid_nr(current);

	printk("%s: Pre load_elf_binary: pid %d, filename %s, real file name %s\n",
		__func__, pid, bprm->filename, bprm->interp);
	ret = KHOOK_ORIGIN(load_elf_binary, bprm);
	printk("%s: Post load_elf_binary: pid %d, return %d\n", __func__, pid, ret);

	/* Worth also looking into bprm->vma_pages and  bprm->vma */

	return ret;
}

int init_module(void)
{
	return khook_init();
}

void cleanup_module(void)
{
	khook_cleanup();
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hooking processes creation and termination");
MODULE_AUTHOR("Yan Vugenfirer <yan@bladerunner.io> based on work by Ilya V. Matveychikov");
