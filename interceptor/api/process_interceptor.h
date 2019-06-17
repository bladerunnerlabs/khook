#ifndef PROCESS_INTERCEPTOR_H
#define PROCESS_INTERCEPTOR_H

#include <linux/sched.h>
#include <linux/fs.h>

/* Function pointers definition to be used with process_interceptor_ops */
typedef void (pre__do_fork_fn)(unsigned long flags);
typedef void (post__do_fork_fn)(pid_t pid, unsigned long flags, char *comm);
typedef void (pre_load_elf_binary_fn)(pid_t pid, struct linux_binprm *bprm);
typedef void (post_load_elf_binary_fn)(pid_t pid, struct linux_binprm *bprm,
	int ret);
typedef void (pre_wake_up_new_task_fn)(pid_t pid, void *mm, void *active_mm);
typedef void (post_wake_up_new_task_fn)(pid_t pid, void *mm, void *active_mm);
typedef void (exit_task_fn)(pid_t pid);

/* process_interceptor_ops should be populated by the caller of the
   process_interceptor_init function.
   The callbacks will be called from hooks.
*/

struct process_interceptor_ops {
	pre__do_fork_fn *pre__do_fork;
	post__do_fork_fn *post__do_fork;

	pre_load_elf_binary_fn *pre_load_elf_binary;
	post_load_elf_binary_fn *post_load_elf_binary;

	pre_wake_up_new_task_fn *pre_wake_up_new_task;
	post_wake_up_new_task_fn *post_wake_up_new_task;

	exit_task_fn *exit_task;	/*Will be called in the hook of profile_task_exit
								which is called from do_exit */
};

void process_interceptor_init(struct process_interceptor_ops *ops);
void process_interceptor_destroy();

#endif /* PROCESS_INTERCEPTOR_H */