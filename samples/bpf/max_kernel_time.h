/* SPDX-License-Identifier: GPL-2.0 */
/*
 * max_kernel_time.h - shared types between BPF program and userspace loader
 *
 * Copyright (C) 2026 Steven Rostedt (Google) <rostedt@goodmis.org>
 */
#ifndef __MAX_KERNEL_TIME_H
#define __MAX_KERNEL_TIME_H

#define TASK_COMM_LEN	16
#define IRQ_NAME_LEN	32
#define MAX_STACK_DEPTH	20

/*
 * Four kernel execution paths we detect:
 *
 *  EVENT_SYSCALL  - time from sys_enter to sys_exit
 *  EVENT_IRQ      - time from irq_handler_entry to irq_handler_exit
 *  EVENT_SOFTIRQ  - time from softirq_entry to softirq_exit
 *  EVENT_KTHREAD  - time from sched-in to sched-out for kernel threads
 *
 * Softirqs (NET_RX, TIMER, TASKLET, SCHED, RCU, ...) are a separate
 * deferred context that runs after the hard IRQ handler returns and is
 * NOT covered by irq_handler_entry/exit.
 */
enum event_type {
	EVENT_SYSCALL  = 1,
	EVENT_IRQ      = 2,
	EVENT_SOFTIRQ  = 3,
	EVENT_KTHREAD  = 4,
};

/*
 * softirq vector numbers from <linux/interrupt.h>; repeated here so
 * the userspace binary can name them without a kernel header dependency.
 */
static const char * const softirq_names[] = {
	[0] = "HI",
	[1] = "TIMER",
	[2] = "NET_TX",
	[3] = "NET_RX",
	[4] = "BLOCK",
	[5] = "IRQ_POLL",
	[6] = "TASKLET",
	[7] = "SCHED",
	[8] = "HRTIMER",
	[9] = "RCU",
};
#define NR_SOFTIRQ_NAMES	(sizeof(softirq_names) / sizeof(softirq_names[0]))

/*
 * One event is written to the ring buffer for every threshold violation.
 * The `type` field identifies which path fired; the remaining fields are
 * populated selectively:
 *
 *  SYSCALL  syscall_nr + pid + comm
 *  IRQ      irq_nr + irq_name
 *  SOFTIRQ  softirq_vec
 *  KTHREAD  pid + comm + stack_id (live stack at sched-out)
 */
struct mkt_event {
	__u32	type;		/* enum event_type */
	__u32	cpu;
	__u32	pid;
	__s32	stack_id;	/* valid for KTHREAD; -1 otherwise */
	__u64	duration_ns;
	char	comm[TASK_COMM_LEN];
	__s64	syscall_nr;	/* SYSCALL */
	__s32	irq_nr;		/* IRQ */
	__u32	softirq_vec;	/* SOFTIRQ */
	char	irq_name[IRQ_NAME_LEN]; /* IRQ */
};

#endif /* __MAX_KERNEL_TIME_H */
