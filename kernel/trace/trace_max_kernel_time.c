// SPDX-License-Identifier: GPL-2.0
/*
 * trace_max_kernel_time.c - detect long kernel execution paths
 *
 * Tracks time spent in the three ways a task executes kernel code:
 *
 *   1. Syscalls     - sys_enter  to sys_exit
 *   2. IRQ handlers - irq_handler_entry to irq_handler_exit
 *   3. Kthreads     - sched_switch in  to sched_switch out
 *
 * Measuring only sched_switch in/out for all tasks would be wrong:
 * a task in R state running in userspace also context-switches, so
 * that approach conflates kernel time with user time.
 *
 * For cases 1 and 2 the ring buffer records the duration plus the
 * syscall number or IRQ name.  A stack trace at the exit point of a
 * syscall or IRQ is not useful because the work has already finished
 * by then.
 *
 * For case 3 the task is still on-CPU at sched_switch time, so a live
 * stack trace IS captured and shows exactly where the kthread was when
 * it finally got switched out.
 *
 * Usage:
 *   echo max_kernel_time > /sys/kernel/tracing/current_tracer
 *   echo 1000            > /sys/kernel/tracing/tracing_thresh   # us
 *   cat  /sys/kernel/tracing/trace
 *
 * Copyright (C) 2026 Steven Rostedt (Google) <rostedt@goodmis.org>
 */
#include <linux/ftrace.h>
#include <trace/events/sched.h>
#include <trace/events/irq.h>
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
#include <trace/events/syscalls.h>
#endif
#include "trace.h"

static struct trace_array *mkt_tr;
static int __read_mostly   mkt_enabled;

/* ---------------------------------------------------------------
 * 1. Syscall tracking
 *
 * Per-CPU storage is safe: only one task runs on a CPU at a time,
 * and syscalls cannot be nested.
 * --------------------------------------------------------------- */
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
static DEFINE_PER_CPU(u64,  syscall_start);
static DEFINE_PER_CPU(long, syscall_id);

static void notrace
probe_sys_enter(void *ignore, struct pt_regs *regs, long id)
{
	int cpu = raw_smp_processor_id();

	if (!mkt_enabled)
		return;

	per_cpu(syscall_id,    cpu) = id;
	per_cpu(syscall_start, cpu) = ftrace_now(cpu);
}

static void notrace
probe_sys_exit(void *ignore, struct pt_regs *regs, long ret)
{
	int cpu = raw_smp_processor_id();
	u64 start, delta;
	long disabled;

	if (!mkt_enabled)
		return;

	start = per_cpu(syscall_start, cpu);
	if (!start)
		return;

	delta = ftrace_now(cpu) - start;
	per_cpu(syscall_start, cpu) = 0;

	if (!tracing_thresh || delta <= tracing_thresh)
		return;

	/*
	 * A stack trace here would show only the syscall return path,
	 * not where the time was spent.  Record the duration and syscall
	 * number so the user knows which syscall was slow.
	 */
	disabled = local_inc_return(
		&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
	if (likely(disabled == 1))
		trace_array_printk(mkt_tr, _THIS_IP_,
				   "syscall: %.16s pid: %d nr: %ld ran for %llu us\n",
				   current->comm, current->pid,
				   per_cpu(syscall_id, cpu),
				   div_u64(delta, NSEC_PER_USEC));
	local_dec(&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
}
#endif /* CONFIG_HAVE_SYSCALL_TRACEPOINTS */

/* ---------------------------------------------------------------
 * 2. IRQ handler tracking
 *
 * IRQ handlers can be nested (an IRQ preempting another IRQ).
 * Track depth so we time only the outermost handler; inner ones
 * are accounted for within the outer window.
 * --------------------------------------------------------------- */
static DEFINE_PER_CPU(u64, irq_start);
static DEFINE_PER_CPU(int, irq_depth);

static void notrace
probe_irq_handler_entry(void *ignore, int irq, struct irqaction *action)
{
	int cpu = raw_smp_processor_id();

	if (!mkt_enabled)
		return;

	per_cpu(irq_depth, cpu)++;
	if (per_cpu(irq_depth, cpu) == 1)
		per_cpu(irq_start, cpu) = ftrace_now(cpu);
}

static void notrace
probe_irq_handler_exit(void *ignore, int irq, struct irqaction *action,
		       int ret)
{
	int cpu = raw_smp_processor_id();
	u64 delta;
	long disabled;

	if (!mkt_enabled)
		return;

	per_cpu(irq_depth, cpu)--;
	if (per_cpu(irq_depth, cpu) != 0)
		return;

	delta = ftrace_now(cpu) - per_cpu(irq_start, cpu);

	if (!tracing_thresh || delta <= tracing_thresh)
		return;

	/*
	 * Same limitation as syscalls: at exit the handler has returned,
	 * so a stack trace shows only the return path.  Record the IRQ
	 * number and handler name so the user knows which handler was slow.
	 */
	disabled = local_inc_return(
		&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
	if (likely(disabled == 1))
		trace_array_printk(mkt_tr, _THIS_IP_,
				   "irq: %d (%s) ran for %llu us\n",
				   irq, action->name,
				   div_u64(delta, NSEC_PER_USEC));
	local_dec(&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
}

/* ---------------------------------------------------------------
 * 3. Kthread tracking via sched_switch
 *
 * Kernel threads (task->mm == NULL) only ever run in kernel space,
 * so measuring their full scheduled slice IS measuring kernel time.
 * At sched_switch the kthread is still on-CPU, so __trace_stack()
 * captures a live, meaningful call chain.
 * --------------------------------------------------------------- */
static DEFINE_PER_CPU(struct task_struct *, kthread_task);
static DEFINE_PER_CPU(u64,                  kthread_start);

static void notrace
probe_sched_switch(void *ignore, bool preempt,
		   struct task_struct *prev, struct task_struct *next,
		   unsigned int prev_state)
{
	int cpu = raw_smp_processor_id();
	long disabled;

	if (!mkt_enabled)
		return;

	disabled = local_inc_return(
		&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
	if (unlikely(disabled != 1))
		goto out;

	/* Check the outgoing kthread. */
	if (per_cpu(kthread_task, cpu) == prev && !prev->mm) {
		u64 delta = ftrace_now(cpu) - per_cpu(kthread_start, cpu);

		if (tracing_thresh && delta > tracing_thresh) {
			trace_array_printk(mkt_tr, _THIS_IP_,
					   "kthread: %.16s pid: %d ran for %llu us\n",
					   prev->comm, prev->pid,
					   div_u64(delta, NSEC_PER_USEC));
			/* prev is still on-CPU: stack trace is meaningful. */
			__trace_stack(mkt_tr, tracing_gen_ctx(), 0);
		}
	}

	/* Start timing the incoming task if it is a kthread; skip idle. */
	if (!next->mm && !is_idle_task(next)) {
		per_cpu(kthread_task,  cpu) = next;
		per_cpu(kthread_start, cpu) = ftrace_now(cpu);
	} else {
		per_cpu(kthread_task, cpu) = NULL;
	}
out:
	local_dec(&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
}

/* --------------------------------------------------------------- */

static void mkt_reset_cpus(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
		per_cpu(syscall_start, cpu) = 0;
		per_cpu(syscall_id,    cpu) = 0;
#endif
		per_cpu(irq_start,     cpu) = 0;
		per_cpu(irq_depth,     cpu) = 0;
		per_cpu(kthread_task,  cpu) = NULL;
		per_cpu(kthread_start, cpu) = 0;
	}
}

static int mkt_init(struct trace_array *tr)
{
	int ret;

	mkt_tr = tr;
	mkt_reset_cpus();

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
	ret = register_trace_sys_enter(probe_sys_enter, NULL);
	if (ret)
		goto err_sys_enter;

	ret = register_trace_sys_exit(probe_sys_exit, NULL);
	if (ret)
		goto err_sys_exit;
#endif

	ret = register_trace_irq_handler_entry(probe_irq_handler_entry, NULL);
	if (ret)
		goto err_irq_entry;

	ret = register_trace_irq_handler_exit(probe_irq_handler_exit, NULL);
	if (ret)
		goto err_irq_exit;

	ret = register_trace_sched_switch(probe_sched_switch, NULL);
	if (ret)
		goto err_sched;

	mkt_enabled = 1;
	return 0;

err_sched:
	unregister_trace_irq_handler_exit(probe_irq_handler_exit, NULL);
err_irq_exit:
	unregister_trace_irq_handler_entry(probe_irq_handler_entry, NULL);
err_irq_entry:
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
	unregister_trace_sys_exit(probe_sys_exit, NULL);
err_sys_exit:
	unregister_trace_sys_enter(probe_sys_enter, NULL);
err_sys_enter:
#endif
	mkt_tr = NULL;
	return ret;
}

static void mkt_reset(struct trace_array *tr)
{
	mkt_enabled = 0;
	unregister_trace_sched_switch(probe_sched_switch, NULL);
	unregister_trace_irq_handler_exit(probe_irq_handler_exit, NULL);
	unregister_trace_irq_handler_entry(probe_irq_handler_entry, NULL);
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
	unregister_trace_sys_exit(probe_sys_exit, NULL);
	unregister_trace_sys_enter(probe_sys_enter, NULL);
#endif
	mkt_reset_cpus();
	mkt_tr = NULL;
}

static struct tracer max_kernel_time_tracer __read_mostly = {
	.name		 = "max_kernel_time",
	.init		 = mkt_init,
	.reset		 = mkt_reset,
	.allow_instances = true,
};

__init static int init_max_ktime_tracer(void)
{
	return register_tracer(&max_kernel_time_tracer);
}
core_initcall(init_max_ktime_tracer);
