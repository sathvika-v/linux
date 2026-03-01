// SPDX-License-Identifier: GPL-2.0
/*
 * trace_max_kernel_time.c - detect long kernel execution slices
 *
 * Hooks only sched_switch. On every context switch two clock reads are
 * compared - that is the entire overhead.  When a slice exceeds
 * tracing_thresh the task name, PID, duration and a stack trace are
 * written to the ring buffer showing exactly where the task was when it
 * finally scheduled out.
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
#include "trace.h"

static struct trace_array *mkt_tr;
static int __read_mostly   mkt_enabled;

/* Per-CPU: which task is being timed and when it started. */
static DEFINE_PER_CPU(struct task_struct *, mkt_task);
static DEFINE_PER_CPU(u64,                  mkt_start);

static void notrace
probe_sched_switch(void *ignore, bool preempt,
		   struct task_struct *prev, struct task_struct *next,
		   unsigned int prev_state)
{
	int cpu = raw_smp_processor_id();
	long disabled;

	if (!mkt_enabled)
		return;

	/*
	 * Use the per-CPU disabled counter to prevent re-entrancy: if a
	 * tracing call made below somehow triggers another sched_switch
	 * probe on this CPU we bail out immediately.
	 */
	disabled = local_inc_return(
		&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
	if (unlikely(disabled != 1))
		goto out;

	if (per_cpu(mkt_task, cpu) == prev && !is_idle_task(prev)) {
		u64 delta = ftrace_now(cpu) - per_cpu(mkt_start, cpu);

		if (tracing_thresh && delta > tracing_thresh) {
			trace_array_printk(mkt_tr, _THIS_IP_,
					   "task: %.16s pid: %d ran for %llu us\n",
					   prev->comm, prev->pid,
					   div_u64(delta, NSEC_PER_USEC));
			__trace_stack(mkt_tr, tracing_gen_ctx(), 0);
		}
	}

	/* Start timing the incoming task; skip idle. */
	per_cpu(mkt_task,  cpu) = is_idle_task(next) ? NULL : next;
	per_cpu(mkt_start, cpu) = ftrace_now(cpu);
out:
	local_dec(&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
}

static void mkt_reset_cpus(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		per_cpu(mkt_task,  cpu) = NULL;
		per_cpu(mkt_start, cpu) = 0;
	}
}

static int mkt_init(struct trace_array *tr)
{
	int ret;

	mkt_tr = tr;
	mkt_reset_cpus();

	ret = register_trace_sched_switch(probe_sched_switch, NULL);
	if (ret) {
		pr_err("max_kernel_time: failed to register sched_switch probe\n");
		return ret;
	}

	mkt_enabled = 1;
	return 0;
}

static void mkt_reset(struct trace_array *tr)
{
	mkt_enabled = 0;
	unregister_trace_sched_switch(probe_sched_switch, NULL);
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
