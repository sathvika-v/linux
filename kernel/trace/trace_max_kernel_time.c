// SPDX-License-Identifier: GPL-2.0
/*
 * trace_max_kernel_time.c - detect long kernel execution slices
 *
 * Phase 1 (detection, cheap):
 *   Only the sched_switch hook is active. On every context switch two
 *   clock reads are compared - that is the entire overhead. No function
 *   tracing runs during this phase. When a slice exceeds tracing_thresh
 *   a stack trace is written to the ring buffer showing exactly where
 *   the task was when it finally scheduled out.
 *
 * Phase 2 (targeted graph, automatic):
 *   The same stack IPs are saved into an array and a workqueue handler
 *   arms function-graph for exactly those functions. On the next
 *   occurrence the graph tracer records the full call tree with
 *   per-function timing, without ever having traced anything in Phase 1.
 *
 * Usage:
 *   echo max_kernel_time > /sys/kernel/tracing/current_tracer
 *   echo 1000            > /sys/kernel/tracing/tracing_thresh  # us
 *   cat /sys/kernel/tracing/trace
 *
 * To reset and catch the next offender:
 *   echo 0 > /sys/kernel/tracing/tracing_max_latency
 *
 * Copyright (C) 2026 Steven Rostedt (Google) <rostedt@goodmis.org>
 */
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/ftrace.h>
#include <linux/stacktrace.h>
#include <linux/sched/task.h>
#include <trace/events/sched.h>
#include "trace.h"

static struct trace_array	*mkt_tr;
static int __read_mostly	 mkt_enabled;

/* Per-CPU: which task is being timed and when it started. */
static DEFINE_PER_CPU(struct task_struct *, mkt_task);
static DEFINE_PER_CPU(u64,                  mkt_start);

/* ------------------------------------------------------------------ */
/* Phase 2: function-graph on the detected call path                   */
/* ------------------------------------------------------------------ */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
# define is_graph(tr)	((tr)->trace_flags & TRACE_ITER(DISPLAY_GRAPH))
#else
# define is_graph(tr)	false
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

#define DETECT_DEPTH	8

static unsigned long	detect_ips[DETECT_DEPTH];
static int		detect_nr;

static int mkt_graph_entry(struct ftrace_graph_ent *trace,
			   struct fgraph_ops *gops,
			   struct ftrace_regs *fregs)
{
	unsigned int trace_ctx;
	u64 *calltime;

	if (ftrace_graph_ignore_func(gops, trace))
		return 0;
	if (ftrace_graph_notrace_addr(trace->func))
		return 1;

	trace_ctx = tracing_gen_ctx();
	calltime = fgraph_reserve_data(gops->idx, sizeof(*calltime));
	if (calltime) {
		*calltime = trace_clock_local();
		__trace_graph_entry(mkt_tr, trace, trace_ctx);
	}
	return 1;
}

static void mkt_graph_return(struct ftrace_graph_ret *trace,
			     struct fgraph_ops *gops,
			     struct ftrace_regs *fregs)
{
	u64 rettime = trace_clock_local();
	unsigned int trace_ctx;
	u64 *calltime;
	int size;

	ftrace_graph_addr_finish(gops, trace);
	trace_ctx = tracing_gen_ctx();
	calltime = fgraph_retrieve_data(gops->idx, &size);
	if (calltime)
		__trace_graph_return(mkt_tr, trace, trace_ctx,
				     *calltime, rettime);
}

static struct fgraph_ops mkt_fgraph_ops = {
	.entryfunc = mkt_graph_entry,
	.retfunc   = mkt_graph_return,
};

#define GRAPH_FLAGS (TRACE_GRAPH_PRINT_PROC | TRACE_GRAPH_PRINT_CPU |		\
		     TRACE_GRAPH_PRINT_REL_TIME | TRACE_GRAPH_PRINT_DURATION |	\
		     TRACE_GRAPH_PRINT_OVERHEAD | TRACE_GRAPH_PRINT_IRQS)

static void mkt_trace_open(struct trace_iterator *iter)
{
	if (is_graph(iter->tr))
		graph_trace_open(iter);
}

static void mkt_trace_close(struct trace_iterator *iter)
{
	if (iter->private)
		graph_trace_close(iter);
}

static enum print_line_t mkt_print_line(struct trace_iterator *iter)
{
	if (is_graph(iter->tr))
		return print_graph_function_flags(iter, GRAPH_FLAGS);
	return TRACE_TYPE_UNHANDLED;
}

static void mkt_print_header(struct seq_file *s)
{
	if (mkt_tr && is_graph(mkt_tr))
		print_graph_headers_flags(s, GRAPH_FLAGS);
	else
		trace_default_header(s);
}

/*
 * do_arm_graph - workqueue handler for Phase 2 setup
 *
 * Runs in process context after a long slice is detected.  Resets the
 * graph entry-filter, repopulates it with every IP from the detected
 * stack, then registers the fgraph ops so the next call to any of
 * those functions produces a full call-tree trace.
 */
static void do_arm_graph(struct work_struct *work)
{
	int i;

	if (!mkt_tr || !mkt_enabled)
		return;

	ftrace_set_filter_ip(&mkt_fgraph_ops.ops, 0, 0, 1); /* reset */
	for (i = 0; i < detect_nr; i++)
		if (detect_ips[i])
			ftrace_set_filter_ip(&mkt_fgraph_ops.ops,
					     detect_ips[i], 0, 0);

	set_tracer_flag(mkt_tr, TRACE_ITER(DISPLAY_GRAPH), 1);
	register_ftrace_graph(&mkt_fgraph_ops);
}

static DECLARE_WORK(arm_graph_work, do_arm_graph);

static void disarm_graph(void)
{
	cancel_work_sync(&arm_graph_work);
	unregister_ftrace_graph(&mkt_fgraph_ops);
	if (mkt_tr)
		set_tracer_flag(mkt_tr, TRACE_ITER(DISPLAY_GRAPH), 0);
	detect_nr = 0;
}

#else /* !CONFIG_FUNCTION_GRAPH_TRACER */

static void mkt_trace_open(struct trace_iterator *iter) {}
static void mkt_trace_close(struct trace_iterator *iter) {}

static enum print_line_t mkt_print_line(struct trace_iterator *iter)
{
	return TRACE_TYPE_UNHANDLED;
}

static void mkt_print_header(struct seq_file *s)
{
	trace_default_header(s);
}

static void disarm_graph(void) {}

#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

/* ------------------------------------------------------------------ */
/* Phase 1: sched_switch timing                                        */
/* ------------------------------------------------------------------ */

static void notrace
probe_sched_switch(void *ignore, bool preempt,
		   struct task_struct *prev, struct task_struct *next,
		   unsigned int prev_state)
{
	int cpu = raw_smp_processor_id();
	bool need_arm = false;
	long disabled;

	if (!mkt_enabled)
		return;

	/*
	 * Use the per-CPU disabled counter to avoid re-entrancy if
	 * function-graph (Phase 2) happens to call back here.
	 */
	disabled = local_inc_return(
		&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);
	if (unlikely(disabled != 1))
		goto out_dec;

	if (per_cpu(mkt_task, cpu) == prev && !is_idle_task(prev)) {
		u64 delta = ftrace_now(cpu) - per_cpu(mkt_start, cpu);

		if (tracing_thresh && delta > tracing_thresh) {
			/*
			 * Record where the task was when it finally scheduled
			 * out - this is the "detected location" the user (or
			 * the auto-arm path below) uses to identify the culprit.
			 */
			__trace_stack(mkt_tr, tracing_gen_ctx(), 0);

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
			/*
			 * Save the call stack and schedule work to configure
			 * function-graph for those exact functions.  detect_nr
			 * going non-zero guards against arming more than once
			 * per detection cycle.
			 */
			if (!detect_nr) {
				detect_nr = stack_trace_save(
					detect_ips, ARRAY_SIZE(detect_ips), 0);
				need_arm = true;
			}
#endif
		}
	}

	/* Start timing the incoming task; skip idle. */
	per_cpu(mkt_task,  cpu) = is_idle_task(next) ? NULL : next;
	per_cpu(mkt_start, cpu) = ftrace_now(cpu);

out_dec:
	local_dec(&per_cpu_ptr(mkt_tr->array_buffer.data, cpu)->disabled);

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (need_arm)
		schedule_work(&arm_graph_work);
#endif
}

/* ------------------------------------------------------------------ */
/* Tracer registration                                                 */
/* ------------------------------------------------------------------ */

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
	disarm_graph();
	mkt_reset_cpus();
	mkt_tr = NULL;
}

static struct tracer max_kernel_time_tracer __read_mostly = {
	.name		 = "max_kernel_time",
	.init		 = mkt_init,
	.reset		 = mkt_reset,
	.print_header    = mkt_print_header,
	.print_line      = mkt_print_line,
	.open		 = mkt_trace_open,
	.close		 = mkt_trace_close,
	.allow_instances = true,
};

__init static int init_max_ktime_tracer(void)
{
	return register_tracer(&max_kernel_time_tracer);
}
core_initcall(init_max_ktime_tracer);
