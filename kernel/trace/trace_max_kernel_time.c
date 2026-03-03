// SPDX-License-Identifier: GPL-2.0
/*
 * trace max kernel time - latency tracer for long kernel execution slices
 *
 * With PREEMPT_LAZY, tasks running in preemptible sections can run for a
 * long time without triggering a softlockup, making it hard to identify
 * kernel code paths that spend an unexpectedly long time on CPU.
 *
 * This tracer implements the two-phase approach suggested by Steven Rostedt:
 *
 *   "The detection can be done with timings between schedules. What's
 *    the longest running task without any voluntary schedule. Then you
 *    can add function graph tracing to it where it can possibly trigger
 *    in the location that detected the issue.
 *    On a detection of a long schedule, a stack trace can be recorded.
 *    Using that stack trace, you could use the function graph tracer to
 *    see what is happening."
 *
 * Phase 1 (detection): Hook trace_sched_switch. On each context switch,
 * measure how long the outgoing task ran on this CPU since it was last
 * scheduled in. When a new maximum is found, record a stack trace and
 * snapshot the ring buffer.
 *
 * Phase 2 (detail): With function graph tracing enabled (via the
 * "display-graph" or "function" trace options), the ring buffer (in
 * OVERWRITE mode) captures the last N function calls before the task
 * yielded. The stack trace from Phase 1 can guide targeted use of
 * set_graph_function for further investigation.
 *
 * Modeled on trace_irqsoff.c and trace_sched_wakeup.c.
 */
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/sched/rt.h>
#include <linux/trace_events.h>
#include <trace/events/sched.h>
#include "trace.h"

static struct trace_array	*mktime_trace;
static int __read_mostly	tracer_enabled;
static int			save_flags;

/*
 * Per-CPU state:
 *   mktime_tracing_cpu - set to 1 while a task is being timed on this CPU
 *   mktime_start_time  - ftrace_now() timestamp from the last switch-in
 */
static DEFINE_PER_CPU(int, mktime_tracing_cpu);
static DEFINE_PER_CPU(u64, mktime_start_time);

static arch_spinlock_t mktime_lock =
	(arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

static bool mktime_busy;

/* Forward declarations */
static void mktime_reset(struct trace_array *tr);
static int start_func_tracer(struct trace_array *tr, int graph);
static void stop_func_tracer(struct trace_array *tr, int graph);

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
# define is_graph(tr) ((tr)->trace_flags & TRACE_ITER(DISPLAY_GRAPH))
#else
# define is_graph(tr) false
#endif

/*
 * report_latency - should this new latency be reported/recorded?
 *
 * If tracing_thresh is set, only record if delta exceeds the threshold.
 * Otherwise record only if delta is a new maximum.
 */
static bool report_latency(struct trace_array *tr, u64 delta)
{
	if (tracing_thresh) {
		if (delta < tracing_thresh)
			return false;
	} else {
		if (delta <= tr->max_latency)
			return false;
	}
	return true;
}

/*
 * Record a context switch event in the trace buffer so the snapshot shows
 * which task was running and what it switched to.
 */
static void
tracing_sched_switch_trace(struct trace_array *tr,
			   struct task_struct *prev,
			   struct task_struct *next,
			   unsigned int trace_ctx)
{
	struct trace_buffer *buffer = tr->array_buffer.buffer;
	struct ring_buffer_event *event;
	struct ctx_switch_entry *entry;

	event = trace_buffer_lock_reserve(buffer, TRACE_CTX,
					  sizeof(*entry), trace_ctx);
	if (!event)
		return;
	entry			= ring_buffer_event_data(event);
	entry->prev_pid		= prev->pid;
	entry->prev_prio	= prev->prio;
	entry->prev_state	= task_state_index(prev);
	entry->next_pid		= next->pid;
	entry->next_prio	= next->prio;
	entry->next_state	= task_state_index(next);
	entry->next_cpu		= task_cpu(next);
	trace_buffer_unlock_commit(tr, buffer, event, trace_ctx);
}

#ifdef CONFIG_FUNCTION_TRACER

static bool function_enabled;

/*
 * Prologue for the max_kernel_time function tracers.
 *
 * Unlike the irqsoff prologue, we do NOT require IRQs disabled or
 * preempt_count > 0. The task being traced runs with IRQs enabled and
 * in fully preemptible code - that is exactly the scenario we care about.
 *
 * Returns 1 (with preemption disabled and data->disabled incremented)
 * if we should trace, 0 otherwise.
 */
static int
func_prolog_mktime(struct trace_array *tr,
		   struct trace_array_cpu **data,
		   unsigned int *trace_ctx)
{
	long disabled;
	int cpu;

	if (likely(!tracer_enabled))
		return 0;

	*trace_ctx = tracing_gen_ctx();
	preempt_disable_notrace();

	cpu = raw_smp_processor_id();
	if (!per_cpu(mktime_tracing_cpu, cpu))
		goto out_enable;

	*data = per_cpu_ptr(tr->array_buffer.data, cpu);
	disabled = local_inc_return(&(*data)->disabled);
	if (unlikely(disabled != 1))
		goto out;

	return 1;

out:
	local_dec(&(*data)->disabled);
out_enable:
	preempt_enable_notrace();
	return 0;
}

#endif /* CONFIG_FUNCTION_TRACER */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

static int mktime_graph_entry(struct ftrace_graph_ent *trace,
			      struct fgraph_ops *gops,
			      struct ftrace_regs *fregs)
{
	struct trace_array *tr = mktime_trace;
	struct trace_array_cpu *data;
	unsigned int trace_ctx;
	u64 *calltime;
	int ret = 0;

	if (ftrace_graph_ignore_func(gops, trace))
		return 0;
	/*
	 * Do not trace a function if it's filtered by set_graph_notrace.
	 * Make the index of ret stack negative to indicate that it should
	 * ignore further functions.  But it needs its own ret stack entry
	 * to recover the original index in order to continue tracing after
	 * returning from the function.
	 */
	if (ftrace_graph_notrace_addr(trace->func))
		return 1;

	if (!func_prolog_mktime(tr, &data, &trace_ctx))
		return 0;

	calltime = fgraph_reserve_data(gops->idx, sizeof(*calltime));
	if (calltime) {
		*calltime = trace_clock_local();
		ret = __trace_graph_entry(tr, trace, trace_ctx);
	}
	local_dec(&data->disabled);
	preempt_enable_notrace();

	return ret;
}

static void mktime_graph_return(struct ftrace_graph_ret *trace,
				struct fgraph_ops *gops,
				struct ftrace_regs *fregs)
{
	struct trace_array *tr = mktime_trace;
	struct trace_array_cpu *data;
	unsigned int trace_ctx;
	u64 *calltime;
	u64 rettime;
	int size;

	ftrace_graph_addr_finish(gops, trace);

	if (!func_prolog_mktime(tr, &data, &trace_ctx))
		return;

	rettime = trace_clock_local();
	calltime = fgraph_retrieve_data(gops->idx, &size);
	if (calltime)
		__trace_graph_return(tr, trace, trace_ctx, *calltime, rettime);

	local_dec(&data->disabled);
	preempt_enable_notrace();
}

static struct fgraph_ops fgraph_mktime_ops = {
	.entryfunc	= &mktime_graph_entry,
	.retfunc	= &mktime_graph_return,
};

static void mktime_trace_open(struct trace_iterator *iter)
{
	if (is_graph(iter->tr))
		graph_trace_open(iter);
}

static void mktime_trace_close(struct trace_iterator *iter)
{
	if (iter->private)
		graph_trace_close(iter);
}

#define GRAPH_TRACER_FLAGS (TRACE_GRAPH_PRINT_PROC | \
			    TRACE_GRAPH_PRINT_CPU  | \
			    TRACE_GRAPH_PRINT_REL_TIME | \
			    TRACE_GRAPH_PRINT_DURATION | \
			    TRACE_GRAPH_PRINT_OVERHEAD | \
			    TRACE_GRAPH_PRINT_IRQS)

static enum print_line_t mktime_print_line(struct trace_iterator *iter)
{
	/*
	 * In graph mode call the graph tracer output function,
	 * otherwise go with the TRACE_FN event handler.
	 */
	if (is_graph(iter->tr))
		return print_graph_function_flags(iter, GRAPH_TRACER_FLAGS);
	return TRACE_TYPE_UNHANDLED;
}

static void mktime_print_header(struct seq_file *s)
{
	if (is_graph(mktime_trace))
		print_graph_headers_flags(s, GRAPH_TRACER_FLAGS);
	else
		trace_default_header(s);
}

static int mktime_display_graph(struct trace_array *tr, int set)
{
	if (!(is_graph(tr) ^ set))
		return 0;

	stop_func_tracer(tr, !set);
	mktime_reset(tr);
	tr->max_latency = 0;

	return start_func_tracer(tr, set);
}

#else /* !CONFIG_FUNCTION_GRAPH_TRACER */

static enum print_line_t mktime_print_line(struct trace_iterator *iter)
{
	return TRACE_TYPE_UNHANDLED;
}
static void mktime_trace_open(struct trace_iterator *iter) { }
static void mktime_trace_close(struct trace_iterator *iter) { }
static void mktime_print_header(struct seq_file *s)
{
	trace_default_header(s);
}
static int mktime_display_graph(struct trace_array *tr, int set)
{
	return -EINVAL;
}

#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

/*
 * __trace_function - record a function call in either graph or flat mode.
 */
static void
__trace_function(struct trace_array *tr,
		 unsigned long ip, unsigned long parent_ip,
		 unsigned int trace_ctx)
{
	if (is_graph(tr))
		trace_graph_function(tr, ip, parent_ip, trace_ctx);
	else
		trace_function(tr, ip, parent_ip, trace_ctx, NULL);
}

#ifdef CONFIG_FUNCTION_TRACER

/*
 * mktime_tracer_call - ftrace hook recording function calls while a task runs.
 *
 * With OVERWRITE mode enabled, the ring buffer always contains the most recent
 * N function calls. When we detect a new maximum run time, the snapshot shows
 * the last N calls the task made before yielding - exactly the code path of
 * interest.
 */
static void
mktime_tracer_call(unsigned long ip, unsigned long parent_ip,
		   struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct trace_array *tr = mktime_trace;
	struct trace_array_cpu *data;
	unsigned int trace_ctx;

	if (!func_prolog_mktime(tr, &data, &trace_ctx))
		return;

	trace_function(tr, ip, parent_ip, trace_ctx, fregs);

	local_dec(&data->disabled);
	preempt_enable_notrace();
}

static int register_mktime_function(struct trace_array *tr, int graph, int set)
{
	int ret;

	/* 'set' is set if TRACE_ITER(FUNCTION) is about to be set */
	if (function_enabled || (!set && !(tr->trace_flags & TRACE_ITER(FUNCTION))))
		return 0;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (graph)
		ret = register_ftrace_graph(&fgraph_mktime_ops);
	else
#endif
		ret = register_ftrace_function(tr->ops);

	if (!ret)
		function_enabled = true;

	return ret;
}

static void unregister_mktime_function(struct trace_array *tr, int graph)
{
	if (!function_enabled)
		return;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (graph)
		unregister_ftrace_graph(&fgraph_mktime_ops);
	else
#endif
		unregister_ftrace_function(tr->ops);

	function_enabled = false;
}

static int mktime_function_set(struct trace_array *tr, u32 mask, int set)
{
	if (!(mask & TRACE_ITER(FUNCTION)))
		return 0;

	if (set)
		register_mktime_function(tr, is_graph(tr), 1);
	else
		unregister_mktime_function(tr, is_graph(tr));
	return 1;
}

#else /* !CONFIG_FUNCTION_TRACER */

static int register_mktime_function(struct trace_array *tr, int graph, int set)
{
	return 0;
}
static void unregister_mktime_function(struct trace_array *tr, int graph) { }
static int mktime_function_set(struct trace_array *tr, u32 mask, int set)
{
	return 0;
}

#endif /* CONFIG_FUNCTION_TRACER */

static int mktime_flag_changed(struct trace_array *tr, u64 mask, int set)
{
	struct tracer *tracer = tr->current_trace;

	if (mktime_function_set(tr, mask, set))
		return 0;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (mask & TRACE_ITER(DISPLAY_GRAPH))
		return mktime_display_graph(tr, set);
#endif

	return trace_keep_overwrite(tracer, mask, set);
}

static int start_func_tracer(struct trace_array *tr, int graph)
{
	int ret;

	ret = register_mktime_function(tr, graph, 0);

	if (!ret && tracing_is_enabled())
		tracer_enabled = 1;
	else
		tracer_enabled = 0;

	return ret;
}

static void stop_func_tracer(struct trace_array *tr, int graph)
{
	tracer_enabled = 0;
	unregister_mktime_function(tr, graph);
}

/*
 * probe_mktime_migrate_task - called when a traced task migrates CPUs.
 *
 * With per-CPU timing, migration naturally ends timing on the source CPU
 * (the next sched_switch on that CPU will measure the partial run) and
 * starts fresh on the destination CPU.  No explicit action needed.
 */
static void
probe_mktime_migrate_task(void *ignore, struct task_struct *task, int cpu)
{
}

/*
 * probe_mktime_sched_switch - main detection probe, called on every switch.
 *
 * On each context switch (prev → next) on a given CPU:
 *
 *  1. Measure how long 'prev' ran since it was last scheduled in.
 *  2. If that duration is a new maximum, snapshot the ring buffer.
 *     The snapshot contains the function call trace (if enabled) and
 *     a stack trace recorded at the moment of the switch - showing
 *     exactly where the long-running task was when it finally yielded.
 *  3. Arm the timer for 'next' so we can measure its run in turn.
 *
 * This fires from inside __schedule() with IRQs disabled and the runqueue
 * lock held, just before context_switch() is called.
 */
static void notrace
probe_mktime_sched_switch(void *ignore, bool preempt,
			  struct task_struct *prev,
			  struct task_struct *next,
			  unsigned int prev_state)
{
	struct trace_array *tr = mktime_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disabled;
	unsigned int trace_ctx;
	u64 T0, T1, delta;
	int cpu;

	tracing_record_cmdline(prev);
	tracing_record_cmdline(next);

	if (unlikely(!tracer_enabled))
		return;

	/*
	 * Ensure per-CPU state written in start_mktime_tracer() is visible
	 * before we read tracer_enabled. Pairs with smp_wmb() there.
	 */
	smp_rmb();

	cpu = raw_smp_processor_id();

	/*
	 * If we weren't tracking this CPU yet (e.g. first switch after
	 * tracer enabled), just arm the next task and return.
	 */
	if (!per_cpu(mktime_tracing_cpu, cpu))
		goto start_next;

	disabled = local_inc_return(
		&per_cpu_ptr(tr->array_buffer.data, cpu)->disabled);
	if (unlikely(disabled != 1))
		goto out;

	local_irq_save(flags);
	trace_ctx = tracing_gen_ctx_flags(flags);

	arch_spin_lock(&mktime_lock);

	/* Re-check under lock to avoid races with tracer teardown */
	if (unlikely(!tracer_enabled))
		goto out_unlock;

	data = per_cpu_ptr(tr->array_buffer.data, cpu);

	T0 = per_cpu(mktime_start_time, cpu);
	T1 = ftrace_now(cpu);
	delta = T1 - T0;

	/*
	 * Record the context switch event and a stack trace in the live
	 * buffer. If this turns out to be a new max, update_max_tr() will
	 * swap this CPU's live buffer into the snapshot, preserving both
	 * the context switch record and the preceding function trace.
	 */
	tracing_sched_switch_trace(tr, prev, next, trace_ctx);
	__trace_stack(tr, trace_ctx, 0);

	if (!report_latency(tr, delta))
		goto out_unlock;

	if (likely(!is_tracing_stopped())) {
		tr->max_latency = delta;
		update_max_tr(tr, prev, cpu, NULL);
	}

out_unlock:
	arch_spin_unlock(&mktime_lock);
	local_irq_restore(flags);

out:
	local_dec(&per_cpu_ptr(tr->array_buffer.data, cpu)->disabled);

start_next:
	/* Stop timing the outgoing task on this CPU */
	per_cpu(mktime_tracing_cpu, cpu) = 0;

	/* Arm timing for the incoming task */
	if (tracer_enabled && tracing_is_enabled()) {
		per_cpu(mktime_start_time, cpu) = ftrace_now(cpu);
		per_cpu(mktime_tracing_cpu, cpu) = 1;
	}
}

static void __mktime_reset(struct trace_array *tr)
{
	/* Nothing task-specific to release */
}

static void mktime_reset(struct trace_array *tr)
{
	unsigned long flags;

	tracing_reset_online_cpus(&tr->array_buffer);

	local_irq_save(flags);
	arch_spin_lock(&mktime_lock);
	__mktime_reset(tr);
	arch_spin_unlock(&mktime_lock);
	local_irq_restore(flags);
}

static void start_mktime_tracer(struct trace_array *tr)
{
	int cpu;

	mktime_reset(tr);

	/*
	 * Clear per-CPU tracing flags before enabling so no CPU starts
	 * measuring from an uninitialized start_time.
	 */
	for_each_possible_cpu(cpu)
		per_cpu(mktime_tracing_cpu, cpu) = 0;

	/* Ensure the above writes are visible before tracer_enabled is set */
	smp_wmb();

	if (start_func_tracer(tr, is_graph(tr)))
		pr_err("max_kernel_time tracer: failed to start function tracer\n");
}

static void stop_mktime_tracer(struct trace_array *tr)
{
	tracer_enabled = 0;
	stop_func_tracer(tr, is_graph(tr));
}

static int mktime_tracer_init(struct trace_array *tr)
{
	int ret;

	if (mktime_busy)
		return -EBUSY;

	save_flags = tr->trace_flags;

	/* non-overwrite mode corrupts latency tracers */
	set_tracer_flag(tr, TRACE_ITER(OVERWRITE), 1);
	set_tracer_flag(tr, TRACE_ITER(LATENCY_FMT), 1);

	tr->max_latency = 0;
	mktime_trace = tr;
	/* Ensure mktime_trace is visible to other CPUs before enabling */
	smp_wmb();

#ifdef CONFIG_FUNCTION_TRACER
	ftrace_init_array_ops(tr, mktime_tracer_call);
#endif

	ret = register_trace_sched_switch(probe_mktime_sched_switch, NULL);
	if (ret) {
		pr_info("max_kernel_time tracer: couldn't register sched_switch probe\n");
		goto err_reset_ops;
	}

	ret = register_trace_sched_migrate_task(probe_mktime_migrate_task, NULL);
	if (ret) {
		pr_info("max_kernel_time tracer: couldn't register migrate_task probe\n");
		goto err_unreg_switch;
	}

	start_mktime_tracer(tr);

	mktime_busy = true;
	return 0;

err_unreg_switch:
	unregister_trace_sched_switch(probe_mktime_sched_switch, NULL);
err_reset_ops:
#ifdef CONFIG_FUNCTION_TRACER
	ftrace_reset_array_ops(tr);
#endif
	set_tracer_flag(tr, TRACE_ITER(LATENCY_FMT),
			save_flags & TRACE_ITER(LATENCY_FMT));
	set_tracer_flag(tr, TRACE_ITER(OVERWRITE),
			save_flags & TRACE_ITER(OVERWRITE));
	return ret;
}

static void mktime_tracer_reset(struct trace_array *tr)
{
	int lat_flag = save_flags & TRACE_ITER(LATENCY_FMT);
	int overwrite_flag = save_flags & TRACE_ITER(OVERWRITE);

	stop_mktime_tracer(tr);

	unregister_trace_sched_switch(probe_mktime_sched_switch, NULL);
	unregister_trace_sched_migrate_task(probe_mktime_migrate_task, NULL);

	mktime_reset(tr);

	set_tracer_flag(tr, TRACE_ITER(LATENCY_FMT), lat_flag);
	set_tracer_flag(tr, TRACE_ITER(OVERWRITE), overwrite_flag);
#ifdef CONFIG_FUNCTION_TRACER
	ftrace_reset_array_ops(tr);
#endif

	mktime_busy = false;
}

static void mktime_tracer_start(struct trace_array *tr)
{
	mktime_reset(tr);
	tracer_enabled = 1;
}

static void mktime_tracer_stop(struct trace_array *tr)
{
	tracer_enabled = 0;
}

static struct tracer max_kernel_time_tracer __read_mostly = {
	.name		= "max_kernel_time",
	.init		= mktime_tracer_init,
	.reset		= mktime_tracer_reset,
	.start		= mktime_tracer_start,
	.stop		= mktime_tracer_stop,
	.print_max	= true,
	.print_header	= mktime_print_header,
	.print_line	= mktime_print_line,
	.flag_changed	= mktime_flag_changed,
	.open		= mktime_trace_open,
	.close		= mktime_trace_close,
	.allow_instances = true,
	.use_max_tr	= true,
};

__init static int init_max_kernel_time_tracer(void)
{
	return register_tracer(&max_kernel_time_tracer);
}
core_initcall(init_max_kernel_time_tracer);
