// SPDX-License-Identifier: GPL-2.0
/*
 * max_kernel_time.bpf.c - detect long kernel execution paths
 *
 * Implements the approach suggested by Shrikanth Hegde:
 * track the three kernel entry/exit points (syscalls, IRQ handlers,
 * kworker/kthreads) plus softirqs which are a distinct deferred
 * execution context not covered by irq_handler_entry/exit.
 *
 * Path 1 - Syscalls:
 *   raw_tracepoint/sys_enter -> raw_tracepoint/sys_exit
 *   Reports task name, PID and syscall number.  A stack at sys_exit
 *   is not useful because the work is done; duration alone identifies
 *   which syscall was slow.
 *
 * Path 2 - Hard IRQ handlers:
 *   tp_btf/irq_handler_entry -> tp_btf/irq_handler_exit
 *   Reports IRQ number and handler name.  Depth-tracked so that
 *   re-raised IRQs do not corrupt the outer window's start time.
 *
 * Path 3 - Softirqs:
 *   tp_btf/softirq_entry -> tp_btf/softirq_exit
 *   Reports softirq vector (NET_RX, TIMER, TASKLET, SCHED, RCU, ...).
 *   Depth-tracked for the same reason as IRQs.
 *
 * Path 4 - Kernel threads (task->mm == NULL):
 *   tp_btf/sched_switch (in) -> tp_btf/sched_switch (out)
 *   Records a live stack trace at sched-out time because the kthread
 *   is still on-CPU at that point.  This is the only path where a
 *   meaningful stack is available.
 *
 * Usage:
 *   # build:  make -C samples/bpf
 *   # run:    ./max_kernel_time [-t threshold_us]
 *
 * Copyright (C) 2026 Steven Rostedt (Google) <rostedt@goodmis.org>
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "max_kernel_time.h"

/*
 * Threshold in nanoseconds.  Userspace sets this via the
 * `const volatile` trick before loading so the verifier can treat it
 * as a known constant and dead-code-eliminate the fast path.
 */
const volatile __u64 thresh_ns = 1000000ULL; /* 1 ms default */

/* ---------------------------------------------------------------
 * Per-CPU context structs (internal, not shared with userspace).
 *
 * BPF_MAP_TYPE_PERCPU_ARRAY with max_entries=1: bpf_map_lookup_elem
 * returns a pointer to the *current CPU's* copy of the value.
 * No explicit CPU indexing is needed.
 * --------------------------------------------------------------- */
struct syscall_ctx {
	__u64	start;
	__s64	nr;
};

struct irq_ctx {
	__u64	start;
	__s32	depth;
	__s32	irq;
	char	irq_name[IRQ_NAME_LEN];
};

struct softirq_ctx {
	__u64	start;
	__s32	depth;
	__u32	vec;
};

struct kthread_ctx {
	__u64	start;
	__u32	pid;
	__u32	pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct syscall_ctx);
} syscall_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct irq_ctx);
} irq_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct softirq_ctx);
} softirq_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kthread_ctx);
} kthread_map SEC(".maps");

/* Stack traces captured at kthread sched-out. */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

/* Ring buffer: BPF writes events, userspace reads them. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

/* ---------------------------------------------------------------
 * Path 1: Syscalls
 *
 * raw_tracepoint/sys_enter args:
 *   args[0] = (unsigned long) struct pt_regs *
 *   args[1] = (unsigned long) syscall id
 *
 * raw_tracepoint/sys_exit args:
 *   args[0] = (unsigned long) struct pt_regs *
 *   args[1] = (unsigned long) return value
 * --------------------------------------------------------------- */
SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 key = 0;
	struct syscall_ctx *sc = bpf_map_lookup_elem(&syscall_map, &key);

	if (!sc)
		return 0;

	sc->start = bpf_ktime_get_ns();
	sc->nr    = (__s64)ctx->args[1];
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 key = 0;
	struct syscall_ctx *sc = bpf_map_lookup_elem(&syscall_map, &key);
	struct mkt_event *e;
	__u64 delta;

	if (!sc || !sc->start)
		return 0;

	delta     = bpf_ktime_get_ns() - sc->start;
	sc->start = 0;

	if (delta <= thresh_ns)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type        = EVENT_SYSCALL;
	e->duration_ns = delta;
	e->pid         = bpf_get_current_pid_tgid() & 0xffffffff;
	e->cpu         = bpf_get_smp_processor_id();
	e->stack_id    = -1;
	e->syscall_nr  = sc->nr;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------------------------------------------------------
 * Path 2: Hard IRQ handlers
 *
 * tp_btf gives us fully typed access to the tracepoint args:
 *   irq_handler_entry(int irq, struct irqaction *action)
 *   irq_handler_exit (int irq, struct irqaction *action, int ret)
 *
 * Depth counter handles the case where a hard IRQ preempts another
 * hard IRQ; only the outermost window is timed.
 * --------------------------------------------------------------- */
SEC("tp_btf/irq_handler_entry")
int BPF_PROG(handle_irq_entry, int irq, struct irqaction *action)
{
	__u32 key = 0;
	struct irq_ctx *ic = bpf_map_lookup_elem(&irq_map, &key);

	if (!ic)
		return 0;

	ic->depth++;
	if (ic->depth == 1) {
		ic->start = bpf_ktime_get_ns();
		ic->irq   = irq;
		bpf_probe_read_kernel_str(ic->irq_name, sizeof(ic->irq_name),
					  BPF_CORE_READ(action, name));
	}
	return 0;
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(handle_irq_exit, int irq, struct irqaction *action, int ret)
{
	__u32 key = 0;
	struct irq_ctx *ic = bpf_map_lookup_elem(&irq_map, &key);
	struct mkt_event *e;
	__u64 delta;

	if (!ic || ic->depth == 0)
		return 0;

	ic->depth--;
	if (ic->depth != 0)
		return 0;

	delta = bpf_ktime_get_ns() - ic->start;
	if (delta <= thresh_ns)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type        = EVENT_IRQ;
	e->duration_ns = delta;
	e->cpu         = bpf_get_smp_processor_id();
	e->pid         = 0;
	e->stack_id    = -1;
	e->irq_nr      = ic->irq;
	__builtin_memcpy(e->irq_name, ic->irq_name, IRQ_NAME_LEN);
	e->comm[0]     = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------------------------------------------------------
 * Path 3: Softirqs
 *
 * tp_btf/softirq_entry and tp_btf/softirq_exit both take a single
 * argument: unsigned int vec_nr.
 *
 * Softirqs (NET_RX, TIMER, TASKLET, SCHED, RCU ...) are a deferred
 * execution context raised by hard IRQ handlers and run after the
 * handler returns.  They are NOT covered by irq_handler_entry/exit
 * and were the most significant path missing from Shrikanth's original
 * proposal.
 * --------------------------------------------------------------- */
SEC("tp_btf/softirq_entry")
int BPF_PROG(handle_softirq_entry, unsigned int vec_nr)
{
	__u32 key = 0;
	struct softirq_ctx *sc = bpf_map_lookup_elem(&softirq_map, &key);

	if (!sc)
		return 0;

	sc->depth++;
	if (sc->depth == 1) {
		sc->start = bpf_ktime_get_ns();
		sc->vec   = vec_nr;
	}
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(handle_softirq_exit, unsigned int vec_nr)
{
	__u32 key = 0;
	struct softirq_ctx *sc = bpf_map_lookup_elem(&softirq_map, &key);
	struct mkt_event *e;
	__u64 delta;

	if (!sc || sc->depth == 0)
		return 0;

	sc->depth--;
	if (sc->depth != 0)
		return 0;

	delta = bpf_ktime_get_ns() - sc->start;
	if (delta <= thresh_ns)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type        = EVENT_SOFTIRQ;
	e->duration_ns = delta;
	e->cpu         = bpf_get_smp_processor_id();
	e->pid         = 0;
	e->stack_id    = -1;
	e->softirq_vec = sc->vec;
	e->comm[0]     = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------------------------------------------------------
 * Path 4: Kernel threads (task->mm == NULL)
 *
 * tp_btf/sched_switch gives fully typed task_struct pointers so we
 * can read ->mm and ->pid via CO-RE without needing a kprobe.
 *
 * Kernel threads only ever run in kernel space so their full scheduled
 * slice IS kernel execution time.  At sched-out time the kthread is
 * still on-CPU, making bpf_get_stackid() meaningful -- this is the
 * only path where a useful stack trace is available.
 * --------------------------------------------------------------- */
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next,
	     unsigned int prev_state)
{
	__u32 key = 0;
	struct kthread_ctx *kc = bpf_map_lookup_elem(&kthread_map, &key);
	struct mkt_event *e;
	__u64 delta;
	__u32 next_pid;

	if (!kc)
		return 0;

	/*
	 * Check whether the outgoing task is the kthread we were timing.
	 * Verify pid matches to guard against a missed sched-in (e.g. at
	 * tracer start time) leaving stale state.
	 */
	if (kc->pid && kc->pid == BPF_CORE_READ(prev, pid) &&
	    BPF_CORE_READ(prev, mm) == NULL) {
		delta = bpf_ktime_get_ns() - kc->start;

		if (delta > thresh_ns) {
			e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
			if (e) {
				e->type        = EVENT_KTHREAD;
				e->duration_ns = delta;
				e->cpu         = bpf_get_smp_processor_id();
				e->pid         = kc->pid;
				/*
				 * prev is still on-CPU: the stack trace
				 * shows exactly where the kthread was when
				 * the scheduler finally ran.
				 */
				e->stack_id = bpf_get_stackid(ctx, &stacks,
							      BPF_F_REUSE_STACKID);
				BPF_CORE_READ_STR_INTO(&e->comm, prev, comm);
				bpf_ringbuf_submit(e, 0);
			}
		}
		kc->pid = 0;
	}

	/* Start timing the incoming kthread; skip idle (pid == 0). */
	next_pid = BPF_CORE_READ(next, pid);
	if (next_pid && BPF_CORE_READ(next, mm) == NULL) {
		kc->start = bpf_ktime_get_ns();
		kc->pid   = next_pid;
	} else {
		kc->pid = 0;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
