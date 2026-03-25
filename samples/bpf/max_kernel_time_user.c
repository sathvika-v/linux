// SPDX-License-Identifier: GPL-2.0
/*
 * max_kernel_time_user.c - detect long kernel execution paths (BPF loader)
 *
 * Loads max_kernel_time.bpf.o, sets the threshold, and prints a line for
 * every kernel path that exceeds it.  For kthread events a symbolic stack
 * trace is printed using /proc/kallsyms.
 *
 * Usage:
 *   ./max_kernel_time [-t threshold_us]   # default: 1000 us (1 ms)
 *
 * Output format:
 *   [CPU] TYPE  comm/name      pid   duration
 *   [001] SYSCALL my_app        1234  5231 us  nr=0 (read)
 *   [002] IRQ    eth0             -   1823 us  irq=42
 *   [002] SOFTIRQ NET_RX          -   4821 us  vec=3
 *   [001] KTHREAD kworker/1:2   456   8341 us
 *          => expensive_fn
 *          => process_one_work
 *          => worker_thread
 *
 * Copyright (C) 2026 Steven Rostedt (Google) <rostedt@goodmis.org>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "max_kernel_time.h"

/* ---------------------------------------------------------------
 * Simple /proc/kallsyms reader for stack trace symbolisation.
 * --------------------------------------------------------------- */
#define MAX_SYMS	300000

struct ksym {
	unsigned long addr;
	char	     *name;
};

static struct ksym  syms[MAX_SYMS];
static int	    sym_cnt;

static int ksym_cmp(const void *a, const void *b)
{
	return ((struct ksym *)a)->addr > ((struct ksym *)b)->addr ? 1 : -1;
}

static int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char type, name[256];
	unsigned long addr;

	if (!f)
		return -1;

	while (fscanf(f, "%lx %c %255s%*[^\n]\n", &addr, &type, name) == 3) {
		if (sym_cnt >= MAX_SYMS)
			break;
		syms[sym_cnt].addr = addr;
		syms[sym_cnt].name = strdup(name);
		sym_cnt++;
	}
	fclose(f);
	qsort(syms, sym_cnt, sizeof(syms[0]), ksym_cmp);
	return 0;
}

static const char *ksym_name(unsigned long addr)
{
	int lo = 0, hi = sym_cnt - 1;

	if (!sym_cnt || addr < syms[0].addr)
		return "[unknown]";

	while (lo < hi) {
		int mid = (lo + hi + 1) / 2;

		if (syms[mid].addr <= addr)
			lo = mid;
		else
			hi = mid - 1;
	}
	return syms[lo].name;
}

/* ---------------------------------------------------------------
 * Ring buffer event handler
 * --------------------------------------------------------------- */
static int stacks_fd = -1;

static const char *type_name(enum event_type t)
{
	switch (t) {
	case EVENT_SYSCALL:  return "SYSCALL";
	case EVENT_IRQ:      return "IRQ    ";
	case EVENT_SOFTIRQ:  return "SOFTIRQ";
	case EVENT_KTHREAD:  return "KTHREAD";
	default:             return "UNKNOWN";
	}
}

static void print_stack(int stack_id)
{
	__u64 ip[MAX_STACK_DEPTH] = {};
	int i;

	if (stack_id < 0 || stacks_fd < 0)
		return;

	if (bpf_map_lookup_elem(stacks_fd, &stack_id, ip) != 0)
		return;

	for (i = 0; i < MAX_STACK_DEPTH; i++) {
		if (!ip[i])
			break;
		printf("         => %s\n", ksym_name(ip[i]));
	}
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	struct mkt_event *e = data;
	unsigned long long us = e->duration_ns / 1000;

	printf("[%03u] %s  ", e->cpu, type_name(e->type));

	switch (e->type) {
	case EVENT_SYSCALL:
		printf("%-16s  pid=%-6u  %6llu us  nr=%lld\n",
		       e->comm, e->pid, us, (long long)e->syscall_nr);
		break;

	case EVENT_IRQ:
		printf("%-16s  irq=%-5d  %6llu us\n",
		       e->irq_name, e->irq_nr, us);
		break;

	case EVENT_SOFTIRQ: {
		const char *name = e->softirq_vec < NR_SOFTIRQ_NAMES
				   ? softirq_names[e->softirq_vec]
				   : "UNKNOWN";
		printf("%-16s  vec=%-4u  %6llu us\n", name, e->softirq_vec, us);
		break;
	}

	case EVENT_KTHREAD:
		printf("%-16s  pid=%-6u  %6llu us\n",
		       e->comm, e->pid, us);
		print_stack(e->stack_id);
		break;

	default:
		printf("type=%u  duration=%llu us\n", e->type, us);
		break;
	}

	return 0;
}

/* ---------------------------------------------------------------
 * Main
 * --------------------------------------------------------------- */
static volatile int done;

static void sig_handler(int sig)
{
	done = 1;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-t threshold_us]\n"
		"  -t threshold_us  report kernel paths longer than this (default 1000)\n",
		prog);
}

int main(int argc, char **argv)
{
	struct bpf_object	*obj;
	struct bpf_program	*prog;
	struct ring_buffer	*rb;
	unsigned long long	 thresh_us = 1000;
	int			 rb_fd, opt, err;
	char			 bpf_obj_path[256];

	while ((opt = getopt(argc, argv, "t:h")) != -1) {
		switch (opt) {
		case 't':
			thresh_us = strtoull(optarg, NULL, 0);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	/* Load /proc/kallsyms for stack symbolisation. */
	if (load_kallsyms())
		fprintf(stderr, "Warning: could not load kallsyms; "
			"stack frames will show raw addresses\n");

	/* Open the BPF object file produced by the build system. */
	snprintf(bpf_obj_path, sizeof(bpf_obj_path),
		 "%s/max_kernel_time.bpf.o",
		 argc > optind ? argv[optind] : ".");

	obj = bpf_object__open(bpf_obj_path);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Failed to open %s: %s\n",
			bpf_obj_path, strerror(errno));
		return 1;
	}

	/*
	 * Set the threshold before loading so the verifier can treat it
	 * as a constant and dead-code-eliminate the fast (delta <= thresh)
	 * branches throughout the BPF program.
	 */
	{
		struct bpf_map *map = bpf_object__find_map_by_name(obj, ".rodata");

		if (map) {
			/* thresh_ns is the first (only) rodata field */
			unsigned long long thresh_ns = thresh_us * 1000ULL;

			bpf_map__set_initial_value(map, &thresh_ns,
						   sizeof(thresh_ns));
		}
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %s\n",
			strerror(-err));
		goto cleanup;
	}

	/* Attach all tracepoint programs. */
	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link = bpf_program__attach(prog);

		if (libbpf_get_error(link)) {
			fprintf(stderr, "Failed to attach %s: %s\n",
				bpf_program__name(prog), strerror(errno));
			err = -1;
			goto cleanup;
		}
	}

	/* Get the stack trace map fd for stack lookups in handle_event. */
	stacks_fd = bpf_object__find_map_fd_by_name(obj, "stacks");

	/* Set up the ring buffer reader. */
	rb_fd = bpf_object__find_map_fd_by_name(obj, "events");
	if (rb_fd < 0) {
		fprintf(stderr, "Failed to find events ring buffer\n");
		err = -1;
		goto cleanup;
	}

	rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracing kernel paths longer than %llu us ... "
	       "Hit Ctrl-C to stop.\n\n", thresh_us);
	printf("%-5s %-7s  %-16s  %-8s  %8s\n",
	       "[CPU]", "TYPE", "name/comm", "pid", "duration");
	printf("%-5s %-7s  %-16s  %-8s  %8s\n",
	       "-----", "-------", "----------------", "--------", "--------");

	while (!done) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Ring buffer poll error: %s\n",
				strerror(-err));
			break;
		}
	}

	ring_buffer__free(rb);
cleanup:
	bpf_object__close(obj);
	return err < 0 ? 1 : 0;
}
