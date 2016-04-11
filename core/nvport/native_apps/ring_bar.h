#ifndef __RING_BAR_H__
#define __RING_BAR_H__
#include <rte_malloc.h>
#include <rte_config.h>
#include <rte_ring.h>
#include <rte_errno.h>
#define __cacheline_aligned __attribute__((aligned(64)))
#define PORT_NAME_LEN 128
#define MAX_QUEUES_PER_DIR 32

/* This is equivalent to the old bar */
struct rte_ring_bar {
	char name[PORT_NAME_LEN];

	/* The term RX/TX could be very confusing for a virtual switch.
	 * Instead, we use the "incoming/outgoing" convention:
	 * - incoming: outside -> SoftNIC
	 * - outgoing: SoftNIC -> outside */
	int num_inc_q;
	int num_out_q;

	struct rte_ring* inc_qs[MAX_QUEUES_PER_DIR];
	struct rte_ring* out_qs[MAX_QUEUES_PER_DIR];
};
#endif
