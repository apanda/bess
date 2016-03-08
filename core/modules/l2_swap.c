#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"
#include <rte_ether.h>

struct l2swap_priv {
};

static void l2swap_deinit(struct module *m) {
}

static struct snobj *l2swap_query(struct module *m, struct snobj *q) {
	return NULL;
}

static struct snobj *l2swap_init(struct module *m, struct snobj *arg) {
	return NULL;
}

static struct snobj *l2swap_get_desc(const struct module *m) {
	return NULL;
}

static void l2swap_process_batch(struct module *m, struct pkt_batch *batch) {
	int i;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		struct ether_hdr* hdr = (struct ether_hdr*)snb_head_data(snb);
		struct ether_addr dst = hdr->d_addr;
		hdr->d_addr = hdr->s_addr;
		hdr->s_addr = dst;
	}
	run_next_module(m, batch);
}

static const struct mclass l2_swap = {
	.name            = "L2Swap",
	.def_module_name = "l2swap",
	.priv_size       = sizeof(struct l2swap_priv),
	.init            = l2swap_init,
	.deinit          = l2swap_deinit,
	.query           = l2swap_query,
	.get_desc        = l2swap_get_desc,
	.process_batch   = l2swap_process_batch,
};

ADD_MCLASS(l2_swap)
