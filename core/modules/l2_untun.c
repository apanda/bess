#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"
#include <rte_ether.h>

struct l2untun_priv {
};

static const uint16_t TUNNEL_ETHER_TYPE = 0x88B5;

static void l2untun_deinit(struct module *m) {
}

static struct snobj *l2untun_query(struct module *m, struct snobj *q) {
	return NULL;
}

static struct snobj *l2untun_init(struct module *m, struct snobj *arg) {
	return NULL;
}

static struct snobj *l2untun_get_desc(const struct module *m) {
	return NULL;
}

static void l2untun_process_batch(struct module *m, struct pkt_batch *batch) {
	int i;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		struct ether_hdr* hdr = (struct ether_hdr*)snb_head_data(snb);
		if (hdr->ether_type != rte_cpu_to_be_16(TUNNEL_ETHER_TYPE)) {
			log_warn("Received untunneled packet\n");
			continue;
		}
		/* Remove the tunnel header */
		snb_adj(snb, sizeof(struct ether_hdr));
	}
	run_next_module(m, batch);
}

static const struct mclass l2_untun = {
	.name            = "L2UnTunnel",
	.def_module_name = "l2untun",
	.priv_size       = sizeof(struct l2untun_priv),
	.init            = l2untun_init,
	.deinit          = l2untun_deinit,
	.query           = l2untun_query,
	.get_desc        = l2untun_get_desc,
	.process_batch   = l2untun_process_batch,
};

ADD_MCLASS(l2_untun)
