#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"
#include "../time.h"

struct e2_out_priv {
	uint64_t bytes_tx;
};

static struct snobj *e2_out_init(struct module *m, struct snobj *arg) {
	struct e2_out_priv *priv = get_priv(m);
	priv->bytes_tx = 0;
	return NULL;
}

static void e2_out_deinit(struct module *m) {
}

static struct snobj *e2_out_query(struct module *m, struct snobj *q) {
	struct e2_out_priv *priv = get_priv(m);
	if (snobj_map_get(q, "get_tx_stats")) {
		struct snobj *stat = snobj_map();
		snobj_map_set(stat, "bytes",
				snobj_int(priv->bytes_tx));
		snobj_map_set(stat, "timestamp", 
				snobj_double(get_epoch_time()));
		return stat;
	}
	return snobj_err(EINVAL, "Unrecognized command");
}

static struct snobj *e2_out_get_desc(const struct module *m) {
	const struct e2_out_priv *priv = get_priv_const(m);
	return snobj_str_fmt("%" PRIu64, priv->bytes_tx);
}

int dht_add_flow(struct module* m, struct flow *flow, gate_t gate);

__attribute__((optimize("unroll-loops")))
static void e2_out_process_batch(struct module *m, struct pkt_batch *batch) {
	struct e2_out_priv *priv = get_priv(m);
	const int pkt_overhead = 24;
	int i;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		priv->bytes_tx += 
			(snb_total_len(snb) + pkt_overhead);
	}

	run_next_module(m, batch);
}

static const struct mclass e2_out_bytes = {
	.name            = "E2OutBytes",
	.def_module_name = "e2out",
	.priv_size       = sizeof(struct e2_out_priv),
	.init            = e2_out_init,
	.deinit          = e2_out_deinit,
	.query           = e2_out_query,
	.get_desc        = e2_out_get_desc,
	.process_batch   = e2_out_process_batch,
};

ADD_MCLASS(e2_out_bytes)
