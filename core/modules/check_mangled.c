#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"

struct mangled_priv {
	struct module *dht;
};

static struct snobj *mangled_init(struct module *m, struct snobj *arg) {
	struct mangled_priv *priv = get_priv(m);
	if (arg == NULL || snobj_type(arg) != TYPE_MAP) {
		return snobj_err(EINVAL,
				"Initial argument must be map");
	}
	struct snobj *dht = snobj_map_get(arg, "dht");
	if (dht == NULL || snobj_type(dht) != TYPE_STR) {
		return snobj_err(EINVAL,
				"Must supply a DHT to be used with E2 "
				"load balancing");
	}
	priv->dht = find_module(snobj_str_get(dht));
	if (priv->dht == NULL) {
		return snobj_err(EINVAL,
				"DHT module not found");
	}
	return NULL;
}

static void mangled_deinit(struct module *m) {
}

static struct snobj *mangled_query(struct module *m, struct snobj *q) {
	return NULL;
}

static struct snobj *mangled_get_desc(const struct module *m) {
	return NULL;
}

int dht_check_flow(struct module* m, struct flow *flow);

__attribute__((optimize("unroll-loops")))
static void mangled_process_batch(struct module *m, struct pkt_batch *batch) {
	struct mangled_priv *priv = get_priv(m);
	gate_t ogates[MAX_PKT_BURST];
	int i;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		struct flow flow;
		int r = extract_flow(snb, &flow);
		if (r == 0) {
			/* Check if reverse flow is in flow table */
			reverse_flow(&flow);
			r = dht_check_flow(priv->dht, &flow);
			if (r == 0) {
				ogates[i] = 0;
			} else {
				ogates[i] = 1;
				log_warn("Mangled packet");
			}
		}
		/* If we cannot extract flow, then no one is going to really
		 * look up the reverse traffic, so is fine. */
	}

	run_split(m, ogates, batch);
}

static const struct mclass e2_mangled = {
	.name            = "E2CheckMangled",
	.def_module_name = "e2mangled",
	.priv_size       = sizeof(struct mangled_priv),
	.init            = mangled_init,
	.deinit          = mangled_deinit,
	.query           = mangled_query,
	.get_desc        = mangled_get_desc,
	.process_batch   = mangled_process_batch,
};

ADD_MCLASS(e2_mangled)
