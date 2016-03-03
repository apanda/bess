#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"

/* Number of pipelet instances we can balance between, for now */
const size_t MAX_GATES = 1024;

struct lb_priv {
	struct module *dht;
	gate_t gates;
	gate_t forward_translate_gates[1024];
	gate_t reverse_translate_gates[1024];
};

static struct snobj *lb_init(struct module *m, struct snobj *arg) {
	struct lb_priv *priv = get_priv(m);
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
	struct snobj *gates = snobj_map_get(arg, "num_gates");
	if (gates != NULL && snobj_type(gates) == TYPE_INT) {
		priv->gates = snobj_int_get(gates);
		if (priv->gates > MAX_GATES) {
			return snobj_err(EINVAL,
					"Cannot support more than %d gates",
					(int)MAX_GATES);
		}
		struct snobj *gate_mapping = snobj_map_get(arg, "fwd_gate_map");
		if (gate_mapping == NULL || 
		    snobj_type(gate_mapping) != TYPE_LIST ||
		    snobj_size(gate_mapping) != priv->gates) {
		    	return snobj_err(EINVAL,
		    			"Must supply a mapping from "
		    			"load balancer gate to DHT fwd gate");
		}
		for (int i = 0; i < snobj_size(gate_mapping); i++) {
			priv->forward_translate_gates[i] = 
				snobj_int_get(snobj_list_get(gate_mapping, i));
		}

		gate_mapping = snobj_map_get(arg, "rev_gate_map");
		if (gate_mapping == NULL || 
		    snobj_type(gate_mapping) != TYPE_LIST ||
		    snobj_size(gate_mapping) != priv->gates) {
		    	return snobj_err(EINVAL,
		    			"Must supply a mapping from "
		    			"load balancer gate to DHT rev gate");
		}
		for (int i = 0; i < snobj_size(gate_mapping); i++) {
			priv->reverse_translate_gates[i] = 
				snobj_int_get(snobj_list_get(gate_mapping, i));
		}

	} else {
		priv->gates = 0;
	}
	return NULL;
}

static void lb_deinit(struct module *m) {
}

static struct snobj *lb_query(struct module *m, struct snobj *q) {
	struct lb_priv *priv = get_priv(m);
	// FIXME: Removing is hard just add or change mapping for now.
	if (snobj_map_get(q, "add")) {
		int fwd_gate = snobj_eval_int(q, "add.fwd_gate_map");
		priv->forward_translate_gates[priv->gates] = fwd_gate;
		int rev_gate = snobj_eval_int(q, "add.rev_gate_map");
		priv->reverse_translate_gates[priv->gates] = rev_gate;
		priv->gates += 1;
	} else if (snobj_map_get(q, "change_mapping")) {
		gate_t to_change = (gate_t)snobj_eval_int(q, 
				"change_mapping.gate");
		gate_t fwd_new_val = (gate_t)snobj_eval_int(q,
				"change_mapping.fwd_map");
		gate_t rev_new_val = (gate_t)snobj_eval_int(q,
				"change_mapping.rev_map");
		if (to_change >= priv->gates) {
			return snobj_err(EINVAL,
					"Gate %d is not active", to_change);
		}
		priv->forward_translate_gates[to_change] = fwd_new_val;
		priv->reverse_translate_gates[to_change] = rev_new_val;
	}
	return NULL;
}

static struct snobj *lb_get_desc(const struct module *m) {
	return NULL;
}

int dht_add_flow(struct module* m, struct flow *flow, gate_t gate);

__attribute__((optimize("unroll-loops")))
static void lb_process_batch(struct module *m, struct pkt_batch *batch) {
	struct lb_priv *priv = get_priv(m);
	gate_t ogates[MAX_PKT_BURST];
	int i;
	gate_t gates = priv->gates;
	if (gates == 0) {
		/* Just act like a sink */
		snb_free_bulk(batch->pkts, batch->cnt);
		return;
	}
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		struct flow flow;
		gate_t gate = 0;
		int r = extract_flow(snb, &flow);
		if (r == 0) {
			/* Consistent hashing to make sure no race. */
			uint32_t hash = ftb_hash(&flow);
			gate = hash % gates;
			// FIXME: Error handling/trigger GC or something.
			dht_add_flow(priv->dht, &flow, 
					priv->forward_translate_gates[gate]);
			reverse_flow(&flow);
			dht_add_flow(priv->dht, &flow,
					priv->reverse_translate_gates[gate]);
		}
		ogates[i] = gate;
	}

	run_split(m, ogates, batch);
}

static const struct mclass e2_lb = {
	.name            = "E2LoadBalancer",
	.def_module_name = "e2lb",
	.priv_size       = sizeof(struct lb_priv),
	.init            = lb_init,
	.deinit          = lb_deinit,
	.query           = lb_query,
	.get_desc        = lb_get_desc,
	.process_batch   = lb_process_batch,
};

ADD_MCLASS(e2_lb)
