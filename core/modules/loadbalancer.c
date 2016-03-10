#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"
#include "../time.h"

/* Number of pipelet instances we can balance between, for now */
#define MAX_GATES 1024

struct lb_priv {
	struct module *dht;
	gate_t connected_gates;
	gate_t usable_gates;
	gate_t forward_translate_gates[MAX_GATES];
	gate_t reverse_translate_gates[MAX_GATES];
	gate_t active_gates[MAX_GATES];
	uint64_t bytes_tx[MAX_OUTPUT_GATES];
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
		priv->usable_gates = 
			priv->connected_gates = snobj_int_get(gates);
		if (priv->connected_gates > MAX_GATES) {
			return snobj_err(EINVAL,
					"Cannot support more than %d gates",
					(int)MAX_GATES);
		}
		struct snobj *gate_mapping = snobj_map_get(arg, "fwd_gate_map");
		if (gate_mapping == NULL || 
		    snobj_type(gate_mapping) != TYPE_LIST ||
		    snobj_size(gate_mapping) != priv->connected_gates) {
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
		    snobj_size(gate_mapping) != priv->connected_gates) {
		    	return snobj_err(EINVAL,
		    			"Must supply a mapping from "
		    			"load balancer gate to DHT rev gate");
		}
		for (int i = 0; i < snobj_size(gate_mapping); i++) {
			priv->reverse_translate_gates[i] = 
				snobj_int_get(snobj_list_get(gate_mapping, i));
		}

		/* Mark all gates as usable */
		for (int i = 0; i < priv->connected_gates; i++) {
			priv->active_gates[i] = i;
		}

	} else {
		priv->connected_gates = 0;
		priv->usable_gates = 0;
	}
	return NULL;
}

static void lb_deinit(struct module *m) {
}

static struct snobj *lb_query(struct module *m, struct snobj *q) {
	struct lb_priv *priv = get_priv(m);
	// FIXME: Removing is hard just add or change mapping for now.
	if (snobj_map_get(q, "add")) {
		struct snobj *r = snobj_map();
		int fwd_gate = snobj_eval_int(q, "add.fwd_gate_map");
		int rev_gate = snobj_eval_int(q, "add.rev_gate_map");
		int add_active = snobj_eval_int(q, "add.active");
		priv->forward_translate_gates[priv->connected_gates] = fwd_gate;
		priv->reverse_translate_gates[priv->connected_gates] = rev_gate;
		if (add_active) {
			priv->active_gates[priv->usable_gates] = 
				priv->connected_gates;
			priv->usable_gates++;
		}
		snobj_map_set(r, "gate", snobj_int(priv->connected_gates)); 
		priv->connected_gates += 1;
		return r;
	} else if (snobj_map_get(q, "activate_gate")) {
		int gate = snobj_eval_int(q, "activate_gate.gate");
		if (gate >= priv->connected_gates) {
			return snobj_err(EINVAL,
					"Gate %d is not connected", gate);
		}
		if (priv->usable_gates >= MAX_GATES) {
			return snobj_err(ENOMEM,
					"Cannot activate more than %d gates",
					MAX_GATES);
		}
		for (int i = 0; i < priv->usable_gates; i++) {
			if (priv->active_gates[i] == gate) {
				return snobj_err(EEXIST,
						"Gate %d is already active",
						gate);
			}
		}
		priv->active_gates[priv->usable_gates] = gate;
		priv->usable_gates++;
		return NULL;
	} else if (snobj_map_get(q, "deactivate_gate")) {
		int gate = snobj_eval_int(q, "deactivate_gate.gate");
		int idx = 0;
		int found = 0;
		if (gate >= priv->connected_gates) {
			return snobj_err(EINVAL,
					"Gate %d is not connected", gate);
		}
		for (int i = 0; i < priv->usable_gates; i++) {
			if (priv->active_gates[i] != gate) {
				priv->active_gates[idx++] = 
					priv->active_gates[i];
			} else {
				found = 1;
			}
		}
		if (!found) {
			return snobj_err(ENOENT,
					"Gate %d not found", gate);
		}
		priv->usable_gates = idx;
		return NULL;
	} else if (snobj_map_get(q, "change_mapping")) {
		gate_t to_change = (gate_t)snobj_eval_int(q, 
				"change_mapping.gate");
		gate_t fwd_new_val = (gate_t)snobj_eval_int(q,
				"change_mapping.fwd_map");
		gate_t rev_new_val = (gate_t)snobj_eval_int(q,
				"change_mapping.rev_map");
		if (to_change >= priv->connected_gates) {
			return snobj_err(EINVAL,
					"Gate %d is not active", to_change);
		}
		priv->forward_translate_gates[to_change] = fwd_new_val;
		priv->reverse_translate_gates[to_change] = rev_new_val;
		return NULL;
	} else if (snobj_map_get(q, "get_tx_stats")) {
		struct snobj *gates = snobj_map_get(q, "get_tx_stats");
		struct snobj *stats = snobj_list();
		if (snobj_type(gates) != TYPE_LIST) {
			return snobj_err(EINVAL, "Must supply a list of gates");
		}
		for (int i = 0; i < gates->size; i++) {
			gate_t gate = snobj_int_get(
					snobj_list_get(gates, i));
			struct snobj *stat = snobj_map();
			snobj_map_set(stat, "gate", snobj_int(gate));
			snobj_map_set(stat, "bytes",
					snobj_int(priv->bytes_tx[gate]));
			snobj_map_set(stat, "timestamp", 
					snobj_double(get_epoch_time()));
			snobj_list_add(stats, stat);
		}
		return stats;
	}
	return snobj_err(EINVAL, "Unrecognized command");
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
	gate_t gates = priv->usable_gates;
	const int pkt_overhead = 24;
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
			struct ether_hdr *eth;
			struct ipv4_hdr *ip;
			gate = hash % priv->usable_gates;
			gate = priv->active_gates[gate];
			log_info("Assigning flow %u %u %d %d"
				" to gate %d adding for %d\n", 
					flow.src_addr, flow.dst_addr,
					flow.src_port, flow.dst_port,
					gate, 
					priv->forward_translate_gates[gate]);
			// FIXME: Error handling/trigger GC or something.
			dht_add_flow(priv->dht, &flow, 
					priv->forward_translate_gates[gate]);
			reverse_flow(&flow);
			log_info("Assigning flow %u %u %u %u"
				" to gate %d adding for %d\n", 
					flow.src_addr, flow.dst_addr,
					flow.src_port, flow.dst_port,
					gate, 
					priv->reverse_translate_gates[gate]);
			dht_add_flow(priv->dht, &flow,
					priv->reverse_translate_gates[gate]);

			eth = (struct ether_hdr*)snb_head_data(snb);
			ip = (struct ipv4_hdr *)(eth + 1);
			ip->packet_id = priv->forward_translate_gates[gate];
			ip->hdr_checksum = 0;
			ip->hdr_checksum = rte_ipv4_cksum(ip); 
		}
		ogates[i] = gate;
		/* Add ethernet overhead here since we only report bytes, making
		 * it hard to add this overhead in other places. */
		priv->bytes_tx[ogates[i]] += 
			(snb_total_len(snb) + pkt_overhead);
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
