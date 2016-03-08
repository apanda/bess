#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"
#include <rte_ether.h>

#define MAX_GATES 1024
static const uint16_t TUNNEL_ETHER_TYPE = 0x88B5;

struct gate_translation {
	struct ether_addr src;
	gate_t dht_gate;
};

struct fix_mangled_priv {
	struct module *dht;
	struct gate_translation translation[MAX_GATES];
	int entries;
};

/* FIXME: This is stolen from l2_forward, we should combine this together */
/* FIXME: Consider replacing this with rewrite */
static int parse_mac_addr(const char *str, uint8_t *addr)
{
	if (str != NULL && addr != NULL) {
		int r = sscanf(str,
			       "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
			       addr,
			       addr+1,
			       addr+2,
			       addr+3,
			       addr+4,
			       addr+5);

		if (r != 6)
			return -EINVAL;
	}

	return 0;
}

static void fix_mangled_deinit(struct module *m) {
}

static struct snobj *fix_mangled_query(struct module *m, struct snobj *q) {
	struct fix_mangled_priv *priv = get_priv(m);
	struct snobj *servers;
	if (q == NULL || snobj_type(q) != TYPE_MAP) {
		return snobj_err(EINVAL,
				"Initial argument must be map");
	}
	servers = snobj_map_get(q, "servers");
	if (servers != NULL) {
		if (snobj_type(servers) != TYPE_LIST) {
			return snobj_err(EINVAL,
					"Servers must be a list");
		}
		if (snobj_size(servers) + priv->entries >= MAX_GATES) {
			return snobj_err(ENOMEM,
					"Ran out of slots");
		}
		for (int i = 0; i < snobj_size(servers); i++) {
			struct snobj *entry = snobj_list_get(servers, i);
			parse_mac_addr(snobj_eval_str(entry, "address"),
				priv->translation[priv->entries].
							src.addr_bytes);
			priv->translation[priv->entries].dht_gate =
				(gate_t)snobj_eval_int(entry, "gate");
			priv->entries++;
		}
	}

	return NULL;
}

static struct snobj *fix_mangled_init(struct module *m, struct snobj *arg) {
	struct fix_mangled_priv *priv = get_priv(m);
	priv->entries = 0;
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

	return fix_mangled_query(m, arg);
}

static struct snobj *fix_mangled_get_desc(const struct module *m) {
	return NULL;
}

int dht_check_flow(struct module* m, struct flow *flow);

int dht_add_flow(struct module* m, struct flow *flow, gate_t gate);

static void fix_mangled_process_batch(struct module *m, struct pkt_batch *batch) {
	/* This is hooked up to go to the external forwarding interface */
	struct fix_mangled_priv *priv = get_priv(m);
	int i;
	struct ether_addr src;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		struct ether_hdr* hdr = (struct ether_hdr*)snb_head_data(snb);
		if (hdr->ether_type == rte_cpu_to_be_16(TUNNEL_ETHER_TYPE)) {
			int found = 0;
			gate_t gate = 0;
			int r = 0;
			struct flow flow;
			src = hdr->s_addr;
			snb_adj(snb, sizeof(struct ether_hdr));
			r = extract_flow(snb, &flow);
			if (r != 0) {
				log_warn("No flow for mangled packet");
				continue;
			}

			for (int j = 0; j < priv->entries; j++) {
				if (is_same_ether_addr(&src, 
						&priv->translation[j].src)) {
					gate = priv->translation[j].dht_gate;
					dht_add_flow(priv->dht, &flow, gate);
					reverse_flow(&flow);
					dht_add_flow(priv->dht, &flow, gate);
					found = 1;
				}
			}
			if (!found && dht_check_flow(priv->dht, &flow) != 0) {
				char s_str[ETHER_ADDR_FMT_SIZE];
				ether_format_addr(s_str, ETHER_ADDR_FMT_SIZE,
						&src);
				log_warn("Could not find gate for mangled"
						" flow %s\n", s_str);
			}
		}	
	}
	run_next_module(m, batch);
}

static const struct mclass fix_mangled = {
	.name            = "FixMangled",
	.def_module_name = "e2fixmangled",
	.priv_size       = sizeof(struct fix_mangled_priv),
	.init            = fix_mangled_init,
	.deinit          = fix_mangled_deinit,
	.query           = fix_mangled_query,
	.get_desc        = fix_mangled_get_desc,
	.process_batch   = fix_mangled_process_batch,
};

ADD_MCLASS(fix_mangled)
