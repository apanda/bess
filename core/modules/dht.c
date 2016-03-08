#include "../module.h"

#include "../utils/simd.h"
#include "flowtable.h"
#include "../time.h"
#include <rte_ether.h>
#include <rte_ip.h>

struct dht_priv {
	int init;
	struct flow_table flow_table;
	gate_t default_gate;
	gate_t sink_gate;
	// Measure how many bytes are sent to each gate
	uint64_t bytes_tx[MAX_OUTPUT_GATES];
};

static struct snobj *dht_init(struct module *m, struct snobj *arg)
{
	struct dht_priv *priv = get_priv(m);
	int ret = 0;
	int size = snobj_eval_int(arg, "size");
	int bucket = snobj_eval_int(arg, "bucket");
	int default_gate = snobj_eval_int(arg, "default_gate");
	int sink_gate = snobj_eval_int(arg, "sink_gate");

	assert(priv != NULL);

	priv->init = 0;

	priv->default_gate = default_gate;
	
	priv->sink_gate = sink_gate;

	if (size == 0)
		size = DEFAULT_TABLE_SIZE;
	if (bucket == 0)
		bucket = MAX_BUCKET_SIZE;

	if (sink_gate == default_gate)
		log_warn("DHT sink_gate and default_gate are the same"
			 " this will result in not dropping non-flows\n");

	ret = ftb_init(&priv->flow_table, size, bucket);

	if (ret != 0) {
		return snobj_err(-ret,
				 "initialization failed with argument " \
                                 "size: '%d' bucket: '%d'\n",
				 size, bucket);
	}

	priv->init = 1;

	return NULL;
}

static void dht_deinit(struct module *m)
{
	struct dht_priv *priv = get_priv(m);

	if (priv->init) {
		priv->init = 0;
		ftb_deinit(&priv->flow_table);
	}
}

int dht_add_flow(struct module* m, struct flow *flow, gate_t gate)
{
	struct dht_priv *priv = get_priv(m);
	/*log_info("Adding entry for gate %d\n", gate);*/
	return ftb_add_entry(&priv->flow_table, flow, gate);
}

static struct snobj 
*handle_add(struct dht_priv *priv, struct snobj *add)
{
	int i;

	if (snobj_type(add) != TYPE_LIST) {
		return snobj_err(EINVAL, "add must be given as a list of map");
	}

	for (i = 0; i < add->size; i++) {
		struct snobj *entry = snobj_list_get(add, i);
		struct flow flow;
		struct snobj *err = flow_from_snobj(entry, &flow);
		if (err != NULL) {
			return NULL;
		}
		struct snobj *gate = snobj_map_get(entry, "gate");

		int r = ftb_add_entry(&priv->flow_table, &flow, 
				(gate_t) snobj_int_get(gate));

		if (r == -EEXIST)
			return snobj_err(EEXIST,
					"Flow entry already exists");
		else if (r == -ENOMEM)
			return snobj_err(ENOMEM,
					"Not enough space");
		else if (r != 0)
			return snobj_err(-r,
					"Unknown error");
	}

	return NULL;
}

static struct snobj *handle_lookup(struct dht_priv *priv,
				   struct snobj *lookup)
{
	int i;

	if (snobj_type(lookup) != TYPE_LIST) {
		return snobj_err(EINVAL, "lookup must be given as a list");
	}

	struct snobj *ret = snobj_list();
	for (i = 0; i < lookup->size; i++) {
		struct snobj *_addr = snobj_list_get(lookup, i);

		struct flow flow;
		gate_t gate;

		struct snobj *err = flow_from_snobj(_addr, &flow);
		if (err != NULL) {
			return NULL;
		}

		int r = ftb_find(&priv->flow_table,
				&flow,
				&gate);

		if (r == -ENOENT) {
			snobj_free(ret);
			return snobj_err(ENOENT,
					 "Flow not found");
		} else if ( r != 0) {
			snobj_free(ret);
			return snobj_err(-r, "Unknown error");
		}

		snobj_list_add(ret, snobj_int(gate));
	}

	return ret;
}

static struct snobj *handle_del(struct dht_priv *priv,
				struct snobj *del)
{
	int i;

	if (snobj_type(del) != TYPE_LIST) {
		return snobj_err(EINVAL, "lookup must be given as a list");
	}

	for (i = 0; i < del->size; i++) {
		struct snobj *_addr = snobj_list_get(del, i);

		struct flow flow;

		struct snobj *err = flow_from_snobj(_addr, &flow);

		if (err) {
			return err;
		}

		int r = ftb_del_entry(&priv->flow_table,
				     &flow);

		if (r == -ENOENT) {
			return snobj_err(ENOENT,
					 "No such entry");
		} else if (r != 0) {
			return snobj_err(-r,
					 "Unknown Error");
		}
	}

	return NULL;
}

static struct snobj *handle_def_gate(struct dht_priv *priv,
				    struct snobj *def_gate)
{
	int gate = snobj_int_get(def_gate);

	priv->default_gate = gate;

	return NULL;
}

static struct snobj *dht_query(struct module *m, struct snobj *q)
{
	struct dht_priv *priv = get_priv(m);

	struct snobj *ret = NULL;

	struct snobj *add = snobj_eval(q, "add");
	struct snobj *lookup = snobj_eval(q, "lookup");
	struct snobj *del = snobj_eval(q, "del");
	struct snobj *def_gate = snobj_eval(q, "default");
	struct snobj *stat_gates = snobj_map_get(q, "get_tx_stats");

	if (stat_gates) {
		struct snobj *stats = snobj_list();
		int idx = 0;
		if (snobj_type(stat_gates) != TYPE_LIST) {
			return snobj_err(EINVAL, "Must supply a list of gates");
		}
		for (int i = 0; i < stat_gates->size; i++) {
			gate_t gate = snobj_int_get(
					snobj_list_get(stat_gates, i));
			struct snobj *stat = snobj_map();
			snobj_map_set(stat, "gate", snobj_int(gate));
			snobj_map_set(stat, "bytes",
					snobj_int(priv->bytes_tx[gate]));
			snobj_map_set(stat, "timestamp", 
					snobj_double(get_epoch_time()));
			idx = snobj_list_add(stats, stat);
		}
		return stats;
	}

	if (add) {
		ret = handle_add(priv, add);
		if (ret)
			return ret;
	}

	if (lookup) {
		ret = handle_lookup(priv, lookup);
		if (ret)
			return ret;
	}

	if (del) {
		ret = handle_del(priv, del);
		if (ret)
			return ret;
	}

	if (def_gate) {
		ret = handle_def_gate(priv, def_gate);
		if (ret)
			return ret;
	}

	return NULL;
}

static struct snobj *dht_get_desc(const struct module *m)
{
	return NULL;
}

int dht_check_flow(struct module* m, struct flow *flow) {
	gate_t ogate;
	struct dht_priv *priv = get_priv(m);
	return ftb_find(&priv->flow_table, flow, &ogate);
}

__attribute__((optimize("unroll-loops")))
static void dht_process_batch(struct module *m, struct pkt_batch *batch)
{
	gate_t ogates[MAX_PKT_BURST];
	int r, i;
	const int pkt_overhead = 24;

	struct dht_priv *priv = get_priv(m);

	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];

		ogates[i] = priv->default_gate;

		struct flow flow;
		
		if (extract_flow(snb, &flow) < 0) {
			/* Forward to default gate */
			ogates[i] = priv->sink_gate;
		} else {
			r = ftb_find(&priv->flow_table,
				     &flow,
				     &ogates[i]);

			/* Record gate so we can use this if mangled */
			struct ether_hdr *eth;
			struct ipv4_hdr *ip;
			if (r == 0) {
				eth = (struct ether_hdr*)snb_head_data(snb);
				ip = (struct ipv4_hdr *)(eth + 1);
				ip->packet_id = ogates[i];
				ip->hdr_checksum = 0;
				ip->hdr_checksum = rte_ipv4_cksum(ip); 
			}
		}
		priv->bytes_tx[ogates[i]] += 
			(snb_total_len(snb) + pkt_overhead);
	}

	run_split(m, ogates, batch);
}

static const struct mclass e2_dht = {
	.name            = "DHT",
	.def_module_name = "dht",
	.priv_size       = sizeof(struct dht_priv),
	.init            = dht_init,
	.deinit          = dht_deinit,
	.query           = dht_query,
	.get_desc        = dht_get_desc,
	.process_batch   = dht_process_batch,
};

ADD_MCLASS(e2_dht)
