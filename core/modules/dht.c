#include "../module.h"

#include "../utils/simd.h"
#include "flowtable.h"

struct dht_priv {
	int init;
	struct flow_table flow_table;
	gate_t default_gate;
};

static struct snobj *dht_init(struct module *m, struct snobj *arg)
{
	struct dht_priv *priv = get_priv(m);
	int ret = 0;
	int size = snobj_eval_int(arg, "size");
	int bucket = snobj_eval_int(arg, "bucket");
	int default_gate = snobj_eval_int(arg, "default_gate");

	assert(priv != NULL);

	priv->init = 0;

	priv->default_gate = default_gate;

	if (size == 0)
		size = DEFAULT_TABLE_SIZE;
	if (bucket == 0)
		bucket = MAX_BUCKET_SIZE;

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
	log_info("Adding entry for gate %d\n", gate);
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

	struct dht_priv *priv = get_priv(m);

	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];

		ogates[i] = priv->default_gate;

		struct flow flow;
		
		if (extract_flow(snb, &flow) < 0) {
			/* Forward to default gate */
			ogates[i] = priv->default_gate;
			log_info("DHT not a flow\n");
		} else {
			r = ftb_find(&priv->flow_table,
				     &flow,
				     &ogates[i]);
			if (r != 0) {
				log_info("DHT Miss %u %u %d %d\n",
					flow.src_addr, flow.dst_addr,
					flow.src_port, flow.dst_port);
			}
		}
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
