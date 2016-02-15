#include "../module.h"

#include "../utils/simd.h"
#include "flowtable.h"

/******************************************************************************/

struct dht_priv {
	int init;
	struct flow_table flow_table;
	gate_t default_gate;
};

static struct snobj *dht_forward_init(struct module *m, struct snobj *arg)
{
	struct dht_priv *priv = get_priv(m);
	int ret = 0;
	int size = snobj_eval_int(arg, "size");
	int bucket = snobj_eval_int(arg, "bucket");

	assert(priv != NULL);

	priv->init = 0;

	priv->default_gate = INVALID_GATE;

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

static void dht_forward_deinit(struct module *m)
{
	struct dht_priv *priv = get_priv(m);

	if (priv->init) {
		priv->init = 0;
		ftb_deinit(&priv->flow_table);
	}
}

static inline struct snobj*
flow_from_snobj(struct snobj *entry, struct flow* flow) {
	if (snobj_type(entry) != TYPE_MAP) {
		return snobj_err(EINVAL,
				 "add must be given as a list of map");
	}

	struct snobj *src_addr = snobj_map_get(entry, "src_addr");
	struct snobj *dst_addr = snobj_map_get(entry, "dst_addr");
	struct snobj *src_port = snobj_map_get(entry, "src_port");
	struct snobj *dst_port = snobj_map_get(entry, "dst_port");
	struct snobj *protocol = snobj_map_get(entry, "protocol");

	struct snobj *gate = snobj_map_get(entry, "gate");

	if (!src_addr || snobj_type(src_addr) != TYPE_INT)
		return snobj_err(EINVAL, "Must supply source address");

	if (!dst_addr || snobj_type(dst_addr) != TYPE_INT)
		return snobj_err(EINVAL, 
				"Must supply destination address");

	if (!src_port || snobj_type(src_port) != TYPE_INT ||
			snobj_int_get(src_port) > UINT16_MAX)
		return snobj_err(EINVAL, 
				"Must supply valid source port");

	if (!dst_port || snobj_type(dst_port) != TYPE_INT ||
			snobj_int_get(dst_port) > UINT16_MAX)
		return snobj_err(EINVAL,
				"Must supply valid destination port");

	if (!protocol || snobj_type(protocol) != TYPE_INT ||
			snobj_int_get(protocol) > UINT8_MAX)
		return snobj_err(EINVAL,
				"Must supply valid protocol");

	if (!gate || snobj_type(gate) != TYPE_INT ||
			snobj_int_get(gate) >= INVALID_GATE)
		return snobj_err(EINVAL,
				"Must supply valid gate");


	flow->src_addr = (uint32_t) snobj_int_get(src_addr);
	flow->dst_addr = (uint32_t) snobj_int_get(dst_addr);
	flow->src_port = (uint16_t) snobj_int_get(src_port);
	flow->dst_port = (uint16_t) snobj_int_get(dst_port);
	flow->protocol = (uint8_t) snobj_int_get(protocol);
	return NULL;
}

static inline int 
extract_flow(struct snbuf *snb, struct flow *flow)
{
	struct ether_hdr *eth;
	struct ipv4_hdr *ip;
	struct udp_hdr *udp;

	eth = (struct ether_hdr*)snb_head_data(snb);

	if (eth->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))
		return -1;

	ip = (struct ipv4_hdr *)(eth + 1);

	int ihl = (ip->version_ihl & IPV4_HDR_IHL_MASK) *
		IPV4_IHL_MULTIPLIER;

	if (ip->next_proto_id != 17 &&
	    ip->next_proto_id != 6)
		return -1;
	
	udp = (struct udp_hdr*)(((char*)ip) + ihl);

	flow->src_addr = ip->src_addr;
	flow->dst_addr = ip->dst_addr;
	flow->src_port = udp->src_port;
	flow->dst_port = udp->dst_port;
	flow->protocol = ip->next_proto_id;
	
	return 0;
}

static struct snobj *handle_add(struct dht_priv *priv,
				struct snobj *add)
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

static struct snobj *dht_forward_query(struct module *m, struct snobj *q)
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

static struct snobj *dht_forward_get_desc(const struct module *m)
{
	return NULL;
}


__attribute__((optimize("unroll-loops")))
static void dht_forward_process_batch(struct module *m, struct pkt_batch *batch)
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
		}else {
			r = ftb_find(&priv->flow_table,
				     &flow,
				     &ogates[i]);
			/* Could not find where to send */
			if (r != 0) {
				ogates[i] = priv->default_gate;
			}
		}
	}

	run_split(m, ogates, batch);
}


static const struct mclass e2_dht = {
	.name            = "DHT",
	.def_module_name = "dht",
	.priv_size       = sizeof(struct dht_priv),
	.init            = dht_forward_init,
	.deinit          = dht_forward_deinit,
	.query           = dht_forward_query,
	.get_desc        = dht_forward_get_desc,
	.process_batch   = dht_forward_process_batch,
};


ADD_MCLASS(e2_dht)
