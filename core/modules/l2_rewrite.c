#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"

struct l2rw_priv {
	uint8_t mac_addr[12];
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

static void l2rw_deinit(struct module *m) {
}

static struct snobj *l2rw_query(struct module *m, struct snobj *q) {
	struct l2rw_priv *priv = get_priv(m);
	int r;
	if (q == NULL || (snobj_eval(q, "dst") == NULL &&
			snobj_eval(q, "src") == NULL)) {
		return snobj_err(EINVAL, "Need source or destination MAC");
	}
	if (snobj_eval(q, "dst") != NULL) {
		r = parse_mac_addr(snobj_eval_str(q, "dst"), 
				priv->mac_addr);
		if (r != 0) {
			return snobj_err(r, 
				"Error parsing destination MAC address");
		}
	}
	if (snobj_eval(q, "src") != NULL) {
		r = parse_mac_addr(snobj_eval_str(q, "src"), 
				&priv->mac_addr[6]);
		if (r != 0) {
			return snobj_err(r, "Error parsing source MAC address");
		}
	}
	return NULL;
}

static struct snobj *l2rw_init(struct module *m, struct snobj *arg) {
	struct l2rw_priv *priv = get_priv(m);
	if (arg == NULL || snobj_eval(arg, "dst") == NULL ||
			snobj_eval(arg, "src") == NULL) {
		return snobj_err(EINVAL, "Need source and destination MAC");
	}
	int r = parse_mac_addr(snobj_eval_str(arg, "dst"), priv->mac_addr);
	if (r != 0) {
		return snobj_err(r, "Error parsing destination MAC address");
	}
	r = parse_mac_addr(snobj_eval_str(arg, "src"), &priv->mac_addr[6]);
	if (r != 0) {
		return snobj_err(r, "Error parsing source MAC address");
	}
	return NULL;
}

static struct snobj *l2rw_get_desc(const struct module *m) {
	const struct l2rw_priv *priv = get_priv_const(m);
	return snobj_str_fmt("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx/"
			"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			priv->mac_addr[0], priv->mac_addr[1],
			priv->mac_addr[2], priv->mac_addr[3],
			priv->mac_addr[4], priv->mac_addr[5],
			priv->mac_addr[6], priv->mac_addr[7],
			priv->mac_addr[8], priv->mac_addr[9],
			priv->mac_addr[10], priv->mac_addr[11]);
	return NULL;
}

static void l2rw_process_batch(struct module *m, struct pkt_batch *batch) {
	/* This is hooked up to go to the internal forwarding interface */
	struct l2rw_priv *priv = get_priv(m);
	int i;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		char* ptr = snb_head_data(snb);
		/* FIXME: This sort of assumes valid length and valid eth
		 * header. Should check for length, but I don't know if there is
		 * other error handling required here */
		rte_memcpy(ptr, priv->mac_addr, 12); 

	}
	run_next_module(m, batch);
}

static const struct mclass e2_int = {
	.name            = "L2Rewrite",
	.def_module_name = "l2rewrite",
	.priv_size       = sizeof(struct l2rw_priv),
	.init            = l2rw_init,
	.deinit          = l2rw_deinit,
	.query           = l2rw_query,
	.get_desc        = l2rw_get_desc,
	.process_batch   = l2rw_process_batch,
};

ADD_MCLASS(e2_int)
