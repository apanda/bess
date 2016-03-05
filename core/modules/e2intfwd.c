#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"

struct e2intfwd_priv {
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

static void e2int_deinit(struct module *m) {
}

static struct snobj *e2int_query(struct module *m, struct snobj *q) {
	struct e2intfwd_priv *priv = get_priv(m);
	if (q == NULL || snobj_eval(q, "dst") == NULL ||
			snobj_eval(q, "src") == NULL) {
		return snobj_err(EINVAL, "Need source and destination MAC");
	}
	int r = parse_mac_addr(snobj_eval_str(q, "dst"), priv->mac_addr);
	if (r != 0) {
		return snobj_err(r, "Error parsing destination MAC address");
	}
	r = parse_mac_addr(snobj_eval_str(q, "src"), &priv->mac_addr[6]);
	if (r != 0) {
		return snobj_err(r, "Error parsing source MAC address");
	}
	return NULL;
}

static struct snobj *e2int_init(struct module *m, struct snobj *arg) {
	return e2int_query(m, arg);
}

static struct snobj *e2int_get_desc(const struct module *m) {
	return NULL;
}

static void e2int_process_batch(struct module *m, struct pkt_batch *batch) {
	/* This is hooked up to go to the internal forwarding interface */
	struct e2intfwd_priv *priv = get_priv(m);
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
	.name            = "E2IntForwarder",
	.def_module_name = "e2int",
	.priv_size       = sizeof(struct e2intfwd_priv),
	.init            = e2int_init,
	.deinit          = e2int_deinit,
	.query           = e2int_query,
	.get_desc        = e2int_get_desc,
	.process_batch   = e2int_process_batch,
};

ADD_MCLASS(e2_int)
