#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"

/* If using a L2 learning switch to direct packets, we need to filter out
 * packets not intended for our datapath. This module implements such a
 * destination MAC address */
struct mac_filter_priv {
	uint8_t mac[6];
};

/* FIXME: This is stolen from l2_forward and mac_filter */
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

static struct snobj *mac_filter_init(struct module *m, struct snobj *arg) {
	struct mac_filter_priv *priv = get_priv(m);
	if (arg == NULL || snobj_eval(arg, "mac") == NULL) {
		return snobj_err(EINVAL, "Need destination MAC");
	}
	int r = parse_mac_addr(snobj_eval_str(arg, "mac"), priv->mac);
	if (r != 0) {
		return snobj_err(r, "Error parsing MAC address");
	}
	return NULL;
}

static void mac_filter_deinit(struct module *m) {
}

static struct snobj *mac_filter_query(struct module *m, struct snobj *q) {
	struct mac_filter_priv *priv = get_priv(m);
	if (q == NULL || snobj_eval(q, "mac") == NULL) {
		return snobj_err(EINVAL, "Need source destination MAC");
	}
	int r = parse_mac_addr(snobj_eval_str(q, "mac"), priv->mac);
	if (r != 0) {
		return snobj_err(r, "Error parsing MAC address");
	}
	return NULL;
}

static struct snobj *mac_filter_get_desc(const struct module *m) {
	return NULL;
}

static void mac_filter_process_batch(struct module *m, struct pkt_batch *batch) {
	/* This is hooked up to go to the internal forwarding interface */
	struct mac_filter_priv *priv = get_priv(m);
	gate_t ogates[MAX_PKT_BURST];
	int i;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		char* ptr = snb_head_data(snb);
		// Get dst mac + 2 bits of source.
		if (memcmp(ptr, priv->mac, 6) == 0) {
			ogates[i] = 0;
		} else {
			ogates[i] = 1;
		}
	}

	run_split(m, ogates, batch);
}

static const struct mclass mac_filter = {
	.name            = "DstMacFilter",
	.def_module_name = "mac_filter",
	.priv_size       = sizeof(struct mac_filter_priv),
	.init            = mac_filter_init,
	.deinit          = mac_filter_deinit,
	.query           = mac_filter_query,
	.get_desc        = mac_filter_get_desc,
	.process_batch   = mac_filter_process_batch,
};

ADD_MCLASS(mac_filter)
