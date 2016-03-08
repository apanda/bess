#include "../module.h"
#include "../utils/simd.h"
#include "flowtable.h"
#include <rte_ether.h>

struct l2tun_priv {
	struct ether_hdr hdr;
};

static const uint16_t TUNNEL_ETHER_TYPE = 0x88B5;

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

static void l2tun_deinit(struct module *m) {
}

static struct snobj *l2tun_query(struct module *m, struct snobj *q) {
	struct l2tun_priv *priv = get_priv(m);
	int r;
	if (q == NULL || (snobj_eval(q, "dst") == NULL &&
			snobj_eval(q, "src") == NULL)) {
		return snobj_err(EINVAL, "Need source or destination MAC");
	}
	if (snobj_eval(q, "dst") != NULL) {
		r = parse_mac_addr(snobj_eval_str(q, "dst"), 
				priv->hdr.d_addr.addr_bytes);
		if (r != 0) {
			return snobj_err(r, 
				"Error parsing destination MAC address");
		}
	}
	if (snobj_eval(q, "src") != NULL) {
		r = parse_mac_addr(snobj_eval_str(q, "src"), 
				priv->hdr.s_addr.addr_bytes);
		if (r != 0) {
			return snobj_err(r, "Error parsing source MAC address");
		}
	}
	priv->hdr.ether_type = rte_cpu_to_be_16(TUNNEL_ETHER_TYPE); 
	return NULL;
}

static struct snobj *l2tun_init(struct module *m, struct snobj *arg) {
	struct l2tun_priv *priv = get_priv(m);
	int r;
	if (arg == NULL || snobj_eval(arg, "dst") == NULL ||
			snobj_eval(arg, "src") == NULL) {
		return snobj_err(EINVAL, "Need source or destination MAC");
	}
	r = parse_mac_addr(snobj_eval_str(arg, "dst"), 
			priv->hdr.d_addr.addr_bytes);
	if (r != 0) {
		return snobj_err(r, 
			"Error parsing destination MAC address");
	}
	r = parse_mac_addr(snobj_eval_str(arg, "src"), 
			priv->hdr.s_addr.addr_bytes);
	if (r != 0) {
		return snobj_err(r, "Error parsing source MAC address");
	}
	priv->hdr.ether_type = rte_cpu_to_be_16(0x88B5); 
	return NULL;
}

static struct snobj *l2tun_get_desc(const struct module *m) {
	const struct l2tun_priv *priv = get_priv_const(m);
	return snobj_str_fmt("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx/"
			"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			priv->hdr.d_addr.addr_bytes[0],
			priv->hdr.d_addr.addr_bytes[1],
			priv->hdr.d_addr.addr_bytes[2],
			priv->hdr.d_addr.addr_bytes[3],
			priv->hdr.d_addr.addr_bytes[4],
			priv->hdr.d_addr.addr_bytes[5],
			priv->hdr.s_addr.addr_bytes[0],
			priv->hdr.s_addr.addr_bytes[1],
			priv->hdr.s_addr.addr_bytes[2],
			priv->hdr.s_addr.addr_bytes[3],
			priv->hdr.s_addr.addr_bytes[4],
			priv->hdr.s_addr.addr_bytes[5]);
	return NULL;
}

static void l2tun_process_batch(struct module *m, struct pkt_batch *batch) {
	/* This is hooked up to go to the internal forwarding interface */
	struct l2tun_priv *priv = get_priv(m);
	int i;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		char *ptr = snb_prepend(snb, sizeof(struct ether_hdr));
		rte_memcpy(ptr, &priv->hdr, sizeof(struct ether_hdr));

	}
	run_next_module(m, batch);
}

static const struct mclass l2_tunnel = {
	.name            = "L2Tunnel",
	.def_module_name = "l2tunnel",
	.priv_size       = sizeof(struct l2tun_priv),
	.init            = l2tun_init,
	.deinit          = l2tun_deinit,
	.query           = l2tun_query,
	.get_desc        = l2tun_get_desc,
	.process_batch   = l2tun_process_batch,
};

ADD_MCLASS(l2_tunnel)
