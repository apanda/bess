#include "../module.h"
#include "../utils/simd.h"

struct delay_priv {
	int delay;
};

static struct snobj *delay_init(struct module *m, struct snobj *arg) {
	struct delay_priv *priv = get_priv(m);
	priv->delay = snobj_eval_int(arg, "delay");
	log_info("Delay is %d\n", priv->delay);
	return NULL;
}

static void delay_deinit(struct module *m) {
}

static struct snobj *delay_query(struct module *m, struct snobj *q) {
	struct delay_priv *priv = get_priv(m);
	priv->delay = snobj_eval_int(q, "delay");
	log_info("Delay is %d\n", priv->delay);
	return NULL;
}

static struct snobj *delay_get_desc(const struct module *m) {
	return NULL;
}

static void delay_process_batch(struct module *m, struct pkt_batch *batch) {
	/* This is hooked up to go to the internal forwarding interface */
	struct delay_priv *priv = get_priv(m);
	int i, j;
	int delay = priv->delay;
	for (i = 0; i < batch->cnt; i++) {
		struct snbuf *snb = batch->pkts[i];
		char *ptr = snb_head_data(snb);
		char tmp[6];
		// Copy destination MAC to tmp
		rte_memcpy(tmp, ptr, 6);
		// Copy source to destination MAC
		rte_memcpy(ptr, ptr+6, 6);
		// Copy destination to source
		rte_memcpy(ptr+6, tmp, 6);
		for (j = 0; j < delay; j++) {
			asm volatile ("nop");
		}
	}

	run_next_module(m, batch);
}

static const struct mclass delay = {
	.name            = "Delay",
	.def_module_name = "delay",
	.priv_size       = sizeof(struct delay_priv),
	.init            = delay_init,
	.deinit          = delay_deinit,
	.query           = delay_query,
	.get_desc        = delay_get_desc,
	.process_batch   = delay_process_batch,
	.num_igates	 = 1,
	.num_ogates	 = 1,
};

ADD_MCLASS(delay)
