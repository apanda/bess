// TODO: Consider IPv6 support

#include "../module.h"

struct random_packet_priv {
	uint32_t src_min_ip;
	uint32_t src_max_ip;
	uint32_t dest_min_ip;
	uint32_t dest_max_ip;
};
static struct snobj *random_packet_init(struct module *m, struct snobj *arg)
{

	srand(time(NULL));

	struct random_packet_priv *priv = get_priv(m);

	if (arg) {
		if (snobj_eval_exists(arg, "src_min_ip") && snobj_eval(arg, "src_min_ip")->type == TYPE_INT) {
			uint64_t ip = snobj_eval_uint(arg, "src_min_ip");
			if (ip > 0xffffffff) 
				return snobj_err(EDOM, "'src_min_ip' was outside the range of possible IPv4 addresses");
			priv->src_min_ip = ip;
		} else {
			priv->src_min_ip = 0;
		}

		if (snobj_eval_exists(arg, "src_max_ip") && snobj_eval(arg, "src_max_ip")->type == TYPE_INT) {
			uint64_t ip = snobj_eval_uint(arg, "src_max_ip");
			if (ip > 0xffffffff) 
				return snobj_err(EDOM, "'src_max_ip' was outside the range of possible IPv4 addresses");
			priv->src_max_ip = ip;
		} else {
			priv->src_max_ip = 0xffffffff;
		}

		if (snobj_eval_exists(arg, "dest_min_ip") && snobj_eval(arg, "dest_min_ip")->type == TYPE_INT) {
			uint64_t ip = snobj_eval_uint(arg, "dest_min_ip");
			if (ip > 0xffffffff) 
				return snobj_err(EDOM, "'dest_min_ip' was outside the range of possible IPv4 addresses");
			priv->dest_min_ip = ip;
		} else {
			priv->dest_min_ip = 0;
		}

		if (snobj_eval_exists(arg, "dest_max_ip") && snobj_eval(arg, "dest_max_ip")->type == TYPE_INT) {
			uint64_t ip = snobj_eval_uint(arg, "dest_max_ip");
			if (ip > 0xffffffff) 
				return snobj_err(EDOM, "'dest_max_ip' was outside the range of possible IPv4 addresses");
			priv->dest_max_ip = ip;
		} else {
			priv->dest_max_ip = 0xffffffff;
		}
	} else {
		priv->src_min_ip = 0;
		priv->src_max_ip = 0xffffffff;
		priv->dest_min_ip = 0;
		priv->dest_max_ip = 0xffffffff;
	}

	return NULL;
}

static struct snobj *random_packet_query(struct module *m, struct snobj *q)
{
	struct random_packet_priv *priv = get_priv(m);

	
	if (snobj_eval_exists(q, "src_min_ip") && snobj_eval(q, "src_min_ip")->type == TYPE_INT) {
		uint64_t ip = snobj_eval_uint(q, "src_min_ip");
		if (ip > 0xffffffff) 
			return snobj_err(EDOM, "'src_min_ip' was outside the range of possible IPv4 addresses");
		priv->src_min_ip = ip;
	}

	if (snobj_eval_exists(q, "src_max_ip") && snobj_eval(q, "src_max_ip")->type == TYPE_INT) {
		uint64_t ip = snobj_eval_uint(q, "src_max_ip");
		if (ip > 0xffffffff) 
			return snobj_err(EDOM, "'src_max_ip' was outside the range of possible IPv4 addresses");
		priv->src_max_ip = ip;
	}

	if (snobj_eval_exists(q, "dest_min_ip") && snobj_eval(q, "dest_min_ip")->type == TYPE_INT) {
		uint64_t ip = snobj_eval_uint(q, "dest_min_ip");
		if (ip > 0xffffffff) 
			return snobj_err(EDOM, "'dest_min_ip' was outside the range of possible IPv4 addresses");
		priv->dest_min_ip = ip;
	}

	if (snobj_eval_exists(q, "dest_max_ip") && snobj_eval(q, "dest_max_ip")->type == TYPE_INT) {
		uint64_t ip = snobj_eval_uint(q, "dest_max_ip");
		if (ip > 0xffffffff) 
			return snobj_err(EDOM, "'dest_max_ip' was outside the range of possible IPv4 addresses");
		priv->dest_max_ip = ip;
	}

	return NULL;
}

static inline void
randomize_packet(struct random_packet_priv* priv, struct snbuf* pkt)
{
	uint8_t *ipv4 = (uint8_t*)((uint8_t*)snb_head_data(pkt) +
			sizeof(struct ether_hdr));
	uint32_t src_ip = priv->src_min_ip + (rand() % (priv->src_max_ip - priv->src_min_ip));
	uint32_t dest_ip = priv->dest_min_ip + (rand() % (priv->dest_max_ip - priv->dest_min_ip));
	
	int i = 0;
	for(i = 0; i < 4; i++) {
		*(ipv4 + 12 + i) = src_ip >> (8 - i * 2);
	}
	for(i = 0; i < 4; i++) {
		*(ipv4 + 16 + i) = dest_ip >> (8 - i * 2);
	}
}

static void
random_packet_process_batch(struct module *m, struct pkt_batch *batch)
{
	struct random_packet_priv *priv = get_priv(m);

	int i = 0;
	for (i = 0; i < batch->cnt; i++)
		randomize_packet(priv, batch->pkts[i]);

	run_next_module(m, batch);
}

static const struct mclass random_packet = {
	.name       = "RandomPacket",
	.priv_size  = sizeof(struct random_packet_priv),
	.init       = random_packet_init,
	.process_batch  = random_packet_process_batch,
	.query      = random_packet_query,
};

ADD_MCLASS(random_packet)
