#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>

#include "../driver.h"
#include "../port.h"
#include "../snbuf.h"

/* This is the same thing as vport_zc except for using rte_ring instead of
 * Bess. Also this kind imposes isolation, where we decide to not trust any
 * packets emitted by the user.*/

#define SLOTS_PER_LLRING	256

/* This watermark is to detect congestion and cache bouncing due to
 * head-eating-tail (needs at least 8 slots less then the total ring slots).
 * Not sure how to tune this... */
#define SLOTS_WATERMARK		((SLOTS_PER_LLRING >> 3) * 7)	/* 87.5% */

/* Disable (0) single producer/consumer mode for now.
 * This is slower, but just to be on the safe side. :) */
#define SINGLE_P		0
#define SINGLE_C		0

#define VPORT_DIR_PREFIX "sn_vports"
#define RTE_RING_NAME "ETH_RXTX"

/* This is sort of equivalent to the old bar */
struct rte_ring_bar {
	char name[PORT_NAME_LEN];

	/* The term RX/TX could be very confusing for a virtual switch.
	 * Instead, we use the "incoming/outgoing" convention:
	 * - incoming: outside -> SoftNIC
	 * - outgoing: SoftNIC -> outside */
	int num_inc_q;
	int num_out_q;

	struct rte_ring* inc_qs[MAX_QUEUES_PER_DIR];

	struct rte_ring* out_qs[MAX_QUEUES_PER_DIR];
};

struct vport_priv {
	struct rte_ring_bar* bar;

	struct rte_ring* inc_qs[MAX_QUEUES_PER_DIR];

	struct rte_ring* out_qs[MAX_QUEUES_PER_DIR];

	int port;
};

static struct snobj *vport_init_port(struct port *p, struct snobj *arg)
{
	struct vport_priv *priv = get_port_priv(p);
	struct rte_ring_bar *bar = NULL;

	int num_inc_q = p->num_queues[PACKET_DIR_INC];
	int num_out_q = p->num_queues[PACKET_DIR_OUT];

	int total_bytes;
	int i;
	char port_dir[PORT_NAME_LEN + 256];
	char file_name[PORT_NAME_LEN + 256];
	char ring_name[PORT_NAME_LEN + 256];
	struct stat sb;
	FILE* fp;
	size_t bar_address;
	int ret;
	struct rte_eth_conf null_conf;
	int numa_node = 0;

	if (snobj_eval_exists(arg, "node")) {
		numa_node = snobj_eval_int(arg, "node");
	}

	memset(&null_conf, 0, sizeof(struct rte_eth_conf));

	/*bytes_per_ring = rte_ring_get_memsize(SLOTS_PER_LLRING);*/
	total_bytes =	sizeof(struct rte_ring_bar);

	bar = rte_zmalloc(NULL, total_bytes, 0);
	bar_address = (size_t)bar;
	assert(bar != NULL);
	priv->bar = bar;

	strncpy(bar->name, p->name, PORT_NAME_LEN);
	bar->num_inc_q = num_inc_q;
	bar->num_out_q = num_out_q;

	/* Set up inc rte_rings */
	for (i = 0; i < num_inc_q; i++) {
		snprintf(ring_name, PORT_NAME_LEN + 256, 
				"%s%s%d", p->name, "incq", i);
		bar->inc_qs[i] = rte_ring_create(ring_name,
				SLOTS_PER_LLRING,
				numa_node,
				SINGLE_P | SINGLE_C);
		if (bar->inc_qs[i] == NULL) {
			return snobj_err(rte_errno, "Failed to allocate ring");
		}
		priv->inc_qs[i] = bar->inc_qs[i];
		if (rte_ring_set_water_mark(priv->inc_qs[i],
					SLOTS_WATERMARK) != 0) {
			return snobj_err(EINVAL, "Could not set watermark");
		}
	}

	/* Set up out rte_rings */
	for (i = 0; i < num_out_q; i++) {
		snprintf(ring_name, PORT_NAME_LEN + 256, 
				"%s%s%d", p->name, "outq", i);
		bar->out_qs[i] = rte_ring_create(ring_name,
				SLOTS_PER_LLRING,
				numa_node,
				SINGLE_P | SINGLE_C);
		if (bar->out_qs[i] == NULL) {
			return snobj_err(rte_errno, "Failed to allocate ring");
		}
		priv->out_qs[i] = bar->out_qs[i];
		if (rte_ring_set_water_mark(priv->out_qs[i],
					SLOTS_WATERMARK) != 0) {
			return snobj_err(EINVAL, "Could not set watermark");
		}
	}

	snprintf(port_dir, PORT_NAME_LEN + 256, "%s/%s",
			P_tmpdir, VPORT_DIR_PREFIX);

	if (stat(port_dir, &sb) == 0) {
		assert((sb.st_mode & S_IFMT) == S_IFDIR);
	} else {
		log_info("Creating directory %s\n", port_dir);
		mkdir(port_dir, S_IRWXU | S_IRWXG | S_IRWXO);
	}

	snprintf(file_name, PORT_NAME_LEN + 256, "%s/%s/%s",
			P_tmpdir, VPORT_DIR_PREFIX, p->name);
	log_info("Writing port information to %s\n", file_name);
	fp = fopen(file_name, "w");
	fwrite(&bar_address, 8, 1, fp);
	fclose(fp);
	priv->port = rte_eth_from_rings(p->name, 
			bar->inc_qs, bar->num_inc_q,
			bar->out_qs, bar->num_out_q,
			numa_node);
	if (priv->port == -1) {
		return snobj_err(EINVAL, "Could not create eth ring");
	}
	if(rte_eth_dev_configure(priv->port, 
		num_inc_q, num_out_q, &null_conf) < 0) {
		return snobj_err(EINVAL, "Could not configure port");
	}

	/* Set up both RX and TX cores */
	for (i = 0; i < num_inc_q; i++) {
		int sid = numa_node;

		ret = rte_eth_rx_queue_setup(priv->port, i, 
					     32,
					     sid, NULL,
					     get_pframe_pool_socket(sid));
		if (ret != 0) 
			return snobj_err(-ret, 
					"rte_eth_rx_queue_setup() failed");
	}

	for (i = 0; i < num_out_q; i++) {
		int sid = numa_node;

		ret = rte_eth_tx_queue_setup(priv->port, i,
					     32,
					     sid, NULL);
		if (ret != 0) 
			return snobj_err(-ret,
					"rte_eth_tx_queue_setup() failed");
	}
	rte_eth_dev_start(priv->port);
	return NULL;
}

static void vport_deinit_port(struct port *p)
{
	struct vport_priv *priv = get_port_priv(p);
	char file_name[PORT_NAME_LEN + 256];

	rte_eth_dev_stop(priv->port);

	snprintf(file_name, PORT_NAME_LEN + 256, "%s/%s/%s",
			P_tmpdir, VPORT_DIR_PREFIX, p->name);
	unlink(file_name);

	rte_free(priv->bar);
}

static int
vport_send_pkts(struct port *p, queue_t qid, snb_array_t pkts, int cnt)
{
	struct vport_priv *priv = get_port_priv(p);
	
	int sent = rte_eth_tx_burst(priv->port, qid, 
			(struct rte_mbuf **)pkts, cnt);
	return sent;
}

static int
vport_recv_pkts(struct port *p, queue_t qid, snb_array_t pkts, int cnt)
{
	struct vport_priv *priv = get_port_priv(p);
	struct pkt_batch recv_batch;
	int recv_cnt, alloc_cnt;
	int i = 0;
	recv_cnt = rte_eth_rx_burst(priv->port, qid, 
			(struct rte_mbuf **)recv_batch.pkts, cnt);

	alloc_cnt = snb_alloc_bulk(pkts, recv_cnt, 
			64);
	for (i = 0; i < MIN(recv_cnt, alloc_cnt); i++) {
		/* First copy the packet metadata */
		rte_memcpy(pkts[i], recv_batch.pkts[i],
				sizeof(struct rte_mbuf) + SNBUF_RESERVE);
		/* Then copy the actual data */
		rte_memcpy(snb_head_data(pkts[i]),
			   snb_head_data(recv_batch.pkts[i]),
			   snb_head_len(recv_batch.pkts[i]));
	}

	/* Finally free up the received batch */
	snb_free_bulk(recv_batch.pkts, recv_cnt);
	return MIN(recv_cnt, alloc_cnt);
}

static const struct driver ring_port_isolate = {
	.name 		= "RteRingVPortIsolated",
	.def_port_name	= "rte_ring",
	.priv_size	= sizeof(struct vport_priv),
	.init_port 	= vport_init_port,
	.recv_pkts 	= vport_recv_pkts,
	.send_pkts 	= vport_send_pkts,
	.deinit_port	= vport_deinit_port,
};

ADD_DRIVER(ring_port_isolate)