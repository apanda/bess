#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_config.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>

#include "../driver.h"
#include "../port.h"
#include "../snbuf.h"

/* This is the same thing as vport_zc except for using rte_ring instead of
 * Bess */

#define SLOTS_PER_LLRING	1024

/* This watermark is to detect congestion and cache bouncing due to
 * head-eating-tail (needs at least 8 slots less then the total ring slots).
 * Not sure how to tune this... */
#define SLOTS_WATERMARK		((SLOTS_PER_LLRING >> 3) * 7)	/* 87.5% */

/* Disable (0) single producer/consumer mode for now.
 * This is slower, but just to be on the safe side. :) */
#define SINGLE_P		0
#define SINGLE_C		0

#define VPORT_DIR_PREFIX "sn_vports"
#define RTE_RING_NAME "vport_ring"

struct vport_inc_regs {
	uint64_t dropped;
} __cacheline_aligned;

struct vport_out_regs {
	uint32_t irq_enabled;
} __cacheline_aligned;

/* This is equivalent to the old bar */
struct rte_ring_bar {
	char name[PORT_NAME_LEN];

	/* The term RX/TX could be very confusing for a virtual switch.
	 * Instead, we use the "incoming/outgoing" convention:
	 * - incoming: outside -> SoftNIC
	 * - outgoing: SoftNIC -> outside */
	int num_inc_q;
	int num_out_q;

	struct vport_inc_regs* inc_regs[MAX_QUEUES_PER_DIR];
	struct rte_ring* inc_qs[MAX_QUEUES_PER_DIR];

	struct vport_out_regs* out_regs[MAX_QUEUES_PER_DIR];
	struct rte_ring* out_qs[MAX_QUEUES_PER_DIR];
};

struct vport_priv {
	struct rte_ring_bar* bar;

	struct vport_inc_regs* inc_regs[MAX_QUEUES_PER_DIR];
	struct rte_ring* inc_qs[MAX_QUEUES_PER_DIR];

	struct vport_out_regs* out_regs[MAX_QUEUES_PER_DIR];
	struct rte_ring* out_qs[MAX_QUEUES_PER_DIR];

	int out_irq_fd[MAX_QUEUES_PER_DIR];
	int port;
};

static struct snobj *vport_init_port(struct port *p, struct snobj *arg)
{
	struct vport_priv *priv = get_port_priv(p);
	struct rte_ring_bar *bar = NULL;

	int num_inc_q = p->num_queues[PACKET_DIR_INC];
	int num_out_q = p->num_queues[PACKET_DIR_OUT];

	int bytes_per_ring;
	int total_bytes;
	uint8_t *ptr;
	int i;
	char port_dir[PORT_NAME_LEN + 256];
	char file_name[PORT_NAME_LEN + 256];
	struct stat sb;
	FILE* fp;
	size_t bar_address;
	struct rte_ring *ring = NULL;
	int ret;
	struct rte_eth_conf null_conf;
	int numa_node = 0;

	if (snobj_eval_exists(arg, "node")) {
		numa_node = snobj_eval_int(arg, "node");
	}

	memset(&null_conf, 0, sizeof(struct rte_eth_conf));

	bytes_per_ring = rte_ring_get_memsize(SLOTS_PER_LLRING);
	total_bytes =	sizeof(struct rte_ring_bar) +
			(bytes_per_ring * (num_inc_q + num_out_q)) +
			(sizeof(struct vport_inc_regs) * (num_inc_q)) +
			(sizeof(struct vport_out_regs) * (num_out_q));

	bar = rte_zmalloc(NULL, total_bytes, 0);
	bar_address = (size_t)bar;
	assert(bar != NULL);
	priv->bar = bar;

	strncpy(bar->name, p->name, PORT_NAME_LEN);
	bar->num_inc_q = num_inc_q;
	bar->num_out_q = num_out_q;

	ptr = (uint8_t*)(bar + 1);

	/* Set up inc rte_rings */
	for (i = 0; i < num_inc_q; i++) {
		priv->inc_regs[i] = bar->inc_regs[i] =
			(struct vport_inc_regs*)ptr;
		ptr += sizeof(struct vport_inc_regs);
		ret = rte_ring_init((struct rte_ring*)ptr, 
				RTE_RING_NAME, SLOTS_PER_LLRING, 
				SINGLE_P | SINGLE_C);
		if (ret != 0) {
			return snobj_err(rte_errno, "Failed to allocate ring");
		}
		ring = (struct rte_ring*)ptr;
		if (rte_ring_set_water_mark(ring, SLOTS_WATERMARK) != 0) {
			return snobj_err(EINVAL, "Could not set watermark");
		}
		bar->inc_qs[i] = ring;
		priv->inc_qs[i] = bar->inc_qs[i];
		ptr += bytes_per_ring;
	}

	/* Set up out rte_rings */
	for (i = 0; i < num_out_q; i++) {
		priv->out_regs[i] = bar->out_regs[i] =
			(struct vport_out_regs*)ptr;
		ptr += sizeof(struct vport_out_regs);

		ret = rte_ring_init((struct rte_ring*)ptr, 
				RTE_RING_NAME, SLOTS_PER_LLRING, 
				SINGLE_P | SINGLE_C);
		if (ret != 0) {
			return snobj_err(rte_errno, "Failed to allocate ring");
		}
		ring = (struct rte_ring*)ptr;
		if (rte_ring_set_water_mark(ring, SLOTS_WATERMARK) != 0) {
			return snobj_err(EINVAL, "Could not set watermark");
		}

		bar->out_qs[i] = ring;
		priv->out_qs[i] = bar->out_qs[i];
		ptr += bytes_per_ring;
	}

	snprintf(port_dir, PORT_NAME_LEN + 256, "%s/%s",
			P_tmpdir, VPORT_DIR_PREFIX);

	if (stat(port_dir, &sb) == 0) {
		assert((sb.st_mode & S_IFMT) == S_IFDIR);
	} else {
		log_info("Creating directory %s\n", port_dir);
		mkdir(port_dir, S_IRWXU | S_IRWXG | S_IRWXO);
	}

	for (i = 0; i < num_out_q; i++) {
		snprintf(file_name, PORT_NAME_LEN + 256, "%s/%s/%s.rx%d",
				P_tmpdir, VPORT_DIR_PREFIX, p->name, i);

		mkfifo(file_name, 0666);

		priv->out_irq_fd[i] = open(file_name, O_RDWR);
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
		int sid = 0;		/* XXX */

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

	int num_out_q = p->num_queues[PACKET_DIR_OUT];
	rte_eth_dev_stop(priv->port);

	for (int i = 0; i <num_out_q; i++) {
		snprintf(file_name, PORT_NAME_LEN + 256, "%s/%s/%s.rx%d",
				P_tmpdir, VPORT_DIR_PREFIX, p->name, i);
		
		unlink(file_name);
		close(priv->out_irq_fd[i]);
	}

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
	return rte_eth_rx_burst(priv->port, qid, 
			(struct rte_mbuf **)pkts, cnt);
}

static const struct driver ring_port = {
	.name 		= "RteRingVPort",
	.def_port_name	= "bessvp",
	.priv_size	= sizeof(struct vport_priv),
	.init_port 	= vport_init_port,
	.recv_pkts 	= vport_recv_pkts,
	.send_pkts 	= vport_send_pkts,
	.deinit_port	= vport_deinit_port,
};

ADD_DRIVER(ring_port)
