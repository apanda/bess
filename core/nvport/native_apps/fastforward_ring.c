#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sched.h>

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_ring.h>
#include <rte_eth_ring.h>

#include <time.h>

#include "ring_bar.h"
#include "sn.h"

// Cycles to stall for
uint64_t stalled_cycles = 0;

// Print stats to stdout?
int print_stats = 0;

int batch_size = 32;

int yield = 0;

int statistics = 0;

int fake_core = -1;

int in_port;
int out_port;

struct {
	uint64_t rx_pkts;
	uint64_t rx_batch;
	uint64_t rx_bytes;

	uint64_t tx_pkts;
	uint64_t tx_batch;
	uint64_t tx_bytes;
} stats, last_stats;

char unique_name[APPNAMESIZ];

static int run_fastforward(void)
{
	int ret = 0;

	struct snbuf *pkts[batch_size];
	int received;
	int sent = 0;

	int i;

	/*received = sn_receive_pkts(in_port, rxq, pkts, batch_size);*/
	received = rte_eth_rx_burst(in_port, 0, (struct rte_mbuf**)pkts, 
			batch_size); 

	if (received == 0 && yield) {
		sched_yield();
	}
	if (statistics) {
		stats.rx_pkts += received;
		stats.rx_batch += (received > 0);
		stats.rx_bytes += received * 24;	/* Ethernet overheads */

		for (i = 0; i < received; i++)
			stats.rx_bytes += snb_total_len(pkts[i]);
	}

	if (stalled_cycles) {
		uint64_t start, end;
		start = rte_rdtsc();
		end = start;
		while (end - start < stalled_cycles)
			end = rte_rdtsc();
	}

	
	while (sent < received) {
		sent += rte_eth_tx_burst(out_port, 0, 
				(struct rte_mbuf**)&pkts[sent], received - sent);
	}

	stats.tx_pkts += sent;
	stats.tx_batch++;

	/* free unsent packets */
	for (i = sent; i < received; i++) {
		/* Slow since packets are freed on this (remote) core */
		assert(0);
		snb_free(pkts[i]);
		pkts[i] = NULL;
	}

	ret += received;
	ret += sent;

	return ret;
}

void show_usage(char *prog_name)
{
	fprintf(stderr, "Usage: %s -i <input iface> -o <output iface>"
		"[-r <rate mbps>] "
		"[-c <core id>] [-p <packet size>] [-b <batch size>]\n",
		prog_name);
	exit(1);
}

/** Initialize a port. If inc is 1, the port is set to the global
 * incoming port. Otherwise, it's set to the outgoing port. */
#define PORT_DIR_PREFIX "sn_vports"
void init_ring_port(const char *ifname, int inport)
{
	struct rte_ring_bar *bar;
	int i;

	FILE* fd;
	char port_file[PORT_FNAME_LEN];
	int port;
	struct rte_eth_conf null_conf;
	memset(&null_conf, 0, sizeof(struct rte_eth_conf));

	snprintf(port_file, PORT_FNAME_LEN, "%s/%s/%s", 
			P_tmpdir, VPORT_DIR_PREFIX, ifname);
	fd = fopen(port_file, "r");
	assert(fd != NULL);
	/*[> Assuming we need to read one pointer <]*/
	i = fread(&bar, 8, 1, fd);
	fclose(fd);
	assert (i == 1);
	assert(bar != NULL);
	printf("Found bar with %d rings\n", bar->num_out_q);
	port = rte_eth_from_rings(ifname,
			bar->out_qs, bar->num_out_q,
			bar->inc_qs, bar->num_inc_q,
			0);
	assert(port != -1);

	// Do not call rte_eth_dev_configure, else everything breaks

	rte_eth_rx_queue_setup(port, 0, 32, 0, NULL, mempool);
	rte_eth_tx_queue_setup(port, 0, 32, 0, NULL);

	if (inport)
		in_port = port;
	else
		out_port = port;
}

void emit_stats(uint64_t loop_count, uint64_t idle_count)
{
	printf("Idle: %4.1f%%\t\t"
	       "RX: %8lu pkts/s (%4.1f pkts/batch) %7.1f Mbps\t\t"
	       "TX: %8lu pkts/s (%4.1f pkts/batch) %7.1f Mbps\n",
	       (double)idle_count * 100 / loop_count,
	       stats.rx_pkts - last_stats.rx_pkts,
	       (double)(stats.rx_pkts - last_stats.rx_pkts) /
	       ((stats.rx_batch - last_stats.rx_batch) ? : 1),
	       (double)(stats.rx_bytes - last_stats.rx_bytes)
	       * 8 / 1000000,
	       stats.tx_pkts - last_stats.tx_pkts,
	       (double)(stats.tx_pkts - last_stats.tx_pkts) /
	       ((stats.tx_batch - last_stats.tx_batch) ? : 1),
	       (double)(stats.tx_bytes - last_stats.tx_bytes)
	       * 8 / 1000000
	       );
}

int main(int argc, char **argv)
{
	uint64_t last_tsc;
	uint64_t hz;

	uint64_t loop_count = 0;
	//uint64_t idle_count = 0;

	// eh..how do i handle this.
	uint64_t core = 7;

	char in_ifname[IFNAMSIZ];
	char out_ifname[IFNAMSIZ];

	char *endptr;

	int idle;

	memset(in_ifname, 0, sizeof(in_ifname));
	memset(out_ifname, 0, sizeof(out_ifname));

	printf("Launched!\n");

	int opt;

	while ((opt = getopt(argc, argv, "c:i:o:r:n:v:peys")) != -1) {
		switch (opt) {
		case 'c':
			core = atoi(optarg);
			break;
		case 'i':
			strncpy(in_ifname, optarg, IFNAMSIZ);
			break;
		case 'o':
			strncpy(out_ifname, optarg, IFNAMSIZ);
			break;
		case 'n':
			strncpy(unique_name, optarg, APPNAMESIZ);
			break;
		case 'r':
			stalled_cycles = strtoul(optarg, &endptr, 10);
			if (endptr == optarg) {
				show_usage(argv[0]);
				exit(1);
			}
			break;
		case 'p':
			print_stats = 1;
			break;
		case 'y':
			yield = 1;
			break;
		case 's':
			statistics = 1;
			break;
		case 'v':
			fake_core = atoi(optarg);
			break;
		default:
			show_usage(argv[0]);
		}
	}

	if (!unique_name[0]) {
		// Choose a random unique name if one isn't provided
		snprintf(unique_name, sizeof(unique_name), "%u", rand());
	}

	if (fake_core == -1) {
		fake_core = core;
	}

	init_softnic(core, unique_name);
	RTE_PER_LCORE(_lcore_id) = fake_core;

	printf("Started fastforward with unique name %s\n", unique_name);
	printf("registering input port %s\n", in_ifname);
	printf("registering output port %s\n", out_ifname);


	init_ring_port(in_ifname, 1);
	if (strncmp(in_ifname, out_ifname, IFNAMSIZ) == 0) {
		out_port = in_port;
	} else {
		init_ring_port(out_ifname, 0);
	}

	hz = rte_get_tsc_hz();
	last_tsc = rte_rdtsc();

	// Main run loop
	for (;; loop_count++) {
		if (run_fastforward() > 0)
			idle = 0;
	}
	return 0;
}
