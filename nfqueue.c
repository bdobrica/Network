#include <sys/socket.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libnetfilter_queue.h"
#include "libnetfilter_queue_headers.c"
#include <linux/netfilter.h>

void analyze_packet (int len, char * data) {
	int c = 0;
	int iph_len = (((uint8_t) data[0])&0x0F)<<2;
	int tcph_len = (((uint8_t) data[iph_len+12])&0xF0)>>2;
	printf ("IP HEADER\n");
	printf ("Version & IHL: %X\n", data[0]);
	printf ("TOS %X\n", data[1]);
	printf ("Length: %X\n", data[2]<<8|data[3]);
	printf ("ID: %X\n", data[4]<<8|data[5]);
	printf ("TTL: %X\n", data[8]);
	printf ("Proto: %X\n", data[9]);
	printf ("Source: %u.%u.%u.%u\n", (uint8_t)data[12], (uint8_t)data[13], (uint8_t)data[14], (uint8_t)data[15]);
	printf ("Destination: %u.%u.%u.%u\n", (uint8_t)data[16], (uint8_t)data[17], (uint8_t)data[18], (uint8_t)data[19]);
	printf ("SPort: %u\n", (((uint8_t)data[iph_len])<<8)|((uint8_t)data[iph_len+1]));
	printf ("DPort: %u\n", (((uint8_t)data[iph_len+2])<<8)|((uint8_t)data[iph_len+3]));
	printf ("Data:\n");
	for (c = iph_len + tcph_len; c<len; c++) {
		printf ("%c", data[c]);
		}
	printf ("\n");
	}


static int manage_packet (
			struct nfq_q_handle * qh,
			struct nfgenmsg * nfmsg,
			struct nfq_data * nfa,
			void * data) {
	char * payload;
	int id = 1;
	struct nfqnl_msg_packet_hdr * ph;
	int c;
	int size;

	if ((ph = nfq_get_msg_packet_hdr(nfa)) != NULL)
		id = ntohl(ph->packet_id);
	size = nfq_get_payload (nfa, &payload);
	//payload = payload + sizeof (struct nfq_iphdr) + sizeof (struct nfq_udphdr);
	printf ("accept %d\n", id);
	analyze_packet (size, payload);
	printf ("\n");
	nfq_set_verdict (qh, id, NF_ACCEPT, 0, NULL);
	return id;
	}

int main (int * argc, char ** argv) {
	struct nfq_handle * handle;
	struct nfq_q_handle * queue;
	struct nfnl_handle * netlink_handle;
	int nfqueue_fd;

	handle = nfq_open ();
	if (!handle) {
		perror ("Error: during nfq_open()");
		exit (1);
		}
	if (nfq_unbind_pf (handle, AF_INET) < 0) {
		nfq_close (handle);
		perror ("Error: during nfq_unbind_pf()");
		exit (1);
		}
	if (nfq_bind_pf (handle, AF_INET) < 0) {
		nfq_close (handle);
		perror ("Error: during nfq_bind_pf()");
		exit (1);
		}
	
	queue = nfq_create_queue (handle, 0, &manage_packet, NULL);
	if (!queue) {
		nfq_close (handle);
		perror ("Error: during nfq_create_queue()");
		exit (1);
		}
	
	if (nfq_set_mode (queue, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
		nfq_destroy_queue (queue);
		nfq_close (handle);
		perror ("Error: can't set packet_copy mode");
		exit (1);
		}
	
	netlink_handle = nfq_nfnlh (handle);
	nfqueue_fd = nfnl_fd (netlink_handle);

	while (1) {
		char buf[4096] __attribute__ ((aligned));
		int received;
		received = recv (nfqueue_fd, buf, sizeof(buf), 0);
		if (received == -1) return;
		nfq_handle_packet (handle, buf, received);
		}

	nfq_destroy_queue (queue);
	nfq_close (handle);
	}
