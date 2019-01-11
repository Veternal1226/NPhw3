#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define SIZE_ETHERNET 14	/* ethernet headers are always exactly 14 bytes */
#define ETHER_ADDR_LEN	6	/* Ethernet addresses are 6 bytes */
#define BUFSIZE 1000

//Ethernet header
typedef struct e_h {
	u_char ether_dhost[ETHER_ADDR_LEN];	//destination host address
	u_char ether_shost[ETHER_ADDR_LEN];	//source host address
	u_short ether_type;			//IP? ARP? RARP? etc
}Ethernet_h;

//IP header
typedef struct i_h {
	u_char  ip_vhl;					//version << 4 | header length >> 2
	u_char  ip_tos;					//type of service
	u_short ip_len;					//total length
	u_short ip_id;					//identification
	u_short ip_off;					//fragment offset field
#define IP_RF 0x8000				//reserved fragment flag
#define IP_DF 0x4000				//dont fragment flag
#define IP_MF 0x2000				//more fragments flag
#define IP_OFFMASK 0x1fff			//mask for fragmenting bits
	u_char  ip_ttl;					//time to live
	u_char  ip_p;					//protocol
	u_short ip_sum;					//checksum
	struct  in_addr ip_src, ip_dst;	//source and dest address
}IP_h;
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

//TCP header
typedef u_int tcp_seq;
typedef struct t_h {
	u_short th_sport;				//source port
	u_short th_dport;				//destination port
	tcp_seq th_seq;					//sequence number
	tcp_seq th_ack;					//acknowledgement number
	u_char  th_offx2;				//data offset, rsvd
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;					//window
	u_short th_sum;					//checksum
	u_short th_urp;					//urgent pointer
}TCP_h;

//UDP header
typedef struct uheader {
	uint16_t uh_sport;					//source port
	uint16_t uh_dport;					//destination port
	uint16_t uh_length;
	uint16_t uh_sum;				//checksum
}UDP_h;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const Ethernet_h *ethernet;	/* The ethernet header */
	const IP_h *ip;			/* The IP header */
	const TCP_h *tcp;		/* The TCP header */
	const UDP_h *udp;		/* The UDP header */
	const char *payload;                    /* Packet payload */

	/*time struct*/
	struct tm *lt;
	char timestr[80];
	time_t local_tv_sec;
	
	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	
	local_tv_sec = header->ts.tv_sec;
	lt = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%b %d %Y, %X", lt);
	
	/* define ethernet header */
	ethernet = (Ethernet_h*)(packet);
	
	/* define/compute ip header offset */
	ip = (IP_h*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	else{
		printf("\nPacket number %d:\n", count);
		count++;
		/* determine protocol */	
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				printf("   Protocol: TCP\n");
				tcp = (TCP_h*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if(size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}

				printf("       From: %s\n", inet_ntoa(ip->ip_src));
				printf("         To: %s\n", inet_ntoa(ip->ip_dst));
				printf("   Src port: %d\n", ntohs(tcp->th_sport));
				printf("   Dst port: %d\n", ntohs(tcp->th_dport));
				printf("     Length: %d bytes\n", header->len);
				printf("       Time: %s\n", timestr);
				break;
			case IPPROTO_UDP:
				printf("   Protocol: UDP\n");
				udp = (UDP_h*)(packet + SIZE_ETHERNET + size_ip);
				printf("       From: %s\n", inet_ntoa(ip->ip_src));
				printf("         To: %s\n", inet_ntoa(ip->ip_dst));
				printf("   Src port: %d\n", ntohs (udp->uh_sport));
				printf("   Dst port: %d\n", ntohs (udp->uh_dport));
				printf("     Length: %d bytes\n", ntohs(udp->uh_length));
				printf("       Time: %s\n", timestr);
				break;
			case IPPROTO_ICMP:
				printf("   Protocol: ICMP\n");
				printf("       From: %s\n", inet_ntoa(ip->ip_src));
				printf("         To: %s\n", inet_ntoa(ip->ip_dst));
				printf("     Length: %d bytes\n",header->len);
				printf("       Time: %s\n", timestr);
				break;
			case IPPROTO_IP:
				printf("   Protocol: IP\n");
				printf("       From: %s\n", inet_ntoa(ip->ip_src));
				printf("         To: %s\n", inet_ntoa(ip->ip_dst));
				printf("     Length: %d bytes\n",header->len);
				printf("       Time: %s\n", timestr);
				break;
			default:
				printf("   Protocol: unknown\n");
				printf("       From: %s\n", inet_ntoa(ip->ip_src));
				printf("         To: %s\n", inet_ntoa(ip->ip_dst));
				printf("     Length: %d bytes\n",header->len);
				printf("       Time: %s\n", timestr);
		}
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if (size_payload > 0) {
		printf("    Payload: %d bytes\n", size_payload);
		//print_payload(payload, size_payload);
	}
	return;
}

int main(int argc, char *argv[])
{
	if(argc<2)
	{
		fprintf(stdout,"please input test filename\n");
		return 0;
	}
	int filter_flag=0;
	int i;
	char argv_buf[BUFSIZE]="";
	pcap_t *handle = NULL;
	char errBuff[PCAP_ERRBUF_SIZE];
	if(argc>2)
	{
		filter_flag=1;
		for(i=2;i<argc;i++)
		{
			strcat(argv_buf,argv[i]);
			if(i!=argc-1)
				strcat(argv_buf," ");
		}
		printf("command=%s\n",argv_buf);
	}
	fprintf (stdout, "test filename=%s\n", argv[1]);
	handle = pcap_open_offline( argv[1] , errBuff);
	if (handle == NULL) {
		fprintf(stderr, "Error: %s\n", errBuff);
		return (EXIT_FAILURE);
	}
	//set filter
	if(filter_flag)
	{
		struct bpf_program fp;		/* The compiled filter expression */
		char *filter_exp = argv_buf;	/* The filter expression */
		bpf_u_int32 net;		/* The IP of our sniffing device */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
	}
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return (EXIT_SUCCESS);
}
