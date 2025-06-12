#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <linux/icmp.h>
#include <netinet/ip.h>
#include <signal.h>

#include <libft.h>
#include "./ft_ping.h"

struct s_ping_config g_ping_config;
unsigned int msg_count = 0;

double get_elapsed_ms(struct timeval *start, struct timeval *end)
{
	time_t elapsed_secs = end->tv_sec - start->tv_sec;
	suseconds_t elapsed_usecs = end->tv_usec - start->tv_usec;

	return elapsed_secs * 1000.0 + elapsed_usecs / 1000.0;
}

void display_stats()
{
	struct timeval now;

	if (gettimeofday(&now, NULL) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while fetching end time: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	double program_total_time_ms = get_elapsed_ms(&g_ping_config.start_time, &now);

	printf("\n--- %s ping statistics ---\n", g_ping_config.hostname);
	int pkt_losts = g_ping_config.stats.transmitted_pkts - g_ping_config.stats.received_pkts;
	double pkt_loss = g_ping_config.stats.transmitted_pkts == 0 ? 0 : pkt_losts / (double) g_ping_config.stats.transmitted_pkts;
	printf("%d packets transmitted, %d received, %d%% packet loss, time %dms\n", g_ping_config.stats.transmitted_pkts, g_ping_config.stats.received_pkts, (int)(pkt_loss * 100), (int)program_total_time_ms);
	// RTT = Round Trip Time
	printf("rtt min/avg/max = %.03f/%.03f/%.03f ms\n", g_ping_config.stats.min_ping_time, g_ping_config.stats.avg_ping_time, g_ping_config.stats.max_ping_time);
}

void handle_sigint(int signal)
{
	if (signal != SIGINT)
		return;

	display_stats();
	exit(EXIT_SUCCESS);
}

void show_usage()
{
	fprintf(stderr, "Usage: ft_ping [options] <destination>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Send ICMP ECHO_REQUESTs to <destination>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Opions:\n");
	fprintf(stderr, " <destination>\tDNS name or ip address\n");
	fprintf(stderr, " -v\t\tVerbose output\n");
	fprintf(stderr, " -h\t\tPrint help and exit\n");

	fprintf(stderr, " -b\t\tAllow pinging broadcast\n");
	fprintf(stderr, " -d\t\tUse SO_DEBUG socket option\n");
	fprintf(stderr, " -q\t\tquiet output\n");
	fprintf(stderr, " -t <ttl>\tDefine time to live\n");

	fprintf(stderr, "\nIPv4 options:\n");
	fprintf(stderr, " -4\t\tUse IPv4\n");
}

struct addrinfo *get_hostname_address(const char *hostname)
{
	struct addrinfo *res;
	int ret;

	if ((ret = getaddrinfo(hostname, NULL, NULL, &res)) < 0)
	{
		fprintf(stderr, "ft_ping: An error occured while retrieving host '%s' IPv4 address: %s\n", hostname, gai_strerror(ret));
		return NULL;
	}

	return res;
}


struct ping_pkt
{
    struct icmphdr hdr;
    char *msg;
};


// https://en.wikipedia.org/wiki/Internet_checksum#:~:text=The%20Internet%20checksum%20is%20mandatory,packets%20(including%20data%20payload).
// https://stackoverflow.com/questions/55218931/calculating-checksum-for-icmp-echo-request-in-python
unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
    unsigned short result;
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void ft_ping(int sockfd, struct addrinfo *address_info)
{
	void *ptr = &((struct sockaddr_in *) address_info->ai_addr)->sin_addr;
	inet_ntop(address_info->ai_family, ptr, g_ping_config.hostname_ip_str, sizeof(g_ping_config.hostname_ip_str));

	struct ping_pkt pkt;

	char pkt_msg[g_ping_config.packet_size - sizeof(struct icmphdr)];
	// https://github.com/dtaht/twd/blob/master/recvmsg.c
	char received_msg_buf[1024];
	struct msghdr received_msg;
	struct iovec iov;
	struct timeval start_time;
	struct timeval end_time;
	ft_bzero(&pkt, sizeof(pkt));
	pkt.msg = pkt_msg;
	pkt.hdr.type = ICMP_ECHO;
	pkt.hdr.un.echo.id = getpid();

	int i;

	for (i = 0; i < sizeof(pkt.msg) - 1; i++)
		pkt.msg[i] = i + '0';

	pkt.msg[i] = 0;
	pkt.hdr.un.echo.sequence = msg_count++;
	pkt.hdr.checksum = checksum(&pkt, sizeof(pkt));

	if (gettimeofday(&start_time, NULL) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while fetching start time: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	g_ping_config.stats.transmitted_pkts++;
	if (sendto(sockfd, &pkt, sizeof(pkt), 0, address_info->ai_addr, address_info->ai_addrlen) == -1)
	{
		if (g_ping_config.flags & FLAG_VERBOSE)
			fprintf(stderr, "An error occured while sending packet to %s\n", g_ping_config.hostname_ip_str);
		return;
	}

	// printf("Sent packed to %s\n", addrstr);

	ft_bzero(&received_msg, sizeof(received_msg));

	received_msg.msg_name = received_msg_buf;
	received_msg.msg_namelen = sizeof(received_msg_buf);
	ft_bzero(&iov, sizeof(iov));
	received_msg.msg_iov = &iov;
	received_msg.msg_iovlen = 1;
	iov.iov_base = (char *) &pkt;
	iov.iov_len = sizeof(pkt);

	char buf[CMSG_SPACE(sizeof(int))];
	received_msg.msg_control = buf;
	received_msg.msg_controllen = sizeof(buf);

	if (recvmsg(sockfd, &received_msg, 0) == -1)
	{
		if (g_ping_config.flags & FLAG_VERBOSE)
			fprintf(stderr, "An error occured while receiving packet from %s\n", g_ping_config.hostname_ip_str);

		return;
	}

	if (gettimeofday(&end_time, NULL) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while fetching end time: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	g_ping_config.stats.received_pkts++;
	double elapsed_ms = get_elapsed_ms(&start_time, &end_time);

	if (g_ping_config.stats.received_pkts == 1)
	{
		g_ping_config.stats.min_ping_time = elapsed_ms;
		g_ping_config.stats.avg_ping_time = elapsed_ms;
		g_ping_config.stats.max_ping_time = elapsed_ms;
	}
	else
	{
		if (elapsed_ms < g_ping_config.stats.min_ping_time)
			g_ping_config.stats.min_ping_time = elapsed_ms;

		if (elapsed_ms > g_ping_config.stats.max_ping_time)
			g_ping_config.stats.max_ping_time = elapsed_ms;

		double new_avg = g_ping_config.stats.avg_ping_time * (g_ping_config.stats.received_pkts - 1);
		new_avg += elapsed_ms;
		new_avg /= g_ping_config.stats.received_pkts;
		g_ping_config.stats.avg_ping_time = new_avg;
	}

	int received_ttl = -1;
	// see example: https://man7.org/linux/man-pages/man3/cmsg.3.html
	// also https://github.com/dtaht/twd/blob/master/recvmsg.c
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&received_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&received_msg, cmsg))
	{
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
		{
			ft_memcpy(&received_ttl, CMSG_DATA(cmsg), sizeof(received_ttl));
			break;
		}
	}

	char resolved_hostname[NI_MAXHOST];
	struct sockaddr_in *addr = (struct sockaddr_in *)received_msg.msg_name;
	memset(resolved_hostname, 0, sizeof(resolved_hostname));

	if (getnameinfo((struct sockaddr *)addr, sizeof(*addr), resolved_hostname, sizeof(resolved_hostname), NULL, 0, NI_NAMEREQD) != 0)
	{
		strncpy(resolved_hostname, g_ping_config.hostname, sizeof(resolved_hostname) - 1);
		resolved_hostname[sizeof(resolved_hostname) - 1] = '\0';
	}

	printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.2f ms\n", g_ping_config.packet_size, resolved_hostname, g_ping_config.hostname_ip_str, msg_count, received_ttl, elapsed_ms);
}

void handle_sigalarm(int signal)
{
	if (signal != SIGALRM)
		return;

	alarm(g_ping_config.ping_interval);
	ft_ping(g_ping_config.sockfd, g_ping_config.target_addr);
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "ft_ping: usage error: Destination address required\n");
		exit(EXIT_FAILURE);
	}

	ft_bzero(&g_ping_config, sizeof(g_ping_config));

	g_ping_config.packet_size = DEFAULT_PING_PACKET_SIZE;
	g_ping_config.ping_interval = DEFAULT_PING_INTERVAL;
	g_ping_config.recv_timeout = DEFAULT_PING_RECV_TIMEOUT;
	g_ping_config.ttl = DEFAULT_PING_TTL;

	for (int i = 1; i < argc; i++)
	{
		if (!ft_strcmp(argv[i], "-h"))
		{
			show_usage();
			exit(EXIT_FAILURE);
		}
		else if (!ft_strcmp(argv[i], "-v"))
		{
			g_ping_config.flags |= FLAG_VERBOSE;
		}
		else if (!ft_strcmp(argv[i], "-d"))
		{
			g_ping_config.flags |= FLAG_DEBUG;
		}
		else if (!ft_strcmp(argv[i], "-q"))
		{
			g_ping_config.flags |= FLAG_QUIET;
		}
		else if (!ft_strcmp(argv[i], "-4"))
		{
			// do nothing :)
		}
		else if (!ft_strcmp(argv[i], "-b"))
		{
			g_ping_config.flags |= FLAG_ALLOW_BROADCAST;
		}
		else if (!ft_strcmp(argv[i], "-t"))
		{
			if (i + 1 >= argc)
			{
				fprintf(stderr, "ft_ping: option requires an argument -- 't'\n");
				show_usage();
				exit(EXIT_FAILURE);
			}

			if (ft_strlen(argv[i + 1]) > 3)
			{
				fprintf(stderr, "ft_ping: invalid argument: '%s': out of range: 0 <= value <= 255\n", argv[i + 1]);
				exit(EXIT_FAILURE);
			}
			int ttl = ft_atoi(argv[i + 1]);
			if (ttl < 0 || ttl > 255)
			{
				fprintf(stderr, "ft_ping: invalid argument: '%s': out of range: 0 <= value <= 255\n", argv[i + 1]);
				exit(EXIT_FAILURE);
			}

			g_ping_config.ttl = ttl;
			i++;
		}
		else
		{
			g_ping_config.hostname = argv[i];
			g_ping_config.hostname = argv[i];
		}
	}

	if (g_ping_config.hostname == NULL)
	{
		fprintf(stderr, "ft_ping: usage error: Destination address required\n");
		exit(EXIT_FAILURE);
	}


	int sockfd;
	if (signal(SIGINT, &handle_sigint) == SIG_ERR)
	{
		fprintf(stderr, "ft_ping: Cannot set-up SIGINT signal handler: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (signal(SIGALRM, &handle_sigalarm)== SIG_ERR)
	{
		fprintf(stderr, "ft_ping: Cannot set-up SIGALRM signal handler: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// https://stackoverflow.com/questions/8290046/icmp-sockets-linux
	if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while creating socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	g_ping_config.sockfd = sockfd;

	struct timeval recv_timeout;
	recv_timeout.tv_sec = g_ping_config.recv_timeout;
	recv_timeout.tv_usec = 0;

	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &g_ping_config.ttl, sizeof(g_ping_config.ttl)) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while setting socket TTL send: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL, &g_ping_config.ttl, sizeof(g_ping_config.ttl)) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while setting socket TTL receive: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout)) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while setting socket timeout: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((g_ping_config.flags & FLAG_DEBUG) && setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, NULL, 0))
	{
		fprintf(stderr, "ft_ping: Cannot set socket SO_DEBUG mode: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct addrinfo *address_info;

	if ((address_info = get_hostname_address(g_ping_config.hostname)) == NULL)
	{
		close(sockfd);
		exit(EXIT_FAILURE);
	}


	void *ptr = &((struct sockaddr_in *) address_info->ai_addr)->sin_addr;
	inet_ntop(address_info->ai_family, ptr, g_ping_config.hostname_ip_str, sizeof(g_ping_config.hostname_ip_str));

	if (address_info->ai_family != AF_INET)
	{
		fprintf(stderr, "ft_ping: The given host address format is not supported\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	g_ping_config.target_addr = address_info;

	struct sockaddr_in *addr = (struct sockaddr_in *)address_info->ai_addr;
	if (addr->sin_addr.s_addr == INADDR_BROADCAST && (g_ping_config.flags & FLAG_ALLOW_BROADCAST) == 0)
	{
		fprintf(stderr, "ft_ping: Do you want to ping broadcast? Then -b. If not, check your firewall rules\n");
		exit(EXIT_FAILURE);
	}

	if (gettimeofday(&g_ping_config.start_time, NULL) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while fetching start time: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("PING %s (%s) %d bytes of data.\n", g_ping_config.hostname, g_ping_config.hostname_ip_str, g_ping_config.packet_size);

	alarm(g_ping_config.ping_interval);
	ft_ping(sockfd, address_info);

	for(;;);
}