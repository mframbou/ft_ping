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

#include <libft.h>

#define FLAG_VERBOSE 0x1
#define WAIT_INTERVAL_SEC 1
#define PING_PKT_SIZE 64

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
    char msg[PING_PKT_SIZE - sizeof(struct icmphdr)];
};


// Calculating the Check Sum
unsigned short checksum(void *b, int len)
{    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


int main(int argc, char **argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "ft_ping: usage error: Destination address required\n");
		exit(EXIT_FAILURE);
	}

	const char *ping_hostname = NULL;
	unsigned long flags = 0;


	for (int i = 1; i < argc; i++)
	{
		if (!ft_strcmp(argv[i], "-h"))
		{
			show_usage();
			exit(EXIT_FAILURE);
		}
		else if (!ft_strcmp(argv[i], "-v"))
		{
			flags |= FLAG_VERBOSE;
		}
		else
		{
			ping_hostname = argv[i];
		}
	}

	if (flags & FLAG_VERBOSE)
	{
		printf("Verbose mode\n");
	}

	int sockfd;

	// https://stackoverflow.com/questions/8290046/icmp-sockets-linux
	if ((sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_ICMP)) == -1)
	{
		fprintf(stderr, "ft_ping: An error occured while creating socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct timeval recv_timeout;
	recv_timeout.tv_sec = WAIT_INTERVAL_SEC;
	recv_timeout.tv_usec = 0;


	unsigned char ttl = 2;
	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1)
	{
		fprintf(stderr, "ft:ping: An error occured while setting socket TTL send: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL, &ttl, sizeof(ttl)) == -1)
	{
		fprintf(stderr, "ft:ping: An error occured while setting socket TTL receive: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout)) == -1)
	{
		fprintf(stderr, "ft:ping: An error occured while setting socket timeout: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct addrinfo *address_info;

	if ((address_info = get_hostname_address(ping_hostname)) == NULL)
	{
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	char ipv4_str[INET_ADDRSTRLEN];
	inet_ntop(address_info->ai_family, address_info->ai_addr->sa_data, ipv4_str, 100);

	if (address_info->ai_family != AF_INET)
	{
		fprintf(stderr, "ft_ping: The given host address format is not supported\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}


	void *ptr = &((struct sockaddr_in *) address_info->ai_addr)->sin_addr;
	inet_ntop(address_info->ai_family, ptr, ipv4_str, sizeof(ipv4_str));

	struct ping_pkt pkt;
	int msg_count = 0;

	// https://github.com/dtaht/twd/blob/master/recvmsg.c
	char received_msg_buf[128];
	struct msghdr received_msg;
	struct iovec iov;
	struct timeval start_time;
	struct timeval end_time;

	printf("PING %s (%s) %d bytes of data.\n", ping_hostname, ipv4_str, PING_PKT_SIZE);

	while (1)
	{
		ft_bzero(&pkt, sizeof(pkt));
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

		if (sendto(sockfd, &pkt, sizeof(pkt), 0, address_info->ai_addr, address_info->ai_addrlen) == -1)
		{
			fprintf(stderr, "An error occured while sending packet to %s\n", ipv4_str);
			usleep(WAIT_INTERVAL_SEC * 1000 * 1000);
			continue;
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




		int cmsg_size = sizeof(struct cmsghdr)+sizeof(int); // NOTE: Size of header + size of data
		char buf[CMSG_SPACE(sizeof(int))];
		received_msg.msg_control = buf; // Assign buffer space for control header + header data/value
		received_msg.msg_controllen = sizeof(buf); //just initializing it


		if (recvmsg(sockfd, &received_msg, 0) == -1)
		{
			fprintf(stderr, "An error occured while receiving packet from %s\n", ipv4_str);
			if (errno != EAGAIN) // If timeout, don't re-wait another second before pinging, but ping directly
				usleep(WAIT_INTERVAL_SEC * 1000 * 1000);

			continue;
		}

		if (gettimeofday(&end_time, NULL) == -1)
		{
			fprintf(stderr, "ft_ping: An error occured while fetching end time: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		time_t elapsed_secs = end_time.tv_sec - start_time.tv_sec;
		suseconds_t elapsed_usecs = end_time.tv_usec - start_time.tv_usec;

		double elapsed_ms = elapsed_secs * 1000.0 + elapsed_usecs / 1000.0;

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

		printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1f ms\n", PING_PKT_SIZE, ping_hostname, ipv4_str, msg_count, received_ttl, elapsed_ms);
	}
}