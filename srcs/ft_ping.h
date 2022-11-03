#ifndef FT_PING_H
#define FT_PING_H

#define FLAG_VERBOSE 0x1
#define DEFAULT_PING_PACKET_SIZE 64
#define DEFAULT_PING_INTERVAL 1
#define DEFAULT_PING_RECV_TIMEOUT 1
#define DEFAULT_PING_TTL 64

struct s_ping_config
{
	char *hostname;
	char *hostname_ip_str;
	unsigned char ttl;
	unsigned int flags;
	unsigned int recv_timeout;
	unsigned int ping_interval;
	unsigned int packet_size;
};

#endif