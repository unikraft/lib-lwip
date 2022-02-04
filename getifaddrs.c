#include <lwip/tcp.h>
#include <ifaddrs.h>

static void
sockaddr_from_ip_addr(
  struct sockaddr *sockaddr,
  const ip_addr_t *addr)
{

    memset(sockaddr, 0, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)sockaddr)->sin_len = sizeof(struct sockaddr_in);
    ((struct sockaddr_in *)sockaddr)->sin_family = AF_INET;
    inet_addr_from_ip4addr(&((struct sockaddr_in *)sockaddr)->sin_addr, ip_2_ip4(addr));
}


int getifaddrs(struct ifaddrs **ifap)
{
	struct netif *netif;
	int is_up;
	uint8_t flags;

	struct ifaddrs *prev = NULL, *ifs;
	struct ifaddrs *head;

	int ok = 0;	
	for (netif = netif_list; netif != NULL; netif = netif->next) {
		ifs = malloc(sizeof(struct ifaddrs));

		ifs->ifa_next = NULL;
		if (ok == 0) {
			ok = 1;
			head = ifs;
		}

		is_up = netif_is_up(netif);
		flags = netif->flags;
		printf("%s%d\n", netif->name, netif->num);

		ifs->ifa_flags = flags;

		char *name = malloc(3);
		sprintf(name, "%c%c%d", netif->name[0], netif->name[1], netif->num);
		ifs->ifa_name = name;
		
		struct sockaddr *t = malloc(sizeof(struct sockaddr));
		sockaddr_from_ip_addr(t, &netif->ip_addr);
		ifs->ifa_addr = t;


		struct sockaddr *netmask = malloc(sizeof(struct sockaddr));
		sockaddr_from_ip_addr(t, &netif->netmask);
		ifs->ifa_netmask = netmask;


		//t->sa_family = AF_INET;

		//printf("%s\n", ipaddr_ntoa(&netif->ip_addr));

		// struct sockaddr *ifa_addr; // &netif->ip_addr
		// struct sockaddr *ifa_netmask // &netif->netmask
		// ifa_ifu.ifu_dstaddr // netif->gw
		ifs->ifa_data = NULL;

		if (prev)
			prev->ifa_next = ifs;

		prev = ifs;
	}
	*ifap = head;
	return 0;
}

void freeifaddrs(struct ifaddrs *ifa)
{
	return 0;
}
