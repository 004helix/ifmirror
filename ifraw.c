#define _GNU_SOURCE

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <errno.h>
#include <err.h>


#define SECRET "0123456789abcdef"


static struct client {
    struct client *next;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    char secret[16];
    int secret_len;
    int auth;
    int tfd;
    int ufd;
} *clients = NULL;


static int ifindex = -1;
static struct __attribute__((__packed__)) iface {
    uint8_t hwaddr[6];
    uint16_t mtu;
    uint32_t ipaddr;
    uint32_t netmask;
} iface;


static int create_tcp_socket(int port)
{
    struct sockaddr_in addr;
    int sock, reuse = 1;

    if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
        err(EXIT_FAILURE, "socket AF_INET SOCK_STREAM 0");

    reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
        err(EXIT_FAILURE, "setsockopt SOL_SOCKET SO_REUSEADDR 1");

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        err(EXIT_FAILURE, "bind");

    if (listen(sock, 5) == -1)
        err(EXIT_FAILURE, "listen");

    return sock;
}


static int create_udp_socket(int tcpsock)
{
    struct sockaddr_in addr;
    int sock, reuse = 1;

    if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1)
        err(EXIT_FAILURE, "socket AF_INET SOCK_DGRAM 0");

    reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
        err(EXIT_FAILURE, "setsockopt SOL_SOCKET SO_REUSEADDR 1");

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        err(EXIT_FAILURE, "bind");

    return sock;
}


static int create_raw_socket(char *ifname)
{
    struct sock_filter bpfcode[6];
    struct sock_fprog bpf = { 6, bpfcode };
    struct sockaddr_ll addr = {0};
    struct ifreq ifr;
    int sock;

    if ((sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL))) == -1)
        err(EXIT_FAILURE, "socket AF_PACKET SOCK_RAW ETH_P_ALL");

    // get interface index
    if (strlen(ifname) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "interface name is too long: %s\n", ifname);
        exit(EXIT_FAILURE);
    }

    strcpy(ifr.ifr_name, ifname);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCGIFINDEX");

    ifindex = ifr.ifr_ifindex;

    // bind raw socket to interface
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        err(EXIT_FAILURE, "bind");

    // get interface hwaddr
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCGIFHWADDR");

    memcpy(iface.hwaddr, ifr.ifr_hwaddr.sa_data, 6);

    if (memcmp(iface.hwaddr, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "Unknown %s hwaddr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                ifname, iface.hwaddr[0], iface.hwaddr[1], iface.hwaddr[2],
                iface.hwaddr[3], iface.hwaddr[4], iface.hwaddr[5]);
        exit(EXIT_FAILURE);
    }

    // create bpf filter to accept only incoming unicast address
    // ldw [0]
    bpfcode[0] = (struct sock_filter){BPF_LD | BPF_W | BPF_ABS, 0, 0, 0};
    // jeq <first 4 bytes of mac>, L2, L5
    bpfcode[1] = (struct sock_filter){BPF_JMP | BPF_JEQ | BPF_K, 0, 2, ntohl(*((uint32_t *)iface.hwaddr))};
    // ldh [4]
    bpfcode[2] = (struct sock_filter){BPF_LD | BPF_H | BPF_ABS, 0, 0, 4};
    // jeq <last 2 bytes of mac>, L5, L4
    bpfcode[3] = (struct sock_filter){BPF_JMP | BPF_JEQ | BPF_K, 1, 0, ntohl(*((uint16_t *)(iface.hwaddr + 4)))};
    // ret 0x0
    bpfcode[4] = (struct sock_filter){BPF_RET | BPF_K, 0, 0, 0};
    // ret 0xffffffff
    bpfcode[5] = (struct sock_filter){BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF};

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) == -1)
        err(EXIT_FAILURE, "setsockopt ATTACH_FILTER");

    // get interface mtu
    if (ioctl(sock, SIOCGIFMTU, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCGIFMTU");

    iface.mtu = htons(ifr.ifr_mtu);

    // get interface ipv4 addr
    if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCGIFMTU");

    memcpy(&iface.ipaddr, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr), 4);

    // get interface ipv4 netmask
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCGIFNETMASK");

    memcpy(&iface.netmask, &(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr), 4);

    return sock;
}


int tcp_accept(int sock)
{
    int optval = 1;
    socklen_t optlen = sizeof(optval);
    struct client *client = malloc(sizeof(struct client));

    if (client == NULL) {
        fprintf(stderr, "cannot allocate memory\n");
        return -1;
    }

    client->addr_len = sizeof(client->addr);
    client->tfd = accept4(sock,
                          (struct sockaddr *)&client->addr,
                          &client->addr_len,
                          SOCK_CLOEXEC | SOCK_NONBLOCK);

    if (client->tfd == -1) {
        free(client);
        return -1;
    }

    if (setsockopt(client->tfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) == -1)
        warn("setsockopt SOL_SOCKET SO_KEEPALIVE 1");

    client->secret_len = 0;
    client->auth = 0;
    client->ufd = -1;
    client->next = clients;
    clients = client;

    return client->tfd;
}


static void raw_read(int rsock, int usock)
{
    char buffer[16384];
    struct client *client;
    ssize_t len = recvfrom(rsock, buffer, sizeof(buffer), 0, NULL, NULL);

    if (len == -1) {
        if (errno == EAGAIN && errno == EWOULDBLOCK)
            return;

        err(EXIT_FAILURE, "recvfrom raw");
    }

    for (client = clients; client; client = client->next)
        if (client->auth)
            sendto(usock, buffer, len, MSG_NOSIGNAL | MSG_DONTWAIT,
                   (struct sockaddr *)&client->addr, client->addr_len);
}


static void udp_read(int usock, int rsock)
{
    int found = 0;
    char buffer[16384];
    struct client *client;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    ssize_t len = recvfrom(usock, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&addr, &addr_len);

    if (len == -1) {
        if (errno == EAGAIN && errno == EWOULDBLOCK)
            return;

        err(EXIT_FAILURE, "recvfrom UDP");
    }

    // minimum size is the ethernet header lenght
    if (len < 14)
        return;

    // find address in connected clients
    for (client = clients; client; client = client->next)
        if (client->auth) {
            if (client->addr.ss_family != addr.ss_family)
                continue;

            if (addr.ss_family == AF_INET) {
                if (((struct sockaddr_in *)(&client->addr))->sin_port !=
                    ((struct sockaddr_in *)(&addr))->sin_port)
                    continue;

                if (((struct sockaddr_in *)(&client->addr))->sin_addr.s_addr !=
                    ((struct sockaddr_in *)(&addr))->sin_addr.s_addr)
                    continue;

                found = 1;
                break;
            }

            // TODO: AF_INET6
        }

    if (found) {
        struct sockaddr_ll ll = {
            .sll_ifindex = ifindex,
            .sll_halen = 6
        };

        // copy destination address from packet
        memcpy(ll.sll_addr, buffer, 6);

        sendto(rsock, buffer, len, 0, (struct sockaddr *)&ll, sizeof(struct sockaddr_ll));
    }
}


int tcp_read(struct client *client)
{
    ssize_t len;

    if (client->auth)
        return -1;

    len = read(client->fd, client->secret + client->secret_len,
               sizeof(client->secret) - client->secret_len);

    if (len == -1) {
        if (errno == EAGAIN && errno == EWOULDBLOCK)
            return 0;

        return -1;
    }

    if (len == 0)
        return -1;

    client->secret_len += len;

    if (client->secret_len < sizeof(client->secret))
        return 0;

    if (memcmp(client->secret, SECRET, sizeof(client->secret)))
        return -1;

    write(client->fd, &iface, sizeof(iface));
    client->auth = 1;

    return 0;
}


static struct client *client_close(struct client *client)
{
    struct client *next = client->next;

    if (client == clients)
        clients = client->next;
    else {
        struct client *curr;

        for (curr = clients; curr->next != client;)
            curr = curr->next;

        curr->next = client->next;
    }

    close(client->fd);
    free(client);

    return next;
}


int main(int argc, char **argv)
{
    struct client *client, *c;
    int tsock = create_tcp_socket(1660);
    int usock = create_udp_socket(1660);
    int rsock;
    int maxfd;
    int ready;
    fd_set rfds;
    fd_set allfds;

    if (argc < 2) {
        fprintf(stderr, "Usage: ifraw <device> [address] [port]\n"
                "\n"
                " device  - ethernet device to mirror\n"
                " address - listen ipv4 address, default 0.0.0.0 (not implemented)\n"
                " port    - listen port, default 1660 (not implemented)\n"
                "\n");
        return 1;
    }

    rsock = create_raw_socket(argv[1]);

    maxfd = tsock;
    if (usock > maxfd)
        maxfd = usock;
    if (rsock > maxfd)
        maxfd = rsock;

    FD_ZERO(&allfds);
    FD_SET(rsock, &allfds);
    FD_SET(tsock, &allfds);
    FD_SET(usock, &allfds);

    // main loop
    for (;;) {
        rfds = allfds;
        ready = select(maxfd + 1, &rfds, NULL, NULL, NULL);

        if (ready == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;

            err(EXIT_FAILURE, "select");
        }

        if (ready == 0)
            continue;

        if (FD_ISSET(tsock, &rfds)) {
            int fd = tcp_accept(tsock);

            if (fd > maxfd)
                maxfd = fd;

            if (fd != -1)
                FD_SET(fd, &allfds);
        }

        if (FD_ISSET(rsock, &rfds))
            raw_read(rsock, usock);

        if (FD_ISSET(usock, &rfds))
            udp_read(usock, rsock);

        for (client = clients; client;) {
            if (FD_ISSET(client->fd, &rfds)) {
                if (tcp_read(client) == -1) {
                    FD_CLR(client->fd, &allfds);
                    client = client_close(client);

                    maxfd = tsock;
                    if (usock > maxfd)
                        maxfd = usock;
                    if (rsock > maxfd)
                        maxfd = rsock;

                    for (c = clients; c; c = c->next)
                        if (c->fd > maxfd)
                            maxfd = c->fd;
                } else
                    client = client->next;
            } else
                client = client->next;
        }
    }

    return 0;
}
