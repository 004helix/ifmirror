#define _GNU_SOURCE

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <netdb.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/filter.h>
#include <errno.h>
#include <err.h>


#define SECRET "0123456789abcdef"


static struct __attribute__((__packed__)) iface {
    uint8_t hwaddr[6];
    uint16_t mtu;
    uint32_t ipaddr;
    uint32_t netmask;
} iface;


static void lookup_host(char *host, char *port, struct sockaddr *addr, socklen_t *addrlen)
{
    struct addrinfo hints, *result, *rp;
    int res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4 lookup only
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    res = getaddrinfo(host, port, &hints, &result);

    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            if (addr == NULL) {
                fprintf(stderr, "lookup_host: cannot allocate memory\n");
                exit(EXIT_FAILURE);
            }

            if (*addrlen < sizeof(struct sockaddr_in)) {
                fprintf(stderr, "lookup_host: addrlen too small\n");
                exit(EXIT_FAILURE);
            }

            memcpy(addr, rp->ai_addr, rp->ai_addrlen);
            *addrlen = rp->ai_addrlen;
            freeaddrinfo(result);
            return;
        }
    }

    fprintf(stderr, "host not found: %s\n", host);
    exit(EXIT_FAILURE);
}


static int tcp_connect(struct sockaddr *addr, socklen_t addrlen)
{
    int flags;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
        err(EXIT_FAILURE, "socket AF_INET SOCK_STREAM");

    if (connect(sock, addr, addrlen) == -1)
        err(EXIT_FAILURE, "connect");

    if (write(sock, SECRET, strlen(SECRET)) == -1)
        err(EXIT_FAILURE, "write handshake");

    if (read(sock, &iface, sizeof(iface)) != sizeof(iface))
        err(EXIT_FAILURE, "read handshake");

    flags = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags)) == -1)
        err(EXIT_FAILURE, "setsockopt SOL_SOCKET SO_KEEPALIVE 1");

    if ((flags = fcntl(sock, F_GETFL, 0)) == -1)
        err(EXIT_FAILURE, "ioctl F_GETFL");

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
        err(EXIT_FAILURE, "ioctl F_SETFL");

    return sock;
}


static int udp_connect(int tcpsock)
{
    struct sockaddr_in srcaddr = { 0 };
    struct sockaddr_in dstaddr = { 0 };
    socklen_t srcaddr_len = sizeof(srcaddr);
    socklen_t dstaddr_len = sizeof(dstaddr);
    int sock;

    if (getsockname(tcpsock, (struct sockaddr *)&srcaddr, &srcaddr_len) == -1)
        err(EXIT_FAILURE, "getsockname");

    if (getpeername(tcpsock, (struct sockaddr *)&dstaddr, &dstaddr_len) == -1)
        err(EXIT_FAILURE, "getpeername");

    if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1)
        err(EXIT_FAILURE, "socket AF_INET SOCK_DGRAM 0");

    if (bind(sock, (struct sockaddr *)&srcaddr, srcaddr_len) == -1)
        err(EXIT_FAILURE, "bind udp");

    if (connect(sock, (struct sockaddr *)&dstaddr, sizeof(dstaddr)) == -1)
        err(EXIT_FAILURE, "connect udp");

    return sock;
}


static int tap_open(char *ifname)
{
    struct sockaddr_in addr;
    struct ifreq ifr;
    int flags;
    int sock;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) == -1)
        err(EXIT_FAILURE, "open /dev/net/tun");

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
        err(EXIT_FAILURE, "socket");

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl TUNSETIFF");

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, iface.hwaddr, 6);
    if (ioctl(sock, SIOCSIFHWADDR, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCSIFHWADDR");

    ifr.ifr_mtu = ntohs(iface.mtu);
    if (ioctl(sock, SIOCSIFMTU, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCSIFMTU");

    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = iface.ipaddr;
    memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
    if (ioctl(sock, SIOCSIFADDR, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCSIFADDR");

    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = iface.netmask;
    memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCSIFNETMASK");

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCGIFFLAGS");

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
        err(EXIT_FAILURE, "ioctl SIOCSIFFLAGS");

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        err(EXIT_FAILURE, "ioctl F_GETFL");

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_CLOEXEC) == -1)
        err(EXIT_FAILURE, "ioctl F_SETFL");

    close(sock);
    return fd;
}


static void udp_read(int sock, int fd)
{
    char buffer[16384];
    ssize_t len = read(sock, buffer, sizeof(buffer));

    if (len == -1) {
        if (errno == EAGAIN && errno == EWOULDBLOCK)
            return;

        err(EXIT_FAILURE, "udp read");
    }

    if (len > 0)
        write(fd, buffer, len);
}


static void tap_read(int fd, int sock)
{
    char buffer[16384];
    ssize_t len = read(fd, buffer, sizeof(buffer));

    if (len == -1) {
        if (errno == EAGAIN && errno == EWOULDBLOCK)
            return;

        err(EXIT_FAILURE, "tap read");
    }

    if (len > 0)
        write(sock, buffer, len);
}


int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int tsock, usock, tapfd;
    fd_set allfds;
    fd_set rfds;
    int maxfd;
    int ready;

    if (argc < 3) {
        fprintf(stderr, "Usage: iftap <device> <host> [port] [command]\n"
                "\n"
                " device  - ethernet device to create\n"
                " address - ifraw daemon host\n"
                " port    - ifraw daemon port, default 1660\n"
                " exec    - command to execure after successful connect\n"
                "\n"
        );
    }

    lookup_host(argv[2], argc > 3 ? argv[3] : "1660",
                (struct sockaddr *)&addr, &addrlen);
    tsock = tcp_connect((struct sockaddr *)&addr, addrlen);
    usock = udp_connect(tsock);
    tapfd = tap_open(argv[1]);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    if (argc > 4) {
        pid_t pid = fork();

        if (pid == -1)
            err(EXIT_FAILURE, "fork");

        if (pid == 0) {
            execvp(argv[4], argv + 4);
            exit(EXIT_FAILURE);
        }
    }

    FD_ZERO(&allfds);
    FD_SET(tsock, &allfds);
    FD_SET(usock, &allfds);
    FD_SET(tapfd, &allfds);

    maxfd = tsock;
    if (usock > maxfd)
        maxfd = usock;
    if (tapfd > maxfd)
        maxfd = tapfd;

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

        if (FD_ISSET(tsock, &rfds))
            exit(0);

        if (FD_ISSET(usock, &rfds))
            udp_read(usock, tapfd);

        if (FD_ISSET(tapfd, &rfds))
            tap_read(tapfd, usock);
    }

    return 0;
}
