#ifndef _GNU_SOURCE
#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#endif
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/if.h>
#include <string.h>
#include <getopt.h>

int ifaddr_cmp(const struct ifaddrs *a, const struct ifaddrs *b) {
    //    printf("comparing %s and %s\n", a->ifa_name, b->ifa_name);
    return strcmp(a->ifa_name, b->ifa_name);
}

void ifaddr_swap(struct ifaddrs *a, struct ifaddrs *b) {
    struct ifaddrs tmp;
    struct ifaddrs *a_next, *b_next;

    a_next = a->ifa_next;
    b_next = b->ifa_next;

    memcpy(&tmp, a, sizeof(struct ifaddrs));
    memcpy(a, b, sizeof(struct ifaddrs));
    memcpy(b, &tmp, sizeof(struct ifaddrs));

    a->ifa_next = a_next;
    b->ifa_next = b_next;

}

int ifaddr_list_sort(struct ifaddrs *head) {
    struct ifaddrs *i, *j, *min;
    int n = 0;

    for (min = i = head, n = 0; i->ifa_next != NULL; i = i->ifa_next, n++) {

        //	printf("n=%u--------------------------------------------\n", n);

        for (j = i->ifa_next; j != NULL; j = j->ifa_next) {

            if (ifaddr_cmp(j, min) < 0) {

                min = j;
                //printf("setting min to %s\n", min->ifa_name);

            }

        }
        //printf("-> swapping %s and %s\n", i->ifa_name, min->ifa_name);
        ifaddr_swap(i, min);

    }
    //printf("--------------------------------------------\n");

    return 0;
}

void print_flags(unsigned int flags) {

    if (flags & IFF_UP) {
        printf("\tInterface is up\n");
    }
    if (flags & IFF_BROADCAST) {
        printf("\tValid broadcast address set\n");
    }
    if (flags & IFF_DEBUG) {
        printf("\tInternal debugging flag set\n");
    }
    if (flags & IFF_LOOPBACK) {
        printf("\tInterface is a loopback interface\n");
    }
    if (flags & IFF_POINTOPOINT) {
        printf("\tInterface is a point-to-point link\n");
    }
    if (flags & IFF_RUNNING) {
        printf("\tInterface has resources allocated\n");
    }
    if (flags & IFF_NOARP) {
        printf("\tNo arp protocol, L2 destination address not set.\n");
    }
    if (flags & IFF_PROMISC) {
        printf("\tInterface is in promiscuous mode\n");
    }
    if (flags & IFF_NOTRAILERS) {
        printf("\tAvoid use of trailers.\n");
    }
    if (flags & IFF_ALLMULTI) {
        printf("\tReceive all multicast packets.\n");
    }
    if (flags & IFF_MASTER) {
        printf("\tMaster of a load balancing bundle.\n");
    }
    if (flags & IFF_SLAVE) {
        printf("\tSlave of a load balancing bundle.\n");
    }
    if (flags & IFF_MULTICAST) {
        printf("\tSupports multicast\n");
    }
    if (flags & IFF_PORTSEL) {
        printf("\tIs able to select media type via ifmap\n");
    }
    if (flags & IFF_AUTOMEDIA) {
        printf("\tAuto media selection active\n");
    }
    if (flags & IFF_DYNAMIC) {
        printf("\tThe addresses are lost when the interface goes down\n");
    }
    if (flags & IFF_LOWER_UP) {
        printf("\tDriver signals L1 up\n");
    }
    if (flags & IFF_DORMANT) {
        printf("\tDriver signals dormant\n");
    }
    if (flags & IFF_ECHO) {
        printf("\tEcho sent packets\n");
    }

}

struct if_candidate {
    char name[IFNAMSIZ];
    double rx_tx_ratio;
    uint64_t rx_packets;
    int not_loopback;
};

void ifaddr_list_print(struct ifaddrs *head_ifaddr, int verbose) {
    struct ifaddrs *ifa;
    int family, s, n;
    char host[NI_MAXHOST];
    char last_ifa_name[IFNAMSIZ] = { 0 };
    const char *ifa_name = "";

    /*
     * loop over linked list of interfaces
     */
    for (ifa = head_ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        // printf("new: %s\told: %s\n", ifa->ifa_name, last_ifa_name);
        if (strcmp(last_ifa_name, ifa->ifa_name) == 0) {
            /* interface name has already appeared on list; don't print it again */

        } else {
            /* new interface name; print it and copy it to last_ifa_name */
            ifa_name = ifa->ifa_name;
            strncpy(last_ifa_name, ifa_name, IFNAMSIZ);
            printf("%s\n", ifa->ifa_name);

            //   printf("\tflags: 0x%x\n", ifa->ifa_flags);
            if (verbose) {
                print_flags(ifa->ifa_flags);
            }

        }

        /* print address family */
        family = ifa->ifa_addr->sa_family;
        const char *printable_family = (family == AF_PACKET) ? "AF_PACKET" :
            (family == AF_INET) ? "AF_INET" :
            (family == AF_INET6) ? "AF_INET6" : "???";

        if (verbose) {
            printf("\t%s\t", printable_family);
        }

        /* For an AF_INET* interface address, display the address */
        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) :
                            sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", strerror(s));
                exit(EXIT_FAILURE);
            }

            if (verbose) {
                printf("\taddress: %s\n", host);
            }

        } else if (family == AF_PACKET && ifa->ifa_data != NULL) {
            struct rtnl_link_stats *stats = (struct rtnl_link_stats *) ifa->ifa_data;

            double rx_ratio = (double) stats->rx_packets / (stats->tx_packets + stats->rx_packets);
            if (verbose) {
                printf("\tpacket RX/TX ratio: %f", rx_ratio);
                printf("\t(received %10u, sent %10u)\n", stats->tx_packets, stats->rx_packets);
            //printf("\tbytes received    = %10u, sent = %10u\n", stats->tx_bytes, stats->rx_bytes);
            }
        }

    }

}

const char *lsif_help = "lists interfaces suitable for monitoring";

#define EXIT_ERR 255

void usage(const char *progname, const char *err_string) {
    if (err_string) {
        printf("error: %s\n", err_string);
    }
    printf(lsif_help, progname);
    exit(EXIT_ERR);
}

enum lsif_mode {
    unknown = 0,
    all     = 1,
    monitor = 2
};

void lsif_mode_set_from_argv(enum lsif_mode *mode, char *argv[], int argc) {
    int c;

    while(1) {
        int opt_idx = 0;
        static struct option long_opts[] = {
            { "all",         no_argument, NULL, 'a'   },
            { "help",        no_argument, NULL, 'h' },
            { "monitor",     no_argument, NULL, 'm' },
            { NULL,          0,           0,     0  }
        };
        c = getopt_long(argc, argv, "am", long_opts, &opt_idx);
        if (c < 0) {
            break;
        }
        switch(c) {
        case 'a':
            if (optarg) {
                usage(argv[0], "error: option -a or --all does not use an argument");
            } else {
                *mode = all;
            }
            break;
        case 'm':
            if (optarg) {
                usage(argv[0], "error: option -m or --monitor does not use an argument");
            } else {
                *mode = monitor;
            }
            break;
        case 'h':
            usage(argv[0], "");
            break;
        default:
            usage(argv[0], "error: unknown option\n");
        }
    }
}

int main(int argc, char *argv[]) {

    enum lsif_mode mode;
    lsif_mode_set_from_argv(&mode, argv, argc);

    struct ifaddrs *head_ifaddr;

    if (getifaddrs(&head_ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    ifaddr_list_sort(head_ifaddr);

    ifaddr_list_print(head_ifaddr, 0);

    freeifaddrs(head_ifaddr);

    exit(EXIT_SUCCESS);
}
