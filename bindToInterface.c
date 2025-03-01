#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <net/if.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>

#define DEBUG

int bind_to_source_ip(int sockfd, const char *source_ip, int family)
{
    if (family == AF_INET) {
        struct sockaddr_in source_addr;
        memset(&source_addr, 0, sizeof(source_addr));
        source_addr.sin_family = AF_INET;
        source_addr.sin_addr.s_addr = inet_addr(source_ip);

        return bind(sockfd, (struct sockaddr *)&source_addr, sizeof(source_addr));
    } else if (family == AF_INET6) {
        struct sockaddr_in6 source_addr;
        memset(&source_addr, 0, sizeof(source_addr));
        source_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, source_ip, &source_addr.sin6_addr);

        return bind(sockfd, (struct sockaddr *)&source_addr, sizeof(source_addr));
    }
    return -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int (*original_connect)(int, const struct sockaddr *, socklen_t);
    original_connect = dlsym(RTLD_NEXT, "connect");

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *socketAddress = (struct sockaddr_in *)addr;
        char *dest = inet_ntoa(socketAddress->sin_addr);
        unsigned short port = ntohs(socketAddress->sin_port);

        char *DNSIP_env = getenv("DNS_OVERRIDE_IP");
        char *DNSPort_env = getenv("DNS_OVERRIDE_PORT");
        int port_new = port;

        // Handle DNS override for IPv4
        if (port == 53 && DNSIP_env != NULL && strlen(DNSIP_env) > 0) {
            if (DNSPort_env != NULL && strlen(DNSPort_env) > 0) {
                port_new = atoi(DNSPort_env);
                socketAddress->sin_port = htons(port_new);
            }
#ifdef DEBUG
            printf("Detected DNS query to: %s:%i, overwriting with %s:%i \n", dest, port, DNSIP_env, port_new);
#endif

            // Override destination IP with DNS server IP
            socketAddress->sin_addr.s_addr = inet_addr(DNSIP_env);
        }
        port = port_new;
        dest = inet_ntoa(socketAddress->sin_addr);

#ifdef DEBUG
        printf("Connecting to: %s:%i \n", dest, port);
#endif

        bool IPExcluded = false;
        char *bind_excludes = getenv("BIND_EXCLUDE");
        if (bind_excludes != NULL && strlen(bind_excludes) > 0) {
            bind_excludes = (char *)malloc(strlen(bind_excludes) * sizeof(char) + 1);
            strcpy(bind_excludes, getenv("BIND_EXCLUDE"));
            char sep[] = ",";
            char *iplist;
            iplist = strtok(bind_excludes, sep);
            while (iplist != NULL) {
                if (!strncmp(dest, iplist, strlen(iplist))) {
                    IPExcluded = true;
#ifdef DEBUG
                    printf("IP %s excluded by IP-List, not binding to interface %s\n", dest, getenv("BIND_INTERFACE"));
#endif
                    break;
                }
                iplist = strtok(NULL, sep);
            }
            free(bind_excludes);
        }

        if (!IPExcluded) {
            char *bind_addr_env = getenv("BIND_INTERFACE");
            char *source_ip_env = getenv("BIND_SOURCE_IPV4");
            struct ifreq interface;

            int errorCode;
            if (bind_addr_env != NULL && strlen(bind_addr_env) > 0) {
                struct ifreq boundInterface = { .ifr_name = "" };
                socklen_t optionlen = sizeof(boundInterface);
                errorCode = getsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &boundInterface, &optionlen);
                if (errorCode < 0) {
                    perror("getsockopt");
                    return -1;
                }
#ifdef DEBUG
                printf("Bound Interface: %s.\n", boundInterface.ifr_name);
#endif

                if (!strcmp(boundInterface.ifr_name, "") || strcmp(boundInterface.ifr_name, bind_addr_env)) {
#ifdef DEBUG
                    printf("Socket not bound to desired interface (Bound to: %s). Binding to interface: %s\n", boundInterface.ifr_name, bind_addr_env);
#endif
                    strcpy(interface.ifr_name, bind_addr_env);
                    errorCode = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface));
                    if (errorCode < 0) {
                        perror("setsockopt");
                        errno = ENETUNREACH;
                        return -1;
                    }
                }
            }

            if (source_ip_env != NULL && strlen(source_ip_env) > 0) {
                if (bind_to_source_ip(sockfd, source_ip_env, AF_INET) < 0) {
                    perror("bind_to_source_ip failed");
                    return -1;
                }
            }

            if (!(source_ip_env != NULL && strlen(source_ip_env) > 0) && !(bind_addr_env != NULL && strlen(bind_addr_env) > 0)) {
                printf("Warning: Program with LD_PRELOAD started, but BIND_INTERFACE environment variable not set\n");
                fprintf(stderr, "Warning: Program with LD_PRELOAD started, but BIND_INTERFACE environment variable not set\n");
            }
        }
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *socketAddress = (struct sockaddr_in6 *)addr;
        char dest[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &socketAddress->sin6_addr, dest, sizeof(dest));
        unsigned short port = ntohs(socketAddress->sin6_port);

        char *DNSIP_env = getenv("DNS_OVERRIDE_IP");
        char *DNSPort_env = getenv("DNS_OVERRIDE_PORT");
        int port_new = port;

        // Handle DNS override for IPv6
        if (port == 53 && DNSIP_env != NULL && strlen(DNSIP_env) > 0) {
            if (DNSPort_env != NULL && strlen(DNSPort_env) > 0) {
                port_new = atoi(DNSPort_env);
                socketAddress->sin6_port = htons(port_new);
            }
#ifdef DEBUG
            printf("Detected DNS query to: [%s]:%i, overwriting with [%s]:%i \n", dest, port, DNSIP_env, port_new);
#endif

            // Override destination IP with DNS server IP
            inet_pton(AF_INET6, DNSIP_env, &socketAddress->sin6_addr);
        }
        port = port_new;
        inet_ntop(AF_INET6, &socketAddress->sin6_addr, dest, sizeof(dest));

#ifdef DEBUG
        printf("Connecting to: [%s]:%i \n", dest, port);
#endif

        bool IPExcluded = false;
        char *bind_excludes = getenv("BIND_EXCLUDE");
        if (bind_excludes != NULL && strlen(bind_excludes) > 0) {
            bind_excludes = (char *)malloc(strlen(bind_excludes) * sizeof(char) + 1);
            strcpy(bind_excludes, getenv("BIND_EXCLUDE"));
            char sep[] = ",";
            char *iplist;
            iplist = strtok(bind_excludes, sep);
            while (iplist != NULL) {
                if (!strncmp(dest, iplist, strlen(iplist))) {
                    IPExcluded = true;
#ifdef DEBUG
                    printf("IP %s excluded by IP-List, not binding to interface %s\n", dest, getenv("BIND_INTERFACE"));
#endif
                    break;
                }
                iplist = strtok(NULL, sep);
            }
            free(bind_excludes);
        }

        if (!IPExcluded) {
            char *bind_addr_env = getenv("BIND_INTERFACE");
            char *source_ip_env = getenv("BIND_SOURCE_IPV6");
            struct ifreq interface;

            int errorCode;
            if (bind_addr_env != NULL && strlen(bind_addr_env) > 0) {
                struct ifreq boundInterface = { .ifr_name = "" };
                socklen_t optionlen = sizeof(boundInterface);
                errorCode = getsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &boundInterface, &optionlen);
                if (errorCode < 0) {
                    perror("getsockopt");
                    return -1;
                }
#ifdef DEBUG
                printf("Bound Interface: %s.\n", boundInterface.ifr_name);
#endif

                if (!strcmp(boundInterface.ifr_name, "") || strcmp(boundInterface.ifr_name, bind_addr_env)) {
#ifdef DEBUG
                    printf("Socket not bound to desired interface (Bound to: %s). Binding to interface: %s\n", boundInterface.ifr_name, bind_addr_env);
#endif
                    strcpy(interface.ifr_name, bind_addr_env);
                    errorCode = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface));
                    if (errorCode < 0) {
                        perror("setsockopt");
                        errno = ENETUNREACH;
                        return -1;
                    }
                }
            }

            if (source_ip_env != NULL && strlen(source_ip_env) > 0) {
                if (bind_to_source_ip(sockfd, source_ip_env, AF_INET6) < 0)
{
                    perror("bind_to_source_ip failed");
                    return -1;
                }
            }

            if (!(source_ip_env != NULL && strlen(source_ip_env) > 0) && !(bind_addr_env != NULL && strlen(bind_addr_env) > 0)) {
                printf("Warning: Program with LD_PRELOAD started, but BIND_INTERFACE environment variable not set\n");
                fprintf(stderr, "Warning: Program with LD_PRELOAD started, but BIND_INTERFACE environment variable not set\n");
            }
        }
    }

    // Call original connect function
    return original_connect(sockfd, addr, addrlen);
}
