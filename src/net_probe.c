/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * net_probe.c - Network state probing from /proc/net
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "sentinel.h"

/* Common service ports - unusual if something else is listening */
static const uint16_t common_ports[] = {
    22,    /* SSH */
    25,    /* SMTP */
    53,    /* DNS */
    80,    /* HTTP */
    110,   /* POP3 */
    143,   /* IMAP */
    443,   /* HTTPS */
    465,   /* SMTPS */
    587,   /* Submission */
    993,   /* IMAPS */
    995,   /* POP3S */
    3306,  /* MySQL */
    5432,  /* PostgreSQL */
    6379,  /* Redis */
    8080,  /* HTTP Alt */
    8443,  /* HTTPS Alt */
    27017, /* MongoDB */
    0      /* Sentinel */
};

static int is_common_port(uint16_t port) {
    for (int i = 0; common_ports[i] != 0; i++) {
        if (common_ports[i] == port) return 1;
    }
    /* Ephemeral ports (>32768) are normal for outbound connections */
    if (port >= 32768) return 1;
    return 0;
}

/* Convert hex IP address from /proc/net to string */
static void hex_to_ip(const char *hex, char *ip, size_t ip_len, int is_ipv6) {
    if (is_ipv6) {
        /* IPv6 - simplified, just show as hex for now */
        snprintf(ip, ip_len, "%s", hex);
    } else {
        /* IPv4 - /proc stores as little-endian hex */
        unsigned int addr;
        sscanf(hex, "%X", &addr);
        snprintf(ip, ip_len, "%u.%u.%u.%u",
                 addr & 0xFF,
                 (addr >> 8) & 0xFF,
                 (addr >> 16) & 0xFF,
                 (addr >> 24) & 0xFF);
    }
}

/* Get process name from pid */
static void get_process_name(pid_t pid, char *name, size_t name_len) {
    char path[64];
    FILE *f;
    
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (f) {
        if (fgets(name, name_len, f)) {
            /* Remove trailing newline */
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0';
        }
        fclose(f);
    } else {
        snprintf(name, name_len, "[unknown]");
    }
}

/* Find PID for a given inode from /proc/[pid]/fd/ */
static pid_t find_pid_for_inode(unsigned long inode) {
    DIR *proc_dir;
    struct dirent *proc_entry;
    char path[512], link_target[512];
    char inode_str[64];
    
    snprintf(inode_str, sizeof(inode_str), "socket:[%lu]", inode);
    
    proc_dir = opendir("/proc");
    if (!proc_dir) return 0;
    
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        /* Only look at numeric directories (PIDs) */
        if (proc_entry->d_name[0] < '0' || proc_entry->d_name[0] > '9')
            continue;
            
        pid_t pid = atoi(proc_entry->d_name);
        char fd_path[128];
        DIR *fd_dir;
        struct dirent *fd_entry;
        
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
        fd_dir = opendir(fd_path);
        if (!fd_dir) continue;
        
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            snprintf(path, sizeof(path), "%s/%s", fd_path, fd_entry->d_name);
            ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
            if (len > 0) {
                link_target[len] = '\0';
                if (strcmp(link_target, inode_str) == 0) {
                    closedir(fd_dir);
                    closedir(proc_dir);
                    return pid;
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
    return 0;
}

/* TCP state names */
static const char *tcp_state_name(int state) {
    static const char *states[] = {
        "UNKNOWN",      /* 0 */
        "ESTABLISHED",  /* 1 */
        "SYN_SENT",     /* 2 */
        "SYN_RECV",     /* 3 */
        "FIN_WAIT1",    /* 4 */
        "FIN_WAIT2",    /* 5 */
        "TIME_WAIT",    /* 6 */
        "CLOSE",        /* 7 */
        "CLOSE_WAIT",   /* 8 */
        "LAST_ACK",     /* 9 */
        "LISTEN",       /* 10 (0x0A) */
        "CLOSING"       /* 11 */
    };
    if (state >= 0 && state <= 11) return states[state];
    return "UNKNOWN";
}

/* Parse /proc/net/tcp or /proc/net/tcp6 */
static int parse_tcp_file(const char *filename, network_info_t *net, int is_ipv6) {
    FILE *f = fopen(filename, "r");
    if (!f) return -1;
    
    char line[512];
    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    
    while (fgets(line, sizeof(line), f)) {
        char local_addr_hex[64], remote_addr_hex[64];
        unsigned int local_port, remote_port;
        unsigned int state;
        unsigned long inode;
        
        /* Parse the line - format varies slightly between tcp and tcp6 */
        if (is_ipv6) {
            if (sscanf(line, "%*d: %32[0-9A-Fa-f]:%X %32[0-9A-Fa-f]:%X %X %*s %*s %*s %*d %*d %lu",
                       local_addr_hex, &local_port,
                       remote_addr_hex, &remote_port,
                       &state, &inode) != 6) continue;
        } else {
            if (sscanf(line, "%*d: %8[0-9A-Fa-f]:%X %8[0-9A-Fa-f]:%X %X %*s %*s %*s %*d %*d %lu",
                       local_addr_hex, &local_port,
                       remote_addr_hex, &remote_port,
                       &state, &inode) != 6) continue;
        }
        
        /* Is this a listener? */
        if (state == 0x0A && net->listener_count < MAX_LISTENERS) {
            net_listener_t *l = &net->listeners[net->listener_count];
            
            snprintf(l->protocol, sizeof(l->protocol), is_ipv6 ? "tcp6" : "tcp");
            hex_to_ip(local_addr_hex, l->local_addr, sizeof(l->local_addr), is_ipv6);
            l->local_port = local_port;
            snprintf(l->state, sizeof(l->state), "%s", tcp_state_name(state));
            
            /* Find owning process */
            l->pid = find_pid_for_inode(inode);
            if (l->pid > 0) {
                get_process_name(l->pid, l->process_name, sizeof(l->process_name));
            } else {
                snprintf(l->process_name, sizeof(l->process_name), "[kernel]");
            }
            
            net->listener_count++;
            net->total_listening++;
            
            if (!is_common_port(local_port)) {
                net->unusual_port_count++;
            }
        }
        /* Is this an established connection? */
        else if (state == 0x01 && net->connection_count < MAX_CONNECTIONS) {
            net_connection_t *c = &net->connections[net->connection_count];
            
            snprintf(c->protocol, sizeof(c->protocol), is_ipv6 ? "tcp6" : "tcp");
            hex_to_ip(local_addr_hex, c->local_addr, sizeof(c->local_addr), is_ipv6);
            c->local_port = local_port;
            hex_to_ip(remote_addr_hex, c->remote_addr, sizeof(c->remote_addr), is_ipv6);
            c->remote_port = remote_port;
            snprintf(c->state, sizeof(c->state), "%s", tcp_state_name(state));
            
            c->pid = find_pid_for_inode(inode);
            if (c->pid > 0) {
                get_process_name(c->pid, c->process_name, sizeof(c->process_name));
            } else {
                snprintf(c->process_name, sizeof(c->process_name), "[kernel]");
            }
            
            net->connection_count++;
            net->total_established++;
        }
    }
    
    fclose(f);
    return 0;
}

/* Parse /proc/net/udp or /proc/net/udp6 for listening UDP sockets */
static int parse_udp_file(const char *filename, network_info_t *net, int is_ipv6) {
    FILE *f = fopen(filename, "r");
    if (!f) return -1;
    
    char line[512];
    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    
    while (fgets(line, sizeof(line), f) && net->listener_count < MAX_LISTENERS) {
        char local_addr_hex[64], remote_addr_hex[64];
        unsigned int local_port, remote_port;
        unsigned int state;
        unsigned long inode;
        
        if (is_ipv6) {
            if (sscanf(line, "%*d: %32[0-9A-Fa-f]:%X %32[0-9A-Fa-f]:%X %X %*s %*s %*s %*d %*d %lu",
                       local_addr_hex, &local_port,
                       remote_addr_hex, &remote_port,
                       &state, &inode) != 6) continue;
        } else {
            if (sscanf(line, "%*d: %8[0-9A-Fa-f]:%X %8[0-9A-Fa-f]:%X %X %*s %*s %*s %*d %*d %lu",
                       local_addr_hex, &local_port,
                       remote_addr_hex, &remote_port,
                       &state, &inode) != 6) continue;
        }
        
        /* UDP sockets with state 07 are listening */
        if (state == 0x07 || local_port > 0) {
            net_listener_t *l = &net->listeners[net->listener_count];
            
            snprintf(l->protocol, sizeof(l->protocol), is_ipv6 ? "udp6" : "udp");
            hex_to_ip(local_addr_hex, l->local_addr, sizeof(l->local_addr), is_ipv6);
            l->local_port = local_port;
            snprintf(l->state, sizeof(l->state), "LISTEN");
            
            l->pid = find_pid_for_inode(inode);
            if (l->pid > 0) {
                get_process_name(l->pid, l->process_name, sizeof(l->process_name));
            } else {
                snprintf(l->process_name, sizeof(l->process_name), "[kernel]");
            }
            
            net->listener_count++;
            net->total_listening++;
            
            if (!is_common_port(local_port)) {
                net->unusual_port_count++;
            }
        }
    }
    
    fclose(f);
    return 0;
}

/* Main network probe function */
int probe_network(network_info_t *net) {
    memset(net, 0, sizeof(network_info_t));
    
    /* Probe TCP */
    parse_tcp_file("/proc/net/tcp", net, 0);
    parse_tcp_file("/proc/net/tcp6", net, 1);
    
    /* Probe UDP */
    parse_udp_file("/proc/net/udp", net, 0);
    parse_udp_file("/proc/net/udp6", net, 1);
    
    return 0;
}
