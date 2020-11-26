/*
    Copyright (C) HWPORT.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(_ISOC99_SOURCE)
# define _ISOC99_SOURCE (1L)
#endif

#if !defined(_GNU_SOURCE)
# define _GNU_SOURCE (1L)
#endif

#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>

#define _ntohll(x) (((uint64_t)(ntohl((uint32_t)((x<<32)>>32)))<<32)|ntohl(((uint32_t)(x>>32))))

static char *hwport_strip_ansi_code(char *s_string);
static void hwport_output_puts(const char *s_string);

static const char *hwport_rtnetlink_name(unsigned int s_type);

static size_t hwport_dump_space(char *s_buffer, size_t s_buffer_size, int s_depth);
static size_t hwport_dump(char *s_buffer, size_t s_buffer_size, int s_depth, const void *s_data, size_t s_size);

static size_t hwport_dump_ifinfomsg(char *s_buffer, size_t s_buffer_size, int s_depth, struct ifinfomsg *s_ifinfomsg);
static size_t hwport_dump_ifaddrmsg(char *s_buffer, size_t s_buffer_size, int s_depth, struct ifaddrmsg *s_ifaddrmsg);
static size_t hwport_dump_rtmsg(char *s_buffer, size_t s_buffer_size, int s_depth, struct rtmsg *s_rtmsg);

static int hwport_process_netlink_recv(int s_socket, void *s_buffer, size_t s_buffer_size);

int main(int s_argc, char **s_argv);

static char *hwport_strip_ansi_code(char *s_string)
{
    size_t s_string_size;

    size_t s_from_offset;
    size_t s_to_offset;

    int s_escape_sequence;

    int s_byte;

    if(s_string == ((char *)0)) {
        return((char *)0);
    }
    
    s_string_size = strlen(s_string);
  
    s_from_offset = (size_t)0u;
    s_to_offset = (size_t)0u;

    s_escape_sequence = 0;

    while(s_from_offset < s_string_size) {
        s_byte = (int)s_string[s_from_offset];
        if(s_byte == '\0') {
            break;
        }

        if(s_escape_sequence == 0) {
            if(s_byte == 0x1b) {
                s_escape_sequence = 1;
            }
            else {
                if(s_to_offset != s_from_offset) {
                    s_string[s_to_offset] = (char)s_byte;
                }
                ++s_to_offset;
            }
        }
        else if((isdigit(s_byte) == 0) && (s_byte != ';') && (s_byte != '[')) {
            s_escape_sequence = 0;
        }

        ++s_from_offset;
    }

    if(s_to_offset != s_from_offset) {
        s_string[s_to_offset] = '\0';
    }

    return(s_string);
}

static void hwport_output_puts(const char *s_string)
{
    static int sg_is_first = 0;
    static int sg_is_tty = 0;

    if(s_string == ((const char *)0)) {
        return;
    }

    if(sg_is_first == 0) {
        int s_fd;

        sg_is_first = 1;

        s_fd = fileno(stdout);
        if(s_fd != (-1)) {
            sg_is_tty = isatty(s_fd);
        }
    }

    if(sg_is_tty == 0) { /* pipe out, escape sequece need strip */
        char *s_dup_string;

        s_dup_string = hwport_strip_ansi_code(strdup(s_string));
        if(s_dup_string != ((char *)0)) {
            (void)fputs(s_dup_string, stdout);
            (void)fflush(stdout);
            
            free((void *)s_dup_string);

            return;
        }
    }

    /* normal tty out */
    (void)fputs(s_string, stdout);
    (void)fflush(stdout);
}

static size_t hwport_dump_space(char *s_buffer, size_t s_buffer_size, int s_depth)
{
    size_t s_offset;
    int s_count;

    s_offset = (size_t)0u;
    for(s_count = 0;s_count < s_depth;s_count++) {
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "  "
        );
    }

    return(s_offset);
}

static const char *hwport_rtnetlink_name(unsigned int s_type)
{
    const char *s_result;

    switch(s_type) {
#if defined(NLMSG_NOOP)
        case NLMSG_NOOP:
            s_result = "NLMSG_NOOP";
            break;
#endif
#if defined(NLMSG_ERROR)
        case NLMSG_ERROR:
            s_result = "NLMSG_ERROR";
            break;
#endif
#if defined(NLMSG_DONE)
        case NLMSG_DONE:
            s_result = "NLMSG_DONE";
            break;
#endif
#if defined(NLMSG_OVERRUN)
        case NLMSG_OVERRUN:
            s_result = "NLMSG_OVERRUN";
            break;
#endif
        case RTM_NEWLINK:
            s_result = "RTM_NEWLINK";
            break;
        case RTM_DELLINK:
            s_result = "RTM_DELLINK";
            break;
        case RTM_NEWADDR:
            s_result = "RTM_NEWADDR";
            break;
        case RTM_DELADDR:
            s_result = "RTM_DELADDR";
            break;
        case RTM_NEWROUTE:
            s_result = "RTM_NEWROUTE";
            break;
        case RTM_DELROUTE:
            s_result = "RTM_DELROUTE";
            break;
        default:
            s_result = "RTM_??? (UNKNOWN)";
            break;
    }

    return(s_result);
}

static size_t hwport_dump(char *s_buffer, size_t s_buffer_size, int s_depth, const void *s_data, size_t s_size)
{
    size_t s_offset;

    size_t s_o;
    size_t s_w;
    size_t s_i;
    uint8_t s_b[17];

    s_offset = (size_t)0u;

    s_b[16] = (uint8_t)'\0';
    s_o = (size_t)0u;

    while(s_o < s_size) {
        s_w = ((s_size - s_o) < ((size_t)16u)) ? (s_size - s_o) : ((size_t)16u);

        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );

        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "%08lX",
            (unsigned long)s_o
        );

        for(s_i = (size_t)0u;s_i < s_w;s_i++){
            if(s_i == ((size_t)8u)) {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    " | "
                );
            }
            else {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    " "
                );
            }

            s_b[s_i] = *(((const uint8_t *)s_data) + s_o + s_i);

            s_offset += (size_t)snprintf(
                (char *)(&s_buffer[s_offset]),
                s_buffer_size - s_offset,
                "%02X",
                (unsigned int)s_b[s_i]
            );

            if((s_b[s_i] & 0x80) || (s_b[s_i] < ' ')) {
                s_b[s_i] = '.';
            }
        }

        while(s_i < 16) {
            if(s_i == 8) {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    "     "
                );
            }
            else {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    "   "
                );
            }

            s_b[s_i] = ' ';
            ++s_i;
        }

        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            " [%s]\n",
            (char *)(&s_b[0])
        );

        s_o += (size_t)16u;
    }

    return(s_offset);
}

static size_t hwport_dump_ifinfomsg(char *s_buffer, size_t s_buffer_size, int s_depth, struct ifinfomsg *s_ifinfomsg)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "family: %u\n",
        (unsigned int)s_ifinfomsg->ifi_family
    );

    /* ARPHRD_* */
    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "type: %u\n",
        (unsigned int)s_ifinfomsg->ifi_type
    );

    /* link index */
    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "index: %u\n",
        (unsigned int)s_ifinfomsg->ifi_index
    );

    /* IFF_* flags */
    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "flags: %u(%08XH)\n",
        (unsigned int)s_ifinfomsg->ifi_flags,
        (unsigned int)s_ifinfomsg->ifi_flags
    );

    /* IFF_* change mask */
    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "change: %u(%08XH)\n",
        (unsigned int)s_ifinfomsg->ifi_change,
        (unsigned int)s_ifinfomsg->ifi_change
    );

    return(s_offset);
}

static size_t hwport_dump_ifaddrmsg(char *s_buffer, size_t s_buffer_size, int s_depth, struct ifaddrmsg *s_ifaddrmsg)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "family: %u\n",
        (unsigned int)s_ifaddrmsg->ifa_family
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "prefixlen: %u\n",
        (unsigned int)s_ifaddrmsg->ifa_prefixlen
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "flags: %u(%08XH)\n",
        (unsigned int)s_ifaddrmsg->ifa_flags,
        (unsigned int)s_ifaddrmsg->ifa_flags
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "scope: %u(%08XH)\n",
        (unsigned int)s_ifaddrmsg->ifa_scope,
        (unsigned int)s_ifaddrmsg->ifa_scope
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "index: %u\n",
        (unsigned int)s_ifaddrmsg->ifa_index
    );

    return(s_offset);
}

static size_t hwport_dump_rtmsg(char *s_buffer, size_t s_buffer_size, int s_depth, struct rtmsg *s_rtmsg)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "family: %u\n",
        (unsigned int)s_rtmsg->rtm_family
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "dst_len: %u\n",
        (unsigned int)s_rtmsg->rtm_dst_len
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "src_len: %u\n",
        (unsigned int)s_rtmsg->rtm_src_len
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "tos: %u\n",
        (unsigned int)s_rtmsg->rtm_tos
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "table: %u\n",
        (unsigned int)s_rtmsg->rtm_table
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "protocol: %u\n",
        (unsigned int)s_rtmsg->rtm_protocol
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "scope: %u\n",
        (unsigned int)s_rtmsg->rtm_scope
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "type: %u\n",
        (unsigned int)s_rtmsg->rtm_type
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "flags: %u(%08XH)\n",
        (unsigned int)s_rtmsg->rtm_flags,
        (unsigned int)s_rtmsg->rtm_flags
    );

    return(s_offset);
}

static int hwport_process_netlink_recv(int s_socket, void *s_buffer, size_t s_buffer_size)
{
    struct sockaddr_nl s_sockaddr_nl; 
    socklen_t s_socklen;

    size_t s_output_buffer_size;
    char *s_output_buffer;
    size_t s_output_offset;
    int s_depth;

    ssize_t s_recv_bytes;

    int s_is_break;

    size_t s_msg_size;
    size_t s_payload_size;
    void *s_payload;
    size_t s_message_size;

    struct nlmsghdr *s_nlmsghdr;

    for(;;) {
        (void)memset((void *)(&s_sockaddr_nl), 0, sizeof(s_sockaddr_nl));
        s_socklen = (socklen_t)sizeof(s_sockaddr_nl);
        s_recv_bytes = recvfrom(
            s_socket,
            s_buffer,
            s_buffer_size,
            MSG_NOSIGNAL,
            (struct sockaddr *)(&s_sockaddr_nl),
            (socklen_t *)(&s_socklen)
        );
        if(s_recv_bytes == ((ssize_t)(-1))) {
            perror("recvfrom");
            break;
        }
#if 0L /* DEBUG */
        (void)fprintf(
            stdout,
            "recvfrom %ld bytes (pid=%lu, groups=%08lXH)\n",
            (long)s_recv_bytes,
            (long)s_sockaddr_nl.nl_pid,
            (unsigned long)s_sockaddr_nl.nl_groups
        );
#endif

        if(s_sockaddr_nl.nl_family != AF_NETLINK) {
            (void)fprintf(stderr, "nl_family != AF_NETLINK is ignore (nl_family=%ld)\n", (long)s_sockaddr_nl.nl_family);
            continue;
        }

        if(s_sockaddr_nl.nl_pid != ((pid_t)0)) {
            /* sender pid 0 is ignore */
            (void)fprintf(stderr, "sender pid 0 is ignore (pid=%ld)\n", (long)s_sockaddr_nl.nl_pid);
            continue;
        }

        s_output_buffer_size = s_buffer_size - ((size_t)s_recv_bytes);
        s_output_buffer = ((char *)s_buffer) + s_recv_bytes;
        s_output_offset = (size_t)0;

        s_is_break = 0;

        s_msg_size = (size_t)s_recv_bytes;
        for(s_nlmsghdr = (struct nlmsghdr *)s_buffer;(s_is_break == 0) && NLMSG_OK(s_nlmsghdr, s_msg_size);s_nlmsghdr = NLMSG_NEXT(s_nlmsghdr, s_msg_size)) {
            s_payload_size = (size_t)NLMSG_PAYLOAD(s_nlmsghdr, 0);
            s_payload = NLMSG_DATA(s_nlmsghdr);

            s_depth = 0;
            s_output_offset += hwport_dump_space(
                (char *)(&s_output_buffer[s_output_offset]),
                s_output_buffer_size - s_output_offset,
                s_depth
            );

            s_output_offset += (size_t)snprintf(
                (char *)(&s_output_buffer[s_output_offset]),
                s_output_buffer_size - s_output_offset,
                "* \"\x1b[1;33m%s\x1b[0m\" (type=%lu[%04lXH], flags=%04lXH[%s%s%s%s%s%s%s%s%s%s%s%s%s%s], seq=%lu, pid=%lu, len=%lu, payload_size=%lu, remain=%lu/%ld)\n",
                hwport_rtnetlink_name((unsigned int)s_nlmsghdr->nlmsg_type),
                (unsigned long)s_nlmsghdr->nlmsg_type,
                (unsigned long)s_nlmsghdr->nlmsg_type,
                (unsigned long)s_nlmsghdr->nlmsg_flags,
                (s_nlmsghdr->nlmsg_flags) ? "" : "<NONE FLAGS>",
#if defined(NLM_F_REQUEST)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_REQUEST) == NLM_F_REQUEST) ? "{REQUEST}" : "",
#else
                "",
#endif
#if defined(NLM_F_MULTI)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_MULTI) == NLM_F_MULTI) ? "{MULTI}" : "",
#else
                "",
#endif
#if defined(NLM_F_ACK)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ACK) == NLM_F_ACK) ? "{ACK}" : "",
#else
                "",
#endif
#if defined(NLM_F_ECHO)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ECHO) == NLM_F_ECHO) ? "{ECHO}" : "",
#else
                "",
#endif
#if defined(NLM_F_DUMP_INTR)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_DUMP_INTR) == NLM_F_DUMP_INTR) ? "{DUMP_INTR}" : "",
#else
                "",
#endif
#if defined(NLM_F_ROOT)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ROOT) == NLM_F_ROOT) ? "{ROOT}" : "",
#else
                "",
#endif
#if defined(NLM_F_MATCH)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_MATCH) == NLM_F_MATCH) ? "{MATCH}" : "",
#else
                "",
#endif
#if defined(NLM_F_ATOMIC)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ATOMIC) == NLM_F_ATOMIC) ? "{ATOMIC}" : "",
#else
                "",
#endif
#if defined(NLM_F_DUMP)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP) ? "{DUMP}" : "",
#else
                "",
#endif
#if defined(NLM_F_REPLACE)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_REPLACE) == NLM_F_REPLACE) ? "{REPLACE}" : "",
#else
                "",
#endif
#if defined(NLM_F_EXCL)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_EXCL) == NLM_F_EXCL) ? "{EXCL}" : "",
#else
                "",
#endif
#if defined(NLM_F_CREATE)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_CREATE) == NLM_F_CREATE) ? "{CREATE}" : "",
#else
                "",
#endif
#if defined(NLM_F_APPEND)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_APPEND) == NLM_F_APPEND) ? "{APPEND}" : "",
#else
                "",
#endif
                (unsigned long)s_nlmsghdr->nlmsg_seq,
                (unsigned long)s_nlmsghdr->nlmsg_pid,
                (unsigned long)s_nlmsghdr->nlmsg_len,
                (unsigned long)s_payload_size,
                (unsigned long)s_msg_size,
                (long)s_recv_bytes
            );
            ++s_depth;

            switch(s_nlmsghdr->nlmsg_type) {
#if defined(NLMSG_NOOP)
                case NLMSG_NOOP:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );
                    break;
#endif
#if defined(NLMSG_ERROR)
                case NLMSG_ERROR:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );

                    s_is_break = 1;
                    break;
#endif
#if defined(NLMSG_DONE)
                case NLMSG_DONE:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );

                    s_is_break = 1;
                    break;
#endif
#if defined(NLMSG_OVERRUN)
                case NLMSG_OVERRUN:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );

                    s_is_break = 1;
                    break;
#endif
                case RTM_NEWLINK: /* struct ifinfomsg */
                case RTM_DELLINK: /* struct ifinfomsg */
                    s_message_size = sizeof(struct ifinfomsg);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_ifinfomsg(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct ifinfomsg *)s_payload
                    );
                    break;
                case RTM_NEWADDR: /* struct ifaddrmsg */
                case RTM_DELADDR: /* struct ifaddrmsg */
                    s_message_size = sizeof(struct ifaddrmsg);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_ifaddrmsg(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct ifaddrmsg *)s_payload
                    );
                    break;
                case RTM_NEWROUTE: /* struct rtmsg */
                case RTM_DELROUTE: /* struct rtmsg */
                    s_message_size = sizeof(struct rtmsg);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_rtmsg(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct rtmsg *)s_payload
                    );
                    break;
                default:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );
                    break;
            }

            if(s_payload_size > s_message_size) { /* attribute parsing */
                static const char *cg_link_attr_name_table[] = {
                    "IFLA_UNSPEC",
                    "IFLA_ADDRESS",
                    "IFLA_BROADCAST",
                    "IFLA_IFNAME",
                    "IFLA_MTU",
                    "IFLA_LINK",
                    "IFLA_QDISC",
                    "IFLA_STATS",
                    "IFLA_COST",
                    "IFLA_PRIORITY",
                    "IFLA_MASTER",
                    "IFLA_WIRELESS",
                    "IFLA_PROTINFO",
                    "IFLA_TXQLEN",
                    "IFLA_MAP",
                    "IFLA_WEIGHT",
                    "IFLA_OPERSTATE",
                    "IFLA_LINKMODE",
                    "IFLA_LINKINFO",
                    "IFLA_NET_NS_PID",
                    "IFLA_IFALIAS",
                    "IFLA_NUM_VF",
                    "IFLA_VFINFO_LIST",
                    "IFLA_STATS64",
                    "IFLA_VF_PORTS",
                    "IFLA_PORT_SELF",
                    "IFLA_AF_SPEC",
                    "IFLA_GROUP",
                    "IFLA_NET_NS_FD",
                    "IFLA_EXT_MASK",
                    "IFLA_PROMISCUITY",
                    "IFLA_NUM_TX_QUEUES",
                    "IFLA_NUM_RX_QUEUES",
                    "IFLA_CARRIER",
                    "IFLA_PHYS_PORT_ID",
                };
                static const char *cg_addr_attr_name_table[] = {
                    "IFA_UNSPEC",
                    "IFA_ADDRESS",
                    "IFA_LOCAL",
                    "IFA_LABEL",
                    "IFA_BROADCAST",
                    "IFA_ANYCAST",
                    "IFA_CACHEINFO",
                    "IFA_MULTICAST",
                };
                static const char *cg_route_attr_name_table[] = {
                    "RTA_UNSPEC",
                    "RTA_DST",
                    "RTA_SRC",
                    "RTA_IIF",
                    "RTA_OIF",
                    "RTA_GATEWAY",
                    "RTA_PRIORITY",
                    "RTA_PREFSRC",
                    "RTA_METRICS",
                    "RTA_MULTIPATH",
                    "RTA_PROTOINFO",
                    "RTA_FLOW",
                    "RTA_CACHEINFO",
                    "RTA_SESSION",
                    "RTA_MP_ALGO",
                    "RTA_TABLE",
                    "RTA_MARK",
                    "RTA_MFC_STATS",
                };

                size_t s_attr_name_table_size;
                const char **s_attr_name_table;

                size_t s_attr_window_size;
                struct nlattr *s_nlattr;
                size_t s_attr_size;
                void *s_attr_payload;

				struct ifinfomsg *s_ifinfomsg;
				struct ifaddrmsg *s_ifaddrmsg;
				struct rtmsg *s_rtmsg;

				s_ifinfomsg = (struct ifinfomsg *)0;
				s_ifaddrmsg = (struct ifaddrmsg *)0;
				s_rtmsg = (struct rtmsg *)0;

                switch(s_nlmsghdr->nlmsg_type) {
                    case RTM_NEWLINK:
                    case RTM_DELLINK:
						s_ifinfomsg = (struct ifinfomsg *)s_payload;
                        s_attr_name_table_size = sizeof(cg_link_attr_name_table) / sizeof(const char *);
                        s_attr_name_table = (const char **)(&cg_link_attr_name_table[0]);
                        break;
                    case RTM_NEWADDR:
                    case RTM_DELADDR:
						s_ifaddrmsg = (struct ifaddrmsg *)s_payload;
                        s_attr_name_table_size = sizeof(cg_addr_attr_name_table) / sizeof(const char *);
                        s_attr_name_table = (const char **)(&cg_addr_attr_name_table[0]);
                        break;
                    case RTM_NEWROUTE:
                    case RTM_DELROUTE:
						s_rtmsg = (struct rtmsg *)s_payload;
                        s_attr_name_table_size = sizeof(cg_route_attr_name_table) / sizeof(const char *);
                        s_attr_name_table = (const char **)(&cg_route_attr_name_table[0]);
                        break;
                    default:
                        s_attr_name_table_size = (size_t)0u;
                        s_attr_name_table = (const char **)0;
                        break;
                }
				
				(void)s_ifinfomsg;
				(void)s_ifaddrmsg;

                s_attr_window_size = s_payload_size - s_message_size;
                
                for(s_nlattr = (struct nlattr *)(((unsigned char *)s_payload) + NLMSG_ALIGN(s_message_size));(s_attr_window_size >= sizeof(struct nlattr)) && (s_nlattr->nla_len >= sizeof(struct nlattr)) && (s_nlattr->nla_len <= s_attr_window_size);s_attr_window_size -= NLA_ALIGN(s_nlattr->nla_len), s_nlattr = (struct nlattr *)(((unsigned char *)s_nlattr) + NLA_ALIGN(s_nlattr->nla_len))) {
                    s_attr_payload = (void *)(((unsigned char *)s_nlattr) + NLA_HDRLEN);
					if(s_nlattr->nla_len < ((size_t)NLA_HDRLEN)) {
						s_attr_size = (size_t)0u;
					}
					else {
                    	s_attr_size = s_nlattr->nla_len - ((size_t)NLA_HDRLEN);
					}

                    s_output_offset += hwport_dump_space(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth + 1
                    );
                    s_output_offset += (size_t)snprintf(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        "attribute: type=%04lu(%s), len=%lu\n",
                        (unsigned long)s_nlattr->nla_type,
                        (s_nlattr->nla_type < s_attr_name_table_size) ? s_attr_name_table[s_nlattr->nla_type] : "UNKNOWN",
                        (unsigned long)s_nlattr->nla_len
                    );
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth + 2,
                        s_attr_payload, 
                        s_attr_size
                    );
                	switch(s_nlmsghdr->nlmsg_type) {
	                    case RTM_NEWLINK:
	                    case RTM_DELLINK:
	                        break;
	                    case RTM_NEWADDR:
	                    case RTM_DELADDR:
	                        break;
	                    case RTM_NEWROUTE:
	                    case RTM_DELROUTE:
							switch(s_nlattr->nla_type) {
								case RTA_UNSPEC:
									break;
								case RTA_DST:
								case RTA_SRC:
								case RTA_GATEWAY:
								case RTA_PREFSRC:
									do {
										char s_address[ INET6_ADDRSTRLEN ];

										if((s_rtmsg->rtm_family == AF_INET) || (s_rtmsg->rtm_family == AF_INET6)) {
											s_output_offset += hwport_dump_space(
												(char *)(&s_output_buffer[s_output_offset]),
												s_output_buffer_size - s_output_offset,
												s_depth + 2
											);
											s_output_offset += (size_t)snprintf(
												(char *)(&s_output_buffer[s_output_offset]),
												s_output_buffer_size - s_output_offset,
												"%s=\"\x1b[1;37m%s\x1b[0m\"\n",
												(s_rtmsg->rtm_family == AF_INET) ? "IPv4" : "IPv6",
												inet_ntop(
													s_rtmsg->rtm_family,
													(const void *)s_attr_payload,
													(char *)(&s_address[0]),
													(socklen_t)sizeof(s_address)
												)
											);
										}
										else {
											s_output_offset += hwport_dump_space(
												(char *)(&s_output_buffer[s_output_offset]),
												s_output_buffer_size - s_output_offset,
												s_depth + 2
											);
											s_output_offset += (size_t)snprintf(
												(char *)(&s_output_buffer[s_output_offset]),
												s_output_buffer_size - s_output_offset,
												"\x1b[1;37mUnknown address family\x1b[0m\n"
											);
										}
									}while(0);
									break;
								case RTA_IIF:
								case RTA_OIF:
									do {
										unsigned int s_ifindex;

										switch(s_attr_size) {
											case 1:
												s_ifindex = (unsigned int)*((uint8_t *)s_attr_payload);
												break;
											case 2:
												s_ifindex = (unsigned int)*((uint16_t *)s_attr_payload);
												break;
											case 4:
												s_ifindex = (unsigned int)*((uint32_t *)s_attr_payload);
												break;
											case 8:
												s_ifindex = (unsigned int)*((uint64_t *)s_attr_payload);
												break;
											default:
												s_ifindex = 0u;
												break;
										}

										if(s_ifindex != 0u) {
											struct if_nameindex *s_if_nameindex;

											s_if_nameindex = if_nameindex();
											if(s_if_nameindex != ((struct if_nameindex *)0)) {
												size_t s_index;

												for(s_index = (size_t)0u;(s_if_nameindex[s_index].if_index != 0u) && (s_if_nameindex[s_index].if_name != ((char *)0));s_index++) {
													if(s_if_nameindex[s_index].if_index == s_ifindex) {
														s_output_offset += hwport_dump_space(
															(char *)(&s_output_buffer[s_output_offset]),
															s_output_buffer_size - s_output_offset,
															s_depth + 2
														);
														s_output_offset += (size_t)snprintf(
															(char *)(&s_output_buffer[s_output_offset]),
															s_output_buffer_size - s_output_offset,
															"ifindex=\x1b[1;37m%u\x1b[0m, name=\"\x1b[1;37m%s\x1b[0m\"\n",
															s_ifindex,
															s_if_nameindex[s_index].if_name
														);

														break;
													}
												}

												if_freenameindex(s_if_nameindex);
											}
										}
									}while(0);
									break;
								case RTA_PRIORITY:
									do {
										unsigned int s_priority;

										switch(s_attr_size) {
											case 1:
												s_priority = (unsigned int)*((uint8_t *)s_attr_payload);
												break;
											case 2:
												s_priority = (unsigned int)*((uint16_t *)s_attr_payload);
												break;
											case 4:
												s_priority = (unsigned int)*((uint32_t *)s_attr_payload);
												break;
											case 8:
												s_priority = (unsigned int)*((uint64_t *)s_attr_payload);
												break;
											default:
												s_priority = 0u;
												break;
										}

										s_output_offset += hwport_dump_space(
											(char *)(&s_output_buffer[s_output_offset]),
											s_output_buffer_size - s_output_offset,
											s_depth + 2
										);
										s_output_offset += (size_t)snprintf(
											(char *)(&s_output_buffer[s_output_offset]),
											s_output_buffer_size - s_output_offset,
											"priority=\x1b[1;37m%u\x1b[0m\n",
											s_priority
										);
									}while(0);
									break;
								case RTA_METRICS:
									break;
								case RTA_MULTIPATH:
									break;
								case RTA_PROTOINFO:
									break;
								case RTA_FLOW:
									break;
								case RTA_CACHEINFO:
									break;
								case RTA_SESSION:
									break;
								case RTA_MP_ALGO:
									break;
								case RTA_TABLE:
									do {
										unsigned int s_table_number;

										switch(s_attr_size) {
											case 1:
												s_table_number = (unsigned int)*((uint8_t *)s_attr_payload);
												break;
											case 2:
												s_table_number = (unsigned int)*((uint16_t *)s_attr_payload);
												break;
											case 4:
												s_table_number = (unsigned int)*((uint32_t *)s_attr_payload);
												break;
											case 8:
												s_table_number = (unsigned int)*((uint64_t *)s_attr_payload);
												break;
											default:
												s_table_number = 0u;
												break;
										}

										s_output_offset += hwport_dump_space(
											(char *)(&s_output_buffer[s_output_offset]),
											s_output_buffer_size - s_output_offset,
											s_depth + 2
										);
										s_output_offset += (size_t)snprintf(
											(char *)(&s_output_buffer[s_output_offset]),
											s_output_buffer_size - s_output_offset,
											"table_number=\x1b[1;37m%u\x1b[0m\n",
											s_table_number
										);
									}while(0);
									break;
								case RTA_MARK:
									do {
										unsigned int s_mark;

										switch(s_attr_size) {
											case 1:
												s_mark = (unsigned int)*((uint8_t *)s_attr_payload);
												break;
											case 2:
												s_mark = (unsigned int)*((uint16_t *)s_attr_payload);
												break;
											case 4:
												s_mark = (unsigned int)*((uint32_t *)s_attr_payload);
												break;
											case 8:
												s_mark = (unsigned int)*((uint64_t *)s_attr_payload);
												break;
											default:
												s_mark = 0u;
												break;
										}

										s_output_offset += hwport_dump_space(
											(char *)(&s_output_buffer[s_output_offset]),
											s_output_buffer_size - s_output_offset,
											s_depth + 2
										);
										s_output_offset += (size_t)snprintf(
											(char *)(&s_output_buffer[s_output_offset]),
											s_output_buffer_size - s_output_offset,
											"mark=\x1b[1;37m%u\x1b[0m\n",
											s_mark
										);
									}while(0);
									break;
								case RTA_MFC_STATS:
									break;
								default:
									break;
							}
	                        break;
	                    default:
	                        break;
	                }
                }
                s_output_offset += hwport_dump_space(
                    (char *)(&s_output_buffer[s_output_offset]),
                    s_output_buffer_size - s_output_offset,
                    s_depth + 1
                );
                s_output_offset += (size_t)snprintf(
                    (char *)(&s_output_buffer[s_output_offset]),
                    s_output_buffer_size - s_output_offset,
                    "end of attribute (remain=%lu/%lu)\n",
                    (unsigned long)s_attr_window_size,
                    (unsigned long)(s_payload_size - s_message_size)
                );
            }

            if((s_output_offset > ((size_t)0u)) && (s_output_offset > (s_output_buffer_size >> 1))) { /* print message buffer (when many buffered) */
                (void)hwport_output_puts((const char *)(&s_output_buffer[0]));
                s_output_offset = (size_t)0u;
            }
        }

        if(s_output_offset > ((size_t)0u)) { /* print message buffer */
            (void)hwport_output_puts((const char *)(&s_output_buffer[0]));
            s_output_offset = (size_t)0u;
        }

        if(s_is_break != 0) {
            break;
        }
    }

    return(0);
}

int main(int s_argc, char **s_argv)
{
    __u32 s_nl_groups;
    int s_socket;
    struct sockaddr_nl s_sockaddr_nl; 

    size_t s_buffer_size;
    void *s_buffer;

    ssize_t s_send_bytes;

    struct nlmsghdr *s_nlmsghdr;
        
    (void)s_argc;
    (void)s_argv;

    (void)fprintf(stdout, "NETLINK RTNETLINK MONITOR\n\n");

    s_nl_groups = RTMGRP_IPV4_IFADDR;
    s_nl_groups |= RTMGRP_IPV6_IFADDR;
    s_nl_groups |= RTMGRP_IPV4_ROUTE;
    s_nl_groups |= RTMGRP_IPV6_ROUTE;
    s_nl_groups |= RTMGRP_LINK;

    s_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(s_socket == (-1)) {
        perror("socket");
        return(EXIT_FAILURE);
    }

    (void)memset((void *)(&s_sockaddr_nl), 0, sizeof(s_sockaddr_nl));
    s_sockaddr_nl.nl_family = AF_NETLINK;
    s_sockaddr_nl.nl_pad = (unsigned short)0u;
    s_sockaddr_nl.nl_pid = (pid_t)0;
    s_sockaddr_nl.nl_groups = s_nl_groups; /* Multicast groups mask */

    if(bind(s_socket, (const struct sockaddr *)(&s_sockaddr_nl), (socklen_t)sizeof(s_sockaddr_nl)) == (-1)) {
        perror("bind");
        return(EXIT_FAILURE);
    }
    (void)fprintf(stdout, "listening...\n");   
 
    s_buffer_size = (size_t)(512 << 10);
    s_buffer = malloc(s_buffer_size);
    if(s_buffer == ((void *)0)) {
        (void)fprintf(stderr, "not enough memory !\n");
        close(s_socket);
        return(EXIT_FAILURE);
    }

    do {
        struct rtgenmsg *s_rtgenmsg;

        s_nlmsghdr = (struct nlmsghdr *)memset((void *)s_buffer, 0, s_buffer_size);
        s_nlmsghdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
        s_nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH | NLM_F_ROOT;
        s_nlmsghdr->nlmsg_type = RTM_GETLINK;

        s_rtgenmsg = (struct rtgenmsg *)NLMSG_DATA(s_nlmsghdr);
        s_rtgenmsg->rtgen_family = AF_UNSPEC;

        s_send_bytes = send(s_socket, (const void *)s_nlmsghdr, (size_t)s_nlmsghdr->nlmsg_len, MSG_NOSIGNAL);
        if(s_send_bytes == ((ssize_t)(-1))) {
            perror("send RTM_GETLINK");
        }
        else {
            (void)hwport_process_netlink_recv(s_socket, s_buffer, s_buffer_size);
        }
    }while(0);

    do {
        struct rtgenmsg *s_rtgenmsg;

        s_nlmsghdr = (struct nlmsghdr *)memset((void *)s_buffer, 0, s_buffer_size);
        s_nlmsghdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
        s_nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH | NLM_F_ROOT;
        s_nlmsghdr->nlmsg_type = RTM_GETADDR;

        s_rtgenmsg = (struct rtgenmsg *)NLMSG_DATA(s_nlmsghdr);
        s_rtgenmsg->rtgen_family = AF_UNSPEC;

        s_send_bytes = send(s_socket, (const void *)s_nlmsghdr, (size_t)s_nlmsghdr->nlmsg_len, MSG_NOSIGNAL);
        if(s_send_bytes == ((ssize_t)(-1))) {
            perror("send RTM_GETADDR");
        }
        else {
            (void)hwport_process_netlink_recv(s_socket, s_buffer, s_buffer_size);
        }
    }while(0);

    do {
        struct rtmsg *s_rtmsg;

        s_nlmsghdr = (struct nlmsghdr *)memset((void *)s_buffer, 0, s_buffer_size);
        s_nlmsghdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        s_nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        s_nlmsghdr->nlmsg_type = RTM_GETROUTE;

        s_rtmsg = (struct rtmsg *)NLMSG_DATA(s_nlmsghdr);
        s_rtmsg->rtm_family = AF_UNSPEC;
        /* need more fill */

        s_send_bytes = send(s_socket, (const void *)s_nlmsghdr, (size_t)s_nlmsghdr->nlmsg_len, MSG_NOSIGNAL);
        if(s_send_bytes == ((ssize_t)(-1))) {
            perror("send RTM_GETROUTE");
        }
        else {
            (void)hwport_process_netlink_recv(s_socket, s_buffer, s_buffer_size);
        }
    }while(0);

    free(s_buffer);
    (void)close(s_socket);

    return(EXIT_SUCCESS);
}

/* vim: set expandtab: */
/* End of source */
