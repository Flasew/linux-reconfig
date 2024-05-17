#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <sys/time.h>

#define SERVER_PORT 5025
#define THIS_SERVER "128.30.92.132"

#define MAX_HOSTS 24
#define MAX_SW_PORTS 192
#define DEGREE 4

#define SW_SRC(m, i) ((uint16_t)(((m) - 'A')*DEGREE + i))
#define SW_DST(m, i) ((uint16_t)(((m) - 'A')*DEGREE + 192 + i))
#define HOST(p) ((uint16_t)((p % MAX_SW_PORTS) / DEGREE))

#define SW_IP "128.30.93.35"

char *host_ips[MAX_HOSTS] = {
    "128.30.92.132",
    "128.30.92.133",
    "128.30.92.136",
    "128.30.92.243",
    "128.30.92.244",
    "128.30.92.246",
    "128.30.93.1",
    "128.30.92.103",
    "128.30.92.254",
    "128.30.92.255",
    "128.30.93.0",
    "128.30.93.2",
    "128.30.92.93",
    "128.30.92.104",
    "128.30.92.111",
    "128.30.92.123",
    "128.30.92.140",
    "128.30.92.180",
    "128.30.92.185",
    "128.30.92.186",
    "128.30.93.33",
    "128.30.92.116",
    "128.30.93.34",
    "128.30.92.117"
};

uint8_t sw_port_to_ifid[MAX_SW_PORTS] = {0};

struct icmphdr
{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_checksum;
    union
    {
        struct
        {
            uint16_t icmp_id;
            uint16_t icmp_sequence;
        } echo; // ECHO | ECHOREPLY
        struct
        {
            uint16_t unused;
            uint16_t nhop_mtu;
        } dest; // DEST_UNREACH
        struct
        {
            uint16_t dst_id;
            uint8_t src_port;
            uint8_t dst_port;
        } reconfig_newconfig;
    } un;
};

struct reconf_configuration
{
    uint16_t src_arr[MAX_SW_PORTS];
    uint16_t dst_arr[MAX_SW_PORTS];
    unsigned int sw_arr_len;
    int duration; // duration of this config in ms
};

struct reconf_message
{
    struct reconf_configuration config;
    uint8_t *icmp_msg_buf_reconfig_start;
    uint8_t *icmp_msg_buf_reconfig_end;
    unsigned int icmp_arr_len;
    char reconfig_message[BUFSIZ];
};

uint16_t checksum(uint16_t *data, int len)
{

    uint16_t ret = 0;
    uint32_t sum = 0;
    uint16_t odd_byte;

    while (len > 1)
    {
        sum += *data++;
        len -= 2;
    }

    if (len == 1)
    {
        *(uint8_t *)(&odd_byte) = *(uint8_t *)data;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ret = ~sum;

    return ret;
}

void convert_to_sw_string(struct reconf_configuration *config, char *result)
{
    // Temporary buffer to hold each part of the final string
    char temp[10];
    memset(result, 0, BUFSIZ);

    // Start constructing the string
    strcpy(result, ":oxc:swit:conn:add (@");

    // Add src_arr values to the string
    for (unsigned int i = 0; i < config->sw_arr_len; i++)
    {
        sprintf(temp, "%u", config->src_arr[i]+1);
        strcat(result, temp);
        if (i < config->sw_arr_len - 1)
        {
            strcat(result, ",");
        }
    }

    // Add separator between arrays
    strcat(result, "),(@");

    // Add dst_arr values to the string
    for (unsigned int i = 0; i < config->sw_arr_len; i++)
    {
        sprintf(temp, "%u", config->dst_arr[i]+1);
        strcat(result, temp);
        if (i < config->sw_arr_len - 1)
        {
            strcat(result, ",");
        }
    }

    // Close the string
    strcat(result, ")\n");
}

int construct_icmp_messages(uint8_t *buffer, uint16_t sw_src, uint16_t sw_dst, uint8_t code)
{
    struct in_addr srcip, dstip;
    char *srcip_str, *dstip_str;
    uint8_t src_port, dst_port;
    uint16_t src_host, dst_host;
    struct iphdr *iph;
    struct icmphdr *icmph;

    srcip_str = host_ips[HOST(sw_src)];
    dstip_str = host_ips[HOST(sw_dst)];
    src_port = sw_port_to_ifid[sw_src];
    dst_port = sw_port_to_ifid[sw_dst];
    src_host = HOST(sw_src);
    dst_host = HOST(sw_dst);
#ifdef DEBUG
    char srcip_displaybuf[BUFSIZ], dstip_displaybuf[BUFSIZ];
    char * tmp;
#endif

    inet_aton(THIS_SERVER, &srcip);
    inet_aton(srcip_str, &dstip);

    memset(buffer, 0, BUFSIZ * sizeof(uint8_t));
    iph = (struct iphdr *)buffer;

    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 1;
    iph->check = 0;
    iph->saddr = srcip.s_addr;
    iph->daddr = dstip.s_addr;

    icmph = (struct icmphdr *)(buffer + sizeof(struct iphdr));
    icmph->icmp_type = 9;
    icmph->icmp_code = code;
    icmph->icmp_checksum = 0;
    icmph->un.reconfig_newconfig.dst_id = htons(dst_host);
    icmph->un.reconfig_newconfig.dst_port = dst_port;
    icmph->un.reconfig_newconfig.src_port = src_port;

    icmph->icmp_checksum = checksum((uint16_t *)icmph, sizeof(struct icmphdr));
    iph->check = checksum((uint16_t *)iph, sizeof(struct iphdr));

#ifdef DEBUG
    tmp = inet_ntoa(srcip);
    strncpy(srcip_displaybuf, tmp, strlen(tmp));
    tmp = inet_ntoa(dstip);
    strncpy(dstip_displaybuf, tmp, strlen(tmp));

    fprintf(stderr, "sw_src %u, sw_dst %u, srcip_str %s, dstip_str %s, out_src %s, out_dst %s, "
        "src_port %u, dst_port %u, src_host %u, dst_host %u, code %u\n",
        sw_src, sw_dst, srcip_str, dstip_str, srcip_displaybuf, dstip_displaybuf, src_port, dst_port, src_host, dst_host, code
    );
#endif

    return 0;
}

int construct_reconf_message(struct reconf_message *msg_buf, struct reconf_configuration *config)
{
    int i, err;

    memset(msg_buf, 0, sizeof(struct reconf_message));
    memcpy(&msg_buf->config, config, sizeof(struct reconf_configuration));
    msg_buf->icmp_arr_len = msg_buf->config.sw_arr_len;
    msg_buf->icmp_msg_buf_reconfig_start = malloc(sizeof(uint8_t) * BUFSIZ * msg_buf->icmp_arr_len);
    msg_buf->icmp_msg_buf_reconfig_end = malloc(sizeof(uint8_t) * BUFSIZ * msg_buf->icmp_arr_len);

    for (i = 0; i < msg_buf->icmp_arr_len; i++)
    {
        err = construct_icmp_messages(msg_buf->icmp_msg_buf_reconfig_start +
                                          (i * BUFSIZ),
                                      msg_buf->config.src_arr[i], msg_buf->config.dst_arr[i], 0);
        if (err)
            return err;
        err = construct_icmp_messages(msg_buf->icmp_msg_buf_reconfig_end +
                                          (i * BUFSIZ),
                                      msg_buf->config.src_arr[i], msg_buf->config.dst_arr[i], 1);
        if (err)
            return err;
    }

    convert_to_sw_string(&msg_buf->config, msg_buf->reconfig_message);
    return 0;
}

enum network_state
{
    RECONFIG,
    CONNECTED
};

/* These should eventually take the form of cmd argument
 * For now hardcoding two configurations
 */
#define NCONFIG 2
struct reconf_configuration configs[NCONFIG] = {
    {.src_arr = {SW_SRC('E', 0), SW_SRC('F', 0), SW_SRC('G', 0), SW_SRC('H', 0)},
     .dst_arr = {SW_DST('F', 0), SW_DST('E', 0), SW_DST('H', 0), SW_DST('G', 0)},
     .sw_arr_len = 4,
     .duration = 1000},
    {.src_arr = {SW_SRC('E', 0), SW_SRC('F', 0), SW_SRC('G', 0), SW_SRC('H', 0)},
     .dst_arr = {SW_DST('G', 0), SW_DST('H', 0), SW_DST('E', 0), SW_DST('F', 0)},
     .sw_arr_len = 4,
     .duration = 1000}};
#define GUARD_TIME_MS 30

int main(int argc, char *argv[])
{
    int sw_sock_fd;
    struct sockaddr_in sw_addr;
    char telnet_buf[BUFSIZ] = {0};
    ssize_t bytes_received;

    struct reconf_message reconf_msgs[NCONFIG];
    int host_socket_fd;
    struct sockaddr_in host_dsts[MAX_HOSTS];
    struct in_addr host_ipaddrs[MAX_HOSTS];

    int i, rv, on, curr_state, next_state;
    enum network_state state = CONNECTED;

    struct reconf_message *curr_reconf_message;

    // Create a socket
    sw_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sw_sock_fd < 0)
    {
        perror("Switch socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    memset(&sw_addr, 0, sizeof(sw_addr));
    sw_addr.sin_family = AF_INET;
    sw_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SW_IP, &sw_addr.sin_addr) <= 0)
    {
        perror("Invalid address or address not supported");
        close(sw_sock_fd);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sw_sock_fd, (struct sockaddr *)&sw_addr, sizeof(sw_addr)) < 0)
    {
        perror("Connection failed");
        close(sw_sock_fd);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Connected to %s\n", SW_IP);
#ifdef DEBUG
    // test: *idn?
    strncpy(telnet_buf, "*idn?\n", strlen("*idn?\n"));
    if (send(sw_sock_fd, telnet_buf, strlen(telnet_buf), 0) < 0)
    {
        perror("*idn? test failed");
        close(sw_sock_fd);
        exit(EXIT_FAILURE);
    }
    bytes_received = recv(sw_sock_fd, telnet_buf, BUFSIZ - 1, 0);
    if (bytes_received < 0)
    {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }
    else if (bytes_received == 0)
    {
        fprintf(stderr, "Server closed the connection\n");
        exit(EXIT_FAILURE);
    }
    // Null-terminate the received data and print it
    telnet_buf[bytes_received] = '\0';
    fprintf(stderr, "Server: %s\n", telnet_buf);
#endif

    for (i = 0; i < NCONFIG; i++)
    {
        construct_reconf_message(reconf_msgs + i, configs + i);
    }

    // create a raw socket
    if ((host_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("host socket()");
        exit(EXIT_FAILURE);
    }

    // set socket option so that we provide the ip header
    on = 1;
    if (setsockopt(host_socket_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }

    memset(host_dsts, 0, sizeof(host_dsts));
    for (i = 0; i < MAX_HOSTS; i++)
    {
        inet_aton(host_ips[i], host_ipaddrs + i);
        host_dsts[i].sin_family = AF_INET;
        host_dsts[i].sin_port = 0;
        host_dsts[i].sin_addr = host_ipaddrs[i];
    }

    // reconfiguration loop
    curr_state = 0;
    do
    {
        next_state = (curr_state + 1) % NCONFIG;
        curr_reconf_message = reconf_msgs + next_state;
        if (state == CONNECTED)
        {
            // send icmp down messages
            for (i = 0; i < curr_reconf_message->icmp_arr_len; i++)
            {
                // on is the switch port id
                on = curr_reconf_message->config.src_arr[i];
                if ((rv = sendto(host_socket_fd,
                                 curr_reconf_message->icmp_msg_buf_reconfig_start + i * sizeof(uint8_t) * BUFSIZ,
                                 sizeof(struct iphdr) + sizeof(struct icmphdr), 0,
                                 (struct sockaddr *)host_dsts + HOST(on), sizeof(host_dsts[i]))) < 0)
                {
                    fprintf(stderr, "Sending icmp start reconfig to host %d failed!\n", i);
                    perror("sendto()");
                    exit(EXIT_FAILURE);
                }
#ifdef DEBUG
                else
                {
                    fprintf(stderr, "Sent icmp start reconfig to host %d.\n", i);
                }
#endif
            }
            if (send(sw_sock_fd, curr_reconf_message->reconfig_message,
                     strlen(curr_reconf_message->reconfig_message), 0) < 0)
            {
                perror("Failed to send reconfig messag to switch!");
                exit(EXIT_FAILURE);
            }
#ifdef DEBUG
            else 
            {
                fprintf(stderr, "Sent %s\n", curr_reconf_message->reconfig_message);
            }
#endif
            state = RECONFIG;
            usleep(GUARD_TIME_MS * 1000);

            // now icmp things up
            for (i = 0; i < curr_reconf_message->icmp_arr_len; i++)
            {
                // on is the switch port id
                on = curr_reconf_message->config.src_arr[i];
                if ((rv = sendto(host_socket_fd,
                                 curr_reconf_message->icmp_msg_buf_reconfig_end + i * sizeof(uint8_t) * BUFSIZ,
                                 sizeof(struct iphdr) + sizeof(struct icmphdr), 0,
                                 (struct sockaddr *)host_dsts + HOST(on), sizeof(host_dsts[i]))) < 0)
                {
                    fprintf(stderr, "Sending icmp finish reconfig to host %d failed!\n", i);
                    perror("sendto()");
                    exit(EXIT_FAILURE);
                }
#ifdef DEBUG
                else
                {
                    fprintf(stderr, "Sent icmp finish reconfig to host %d.\n", i);
                }
#endif
            }
            state = CONNECTED;
            curr_state = next_state;
            usleep(curr_reconf_message->config.duration * 1000);
        }
        else
        {
            perror("Shouldn't enter the loop in RECONFIG");
            exit(EXIT_FAILURE);
        }
    } while (1);

    close(sw_sock_fd);
    close(host_socket_fd);

    return 0;
}
