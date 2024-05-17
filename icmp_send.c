#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <linux/ip.h>
#include <unistd.h>

#define SRC_IP "128.30.92.246"
#define DST_IP "128.30.92.246"

struct icmphdr {
  uint8_t  icmp_type;
  uint8_t  icmp_code;
  uint16_t icmp_checksum;
  union {
    struct {
      uint16_t icmp_id;
      uint16_t icmp_sequence;
    } echo;                     // ECHO | ECHOREPLY
    struct {
      uint16_t unused;
      uint16_t nhop_mtu;
    } dest;                     // DEST_UNREACH
    struct {
      uint16_t dst_id;
      uint8_t src_port;
      uint8_t dst_port;
    } reconfig_newconfig;  
  } un;
};

uint16_t checksum(uint16_t *data, int len) {

  uint16_t ret = 0;
  uint32_t sum = 0;
  uint16_t odd_byte;
  
  while (len > 1) {
    sum += *data++;
    len -= 2;
  }
  
  if (len == 1) {
    *(uint8_t*)(&odd_byte) = * (uint8_t*)data;
    sum += odd_byte;
  }
  
  sum =  (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  ret =  ~sum;
  
  return ret; 
}

int main(int argc, char * argv[]) {

  uint8_t src_port;
  uint8_t dst_port;
  uint16_t dst_id;
  uint8_t code;
  if (argc == 5) {
    src_port = atoi(argv[1]);
    dst_port = atoi(argv[2]);
    dst_id = atoi(argv[3]);
    code = atoi(argv[4]);
  }
  else if (argc == 4) {
    src_port = atoi(argv[1]);
    dst_port = 0;
    dst_id = atoi(argv[2]);
    code = atoi(argv[3]);
  }
  else {
    fprintf(stderr, "Invalid number of arguments\n");
    exit(EXIT_FAILURE);
  }

  // create a raw socket
  int sock;
  if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  // set socket option so that we provide the ip header
  int on = 1;
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
  {
    perror("setsockopt()");
    exit(EXIT_FAILURE);
  }

  // create an ICMP network update header
  uint8_t snd_buf[BUFSIZ] = {0};
  struct in_addr srcip, dstip;
  inet_aton(SRC_IP, &srcip);
  inet_aton(DST_IP, &dstip);
  struct iphdr * iph = (struct iphdr*)snd_buf;

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

  struct icmphdr * icmph = (struct icmphdr*)(snd_buf + sizeof(struct iphdr));
  icmph->icmp_type = 9; 
  icmph->icmp_code = code;
  icmph->icmp_checksum = 0;
  icmph->un.reconfig_newconfig.dst_id = htons(dst_id);
  icmph->un.reconfig_newconfig.dst_port = dst_port;
  icmph->un.reconfig_newconfig.src_port = src_port;

  icmph->icmp_checksum = checksum((uint16_t*)icmph, sizeof(struct icmphdr));
  iph->check = checksum((uint16_t*)iph, sizeof(struct iphdr));

  // send it
  struct sockaddr_in dst = {
    .sin_family = AF_INET,
    .sin_port = 0,
    .sin_addr = dstip
  };


  int rv;
  if ((rv = sendto(sock, snd_buf, 
          sizeof(struct iphdr)+sizeof(struct icmphdr), 0, 
          (struct sockaddr *)&dst, sizeof(dst))) < 0) {
    perror("sendto()");
    exit(EXIT_FAILURE);
  } 

  fprintf(stderr, "Sent icmp succeed\n");
  
  close(sock);
  return 0;

}
