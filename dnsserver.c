/**
 * Implements a basic DNS server that responds to A record requests with an
 * IPv4 address from the file passed in as the <ipfile> argument. It is not
 * recommended to run this program on a publicly accessibly machine due to
 * potential security issues. It is designed for use in a privately run
 * test CDN
 *
 * Written by Blake Madden - github.com/blakelymadden
 */

#include "dnsserver.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <stdio.h>

// these are temporarily global variables for the purpose of avoiding extra
// reads/writes from/to disk. Should possibly be refactored.
static int FILE_OFF = 0;
static FILE *IP_FILE = NULL;

/**
 * function to form a network ready dns header
 */
dns_header *make_header(uint16_t id, char qr, char opcode, char aa, char tc,
                        char rd, char ra, char rcode, uint16_t qdcount,
                        uint16_t ancount, uint16_t nscount, uint16_t arcount) {
  dns_header *head = (dns_header*)malloc(sizeof(dns_header));
  head->id = htons(id);

  // set up line 2
  uint16_t line_2 = 0;
  if (qr)
    line_2 = 0x8000;
  if (opcode == 1)
    line_2 |= 0x0800;
  if (opcode == 2)
    line_2 |= 0x1800;
  if (aa)
    line_2 |= 0x0400;
  if (tc)
    line_2 |= 0x0200;
  if (rd)
    line_2 |= 0x0100;
  if (ra)
    line_2 |= 0x0080;
  line_2 |= rcode; // rcode is the last 4 bits

  // copy the line into the header
  memcpy(&(head->l2), &line_2, sizeof(uint16_t));

  // finish adding the other fields
  head->qdcount = htons(qdcount);
  head->ancount = htons(ancount);
  head->nscount = htons(nscount);
  head->arcount = htons(arcount);

  return head;
}

/**
 * generates the entire dns answer
 */
char *dns_answer(uint16_t id, char qr, char opcode, char aa, char tc, char rd,
                 char ra, char rcode, uint16_t qdcount, uint16_t ancount,
                 uint16_t nscount, uint16_t arcount, char *question, int *len) {
  dns_header *header = make_header(htons(id), qr, opcode, aa, tc, rd, ra, rcode,
                                   qdcount, ancount, nscount, arcount);
  *len = 14+sizeof(dns_header)+strlen(question)+7;
  //security vulnerability -- YOLO
  char *name = (char*)malloc(*len);
  char *name_start = name;

  uint16_t type = 0x0100;
  uint16_t class = 0x0100;
  uint32_t ttl = htonl(512);

  // come one come all, gather 'round. Pick an IP, any IP!
  // route away!

  // pick the next IP in the file and route to it.
  ssize_t size;
  char *addr = NULL;
  if ((size = getline(&addr, NULL, IP_FILE+FILE_OFF)) == -1) {
    FILE_OFF = 0;
    addr = NULL;
    if ((size = getline(&addr, NULL, IP_FILE+FILE_OFF)) < 0)
      fprintf(stderr, "Empty <ipfile> argument or incorrect file format\n");
  }
  FILE_OFF += size;
  if (fseek(IP_FILE, FILE_OFF, SEEK_CUR) < 0) // move forward in the file
    perror("fseek");

  // check for a \n and remove it. This should be safe according to the
  // documentation for getline()
  int i = 0;
  for (i = 0; addr[i] != 0; i++) {
    if (addr[i] == '\n')
      addr[i] = 0;
  }

  // translate the IPv4 address from the file to a network ready 32bit int
  uint32_t temp_ip = inet_addr(addr);
  free(addr);
  temp_ip = htonl(temp_ip);

  uint16_t rdlen = htons(4);
  //uint16_t *q_ptr;
  uint16_t q_val = 0xc00c;
  q_val = htons(q_val);

  memcpy(name, header, sizeof(dns_header));
  name+=sizeof(dns_header);
  memcpy(name, question, strlen(question)+5);
  name+=strlen(question)+5;
  memcpy(name, &q_val, sizeof(uint16_t));
  name+=sizeof(uint16_t);
  memcpy(name, &type, sizeof(uint16_t));
  name+=sizeof(uint16_t);
  memcpy(name, &class, sizeof(uint16_t));
  name+=sizeof(uint16_t);
  memcpy(name, &ttl, sizeof(uint32_t));
  name+=sizeof(uint32_t);
  memcpy(name, &rdlen, sizeof(uint16_t));
  name+=sizeof(uint16_t);
  memcpy(name, &temp_ip, sizeof(uint32_t));

  name = name_start; // address of the beginning of the answer
  
  free(header);
  return name;
}

void process_question(char *buf, struct sockaddr *addr, int sockfd) {
  dns_header head;
  struct sockaddr_in *address = (struct sockaddr_in*)addr;
  memcpy(&head, buf, sizeof(dns_header));

  int len = 0;
  char *to_send = dns_answer(head.id, 1, 0, 0, 0, 0,
                             0, 0, 1, 1, 0, 0, buf+sizeof(dns_header), &len);

  //int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = address->sin_port;
  out.sin_addr.s_addr = address->sin_addr.s_addr;

  if (sendto(sockfd, to_send, len, 0, (struct sockaddr*)&out, sizeof(out)) < 0)
    perror("sendto");
}

void get_question(int port) {
  //open our socket
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct sockaddr_in in, fill;
  in.sin_family = AF_INET;
  in.sin_port = htons(port);
  in.sin_addr.s_addr = htonl(INADDR_ANY);
  socklen_t fill_size = sizeof(fill);
  socklen_t in_size = sizeof(in);
  char buf[8096];
  int received = 0;
  fd_set socks;
  int acceptfd;
  int binded;

  if ((binded = bind(sockfd, (struct sockaddr*)&in, in_size)) < 0)
    perror("bind");

  /* This loop a crude way of making this program a dns daemon.
   * There is no graceful exit from this, currently, and that has the
   * consequence of not closing IP_FILE and possibly leaving a zombie
   * process on the hosting server. Should be refactored.
   */
  while (1) {
    FD_ZERO(&socks);
    FD_SET(sockfd, &socks);
    if (select(sockfd+1, &socks, NULL, NULL, NULL)) {
      if ((received = recvfrom(sockfd, buf, 8096, 0, (struct sockaddr*)&fill,
                               &fill_size)) < 0)
        perror("recv");
      process_question(buf, (struct sockaddr*)&fill, sockfd);
    }
    memset(buf, 0, 8096);
  }
}

int main(int argc, char *argv[]) {
  if (argc != 5) {
    printf("usage: %s -p <port> -n <ipfile>\n\n<ipfile> should be a path to a file containing the IPv4 addresses of the\nnodes in your CDN, seperated by a newline character\n", argv[0]);
    exit(1);
  }

  int port = strtol(argv[2], NULL, 10);
  if (!(IP_FILE = fopen(argv[4], "r")))
    perror("fopen");
  get_question(port);
  return 0;
}
