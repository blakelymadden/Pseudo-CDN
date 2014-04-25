#ifndef DNS_SERVER_HEAD
#define DNS_SERVER_HEAD

#include <stdint.h>

// dns header struct
typedef struct dns_header_s {
  uint16_t id;
  uint16_t l2;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} dns_header;

/**
 * function to form a dns header
 */
dns_header *make_header(uint16_t id, char qr, char opcode, char aa, char tc,
                        char rd, char ra, char rcode, uint16_t qdcount,
                        uint16_t ancount, uint16_t nscount, uint16_t arcount);

/**
 * generates the entire dns answer, header included
 */
char *dns_answer(uint16_t id, char qr, char opcode, char aa, char tc, char rd,
                 char ra, char rcode, uint16_t qdcount, uint16_t ancount,
                 uint16_t nscount, uint16_t arcount, char *question, int *len);

/**
 * waits for a DNS question to appear on the designated port. 
 */
void get_question(int port);
#endif
