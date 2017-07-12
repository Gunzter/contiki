#include "er-coap.h"
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

void test0_a(coap_packet_t* request);
void test0_a_handler(void* response);

void test1_a(coap_packet_t* request);
void test1_a_handler(void* response);

void test2_a(coap_packet_t* request);
void test2_a_handler(void* response);

void test3_a(coap_packet_t* request);
void test3_a_handler(void* response);

void test4_a(uip_ipaddr_t *server_ipaddr, uint16_t server_port);
static void test4_a_handler(coap_observee_t *obs, void *notification,
                      coap_notification_flag_t flag);