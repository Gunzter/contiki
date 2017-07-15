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

void test6_a(coap_packet_t* request);
void test6_a_handler(void* response);

void test7_a(coap_packet_t* request);
void test7_a_handler(void* response);

void test8_a(coap_packet_t* request);
void test8_a_handler(void* response);

void test9_a(coap_packet_t* request);
void test9_a_handler(void* response);

void test10_a(coap_packet_t* request);
void test10_a_handler(void* response);

void test11_a(coap_packet_t* request);
void test11_a_handler(void* response);

void test12_a(coap_packet_t* request);
void test12_a_handler(void* response);

void test13_a(coap_packet_t* request);
void test13_a_handler(void* response);

void test14_a(coap_packet_t* request);
void test14_a_handler(void* response);

void test15_a(coap_packet_t* request);
void test15_a_handler(void* response);