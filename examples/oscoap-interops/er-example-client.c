/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "er-coap-engine.h"
#include "dev/button-sensor.h"
#include "er-oscoap.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0212, 0x7402, 0x0002, 0x0202)      /* cooja2 */
/* #define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xbbbb, 0, 0, 0, 0, 0, 0, 0x1) */

//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0001)      
//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0003) //z1  
#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0200, 0, 0, 0x0003) //wismote


#define LOCAL_PORT      UIP_HTONS(COAP_DEFAULT_PORT + 1)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

#define TOGGLE_INTERVAL 10

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

uip_ipaddr_t server_ipaddr;

uint8_t test = 0;
uint8_t failed_tests = 0;

void test0_a(coap_packet_t* request);
void test0_a_handler(void* response);
void test1_a(coap_packet_t* request);
void test1_a_handler(void* response);
void test2_a(coap_packet_t* request);
void test2_a_handler(void* response);

char *urls[5] = { "/hello/coap", "hello/1", "hello/2", "/hello/3", "hello/6"};


//Interop
uint8_t master_secret[35] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23}; 

uint8_t sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
uint8_t sender_key[] = {0x21, 0x64, 0x42, 0xda, 0x60, 0x3c, 0x51, 0x59, 0x2d, 0xf4, 0xc3, 0xd0, 0xcd, 0x1d, 0x0d, 0x48 };
uint8_t sender_iv[] = {0x01, 0x53, 0xdd, 0xfe, 0xde, 0x44, 0x19 };

uint8_t receiver_id[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
uint8_t receiver_key[] =  {0xd5, 0xcb, 0x37, 0x10, 0x37, 0x15, 0x34, 0xa1, 0xca, 0x22, 0x4e, 0x19, 0xeb, 0x96, 0xe9, 0x6d };
uint8_t receiver_iv[] =  {0x20, 0x75, 0x0b, 0x95, 0xf9, 0x78, 0xc8 };

uint8_t token[] = { 0x05, 0x05};

PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();
  static struct etimer et;
  static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */

  SERVER_NODE(&server_ipaddr);

  /* receives all CoAP messages */
  coap_init_engine();

  oscoap_ctx_store_init();
  init_token_seq_store();

	if(oscoap_new_ctx( sender_key, sender_iv, receiver_key, receiver_iv, sender_id, 6, receiver_id, 6, 32) == 0){
  	printf("Error: Could not create new Context!\n");
	}
/*
  OscoapCommonContext* oscoap_derrive_ctx(uint8_t* master_secret,
           uint8_t master_secret_len, uint8_t* master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t hkdf_alg,
            uint8_t* sid, uint8_t sid_len, uint8_t* rid, uint8_t rid_len, uint8_t replay_window); */
	
	OscoapCommonContext* c = NULL;
  uint8_t rid2[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
  c = oscoap_find_ctx_by_rid(rid2, 6);
  PRINTF("COAP max size %d\n", COAP_MAX_PACKET_SIZE);
  if(c == NULL){
    printf("could not fetch cid\n");
  }else{
    printf("Context sucessfully added to DB!\n");
  }
 
  etimer_set(&et, 10 * CLOCK_SECOND);
    
  //TODO, this should be implemented using the uri -> cid map, not like this.
  uint8_t rid3[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
  
  void (*handler_ptr)(void*);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {   
      switch ( test ) {
        case 0: 
          test0_a(request);
          handler_ptr = test0_a_handler;
          test++;
          break;
        case 1:
          test1_a(request);
          request->context = oscoap_find_ctx_by_rid(rid3, 6);
          handler_ptr = test1_a_handler;
          test++;
          break;

        default:
          if(failed_tests == 0){
          printf("ALL tests PASSED! Drinks all around!\n");
          } else {
            printf("%d tests failed! Go back and fix those :(\n", failed_tests);
          }
      }
      COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request, test0_a_handler);
        
      etimer_reset(&et);
    } /* etimer */
  } /*while 1 */
    

  if(failed_tests == 0){
    printf("ALL tests PASSED! Drinks all around!\n");
  } else {
    printf("%d tests failed! Go back and fix those :(\n", failed_tests);
  }

  PROCESS_END();
}

void test0_a(coap_packet_t* request){
  printf("\n\nTest 0a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[0]);

  printf("Test 0a: Sending!\n");
}

void test0_a_handler(void* response){
  printf("Test 0a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char* desired = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, response_payload, strlen(desired));
  if(res == 0){
    printf("Test 0a: PASSED!\n");
  }else {
    printf("Test 0a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    oscoap_printf_char(response_payload, len);
    failed_tests++;
  }
}

void test1_a(coap_packet_t* request){
  printf("\n\nTest 1a: Starting!\n");
  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, urls[1]);

  printf("Test 1a: Sending!\n");
}

void test1_a_handler(void* response){
  printf("Test 1a: Receiving Response!\n");

  const uint8_t *response_payload;
  const char* desired = "Hello World!";
  int len = coap_get_payload(response, &response_payload);
  int res = strncmp( desired, response_payload, strlen(desired));
  if(res == 0){
    printf("Test 1a: PASSED!\n");
  }else {
    printf("Test 1a: FAILED!\n");
    printf("\t Expected result: \"Hello World!\" but was: ");
    oscoap_printf_char(response_payload, len);
    failed_tests++;
  }
} 