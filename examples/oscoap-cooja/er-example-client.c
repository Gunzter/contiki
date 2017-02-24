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

//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0001)      /* */
#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0003)      /* */


#define LOCAL_PORT      UIP_HTONS(COAP_DEFAULT_PORT + 1)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

#define TOGGLE_INTERVAL 10

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

uip_ipaddr_t server_ipaddr;
static struct etimer et;

/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 5
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "/actuators/toggle", "battery/", "error/in//path", "/hello" };
#if PLATFORM_HAS_BUTTON
static int uri_switch = 0;
#endif

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(void *response)
{
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);
  printf("|%.*s", len, (char *)chunk);
  printf("\n");
}

PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();

  static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */

  SERVER_NODE(&server_ipaddr);

  /* receives all CoAP messages */
  coap_init_engine();
  PRINTF("uIP buffer: %u\n", UIP_BUFSIZE);
  PRINTF("LL header: %u\n", UIP_LLH_LEN);
  PRINTF("IP+UDP header: %u\n", UIP_IPUDPH_LEN);
  PRINTF("REST max chunk: %u\n", REST_MAX_CHUNK_SIZE);

#if PLATFORM_HAS_BUTTON
  SENSORS_ACTIVATE(button_sensor);
  printf("Press a button to request %s\n", service_urls[uri_switch]);
#endif
    
  oscoap_ctx_store_init();
/*
uint8_t master_secret[24] = { 0xfe, 0x29, 0x32, 0xc5, 0x06, 0xde, 0x98, 0xe5, 0x4f, 0xf2, 0x20, 0xf5, 0xbe, 0xb4, 0x73, 0x3b, 
0x24, 0xc5, 0x67, 0x1d, 0x6c, 0x3a, 0xd5, 0x7f };
uint8_t context_id[CONTEXT_ID_LEN] = {0xCA, 0xFE, 0xF0, 0x0D, 0xBA, 0xAD, 0xC0, 0xDE };
uint8_t sid[1] = { 0x00};
uint8_t rid[1] = { 0x01};
uint8_t replay_window = 64;
if(oscoap_derrive_ctx(context_id, CONTEXT_ID_LEN, master_secret, 24, 12 , 1,
            sid, 1, rid, 1, 64) == 0){
  printf("Error: Could not create new Context!\n");
}
*/

/*
//martin's demo
  uint8_t cid[CONTEXT_ID_LEN] = { 0xCA, 0xFE, 0xF0, 0x0D, 0xBA, 0xAD, 0xC0, 0xDE};
  char receiver_key[] = {0xA8,0xFF,0x80,0xB6,0x5C,0xA4,0x15,0xFD,0x48,0x62,0x54,0x0E,0x59,0xC6,0xC0,0x68};
  char receiver_iv[] =  {0x13,0xC6,0xA8,0x98,0xCB,0xCC,0xAD}; 
  

  char sender_key[] = {0x91,0x16,0x33,0x57,0x36,0xA9,0x33,0xCA,0x26,0x8C,0xB6,0x2B,0xD6,0xE4,0xDD,0x36}; 
  char sender_iv[] =  {0x11,0x2C,0xF8,0x2D,0xD0,0xC9,0x43};

  char sender_id[] = { 0x00 };
  char receiver_id[] = { 0x01 };
  if(oscoap_new_ctx( cid, sender_key, sender_iv, receiver_key, receiver_iv,sender_id, 1, receiver_id, 1, 64) == 0){
    printf("Error: Could not create new Context!\n");
  }


  OSCOAP_COMMON_CONTEXT* c = NULL;
  uint8_t cid2[CONTEXT_ID_LEN] =  {0xCA, 0xFE, 0xF0, 0x0D, 0xBA, 0xAD, 0xC0, 0xDE };
  c = oscoap_find_ctx_by_cid(cid2);
  PRINTF("COAP max size %d\n", COAP_MAX_PACKET_SIZE);
  if(c == NULL){
    printf("could not fetch cid\n");
  }else{
    printf("Context sucessfully added to DB!\n");
 //   oscoap_print_context(c);
  }
 */
  
  //Interop
	uint8_t cid[CONTEXT_ID_LEN] = { 0x4B, 0x65, 0x79, 0x23, 0x30};
	char sender_key[] = {0xEB,0x43,0x09,0x8A,0x0F,0x6F,0x7B,0x69,0xCE,0xDF,0x29,0xE0,0x80,0x50,0x95,0x82};
	char sender_iv[] = {0x58,0xF9,0x1A,0x5C,0xDF,0xF4,0xF5};

	char receiver_key[] =  {0xF8,0x20,0x1E,0xD1,0x5E,0x10,0x37,0xBC,0xAF,0x69,0x06,0x07,0x9A,0xD3,0x0B,0x4F};
	char receiver_iv[] =  {0xE8,0x28,0xA4,0x79,0xD0,0x88,0xC4};

	char receiver_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
	char sender_id[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
	if(oscoap_new_ctx( cid, sender_key, sender_iv, receiver_key, receiver_iv, sender_id, ID_LEN, receiver_id, ID_LEN, 64) == 0){
  	printf("Error: Could not create new Context!\n");
	}
	
	OSCOAP_COMMON_CONTEXT* c = NULL;
  uint8_t cid2[CONTEXT_ID_LEN] =  { 0x4B, 0x65, 0x79, 0x23, 0x30};
  c = oscoap_find_ctx_by_cid(cid2);
  PRINTF("COAP max size %d\n", COAP_MAX_PACKET_SIZE);
  if(c == NULL){
    printf("could not fetch cid\n");
  }else{
    printf("Context sucessfully added to DB!\n");
  }

  printf("server ip poither %p\n", &server_ipaddr);

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

#if PLATFORM_HAS_BUTTON
  SENSORS_ACTIVATE(button_sensor);
  printf("Press a button to request %s\n", service_urls[uri_switch]);
#endif

  while(1) {
    PROCESS_YIELD();
  

    if(etimer_expired(&et)) {
 /*     printf("--Toggle timer--\n");

      // prepare request, TID is set by COAP_BLOCKING_REQUEST() 
      coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
      coap_set_header_uri_path(request, service_urls[1]);

      const char msg[] = "Toggle!";

      coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1);

      PRINT6ADDR(&server_ipaddr);
      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request,
                            client_chunk_handler);

      printf("\n--Done--\n");
*/
      printf("\n --Get test/hello-- \n");
   
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
 
      //TODO, this should be implemented using the uri -> cid map, not like this.
      uint8_t cid3[CONTEXT_ID_LEN] = { 0x4B, 0x65, 0x79, 0x23, 0x30};
      request->context = oscoap_find_ctx_by_cid(cid3);
     
      coap_set_header_uri_path(request, service_urls[4]);

      char* u_buffer;
      int uri_len = coap_get_header_uri_path(request, &u_buffer);
      char uri_host = "oscoap.test";
      //int uri_host_len = coap_set_header_uri_host(request, &uri_host);
     // printf("uri_host l %d\n", uri_host_len);
      //char* uh;
      //uri_host_len = coap_get_header_uri_host(request, &uh);
      //printf("ubuf: %s\n",u_buffer);
      //printf("uri-host %.*s\n",uri_host_len, uh);

      coap_set_header_object_security(request);
      //request->ipaddr = &server_ipaddr;
      char token[] = { 0x05, 0x05};
      coap_set_token(request, token, 2);
      printf("--Requesting %s--\n", service_urls[4]);

      PRINT6ADDR(&server_ipaddr);
      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request,
                            client_chunk_handler);

      printf("\n--Done--\n");

      etimer_reset(&et);

#if PLATFORM_HAS_BUTTON
    } else if(ev == sensors_event && data == &button_sensor) {

      /* send a request to notify the end of the process */

      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, service_urls[uri_switch]);

      printf("--Requesting %s--\n", service_urls[uri_switch]);

      PRINT6ADDR(&server_ipaddr);
      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request,
                            client_chunk_handler);

      printf("\n--Done--\n");

      uri_switch = (uri_switch + 1) % NUMBER_OF_URLS;
#endif
    }
  }

  PROCESS_END();
}
