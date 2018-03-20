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

//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0003) //z1  
#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0200, 0, 0, 0x0003) //wismote


#define LOCAL_PORT      UIP_HTONS(COAP_DEFAULT_PORT + 1)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

#define TOGGLE_INTERVAL 2

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

uip_ipaddr_t server_ipaddr;
static struct etimer et;
static int ctr = 0;
static int payload_len = 0;
/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 3
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "/hello/world", "/test" };

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(void *response)
{
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);
  printf("|%.*s", len, (char *)chunk);
  printf("\n");
}

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
  printf("Press a button to request %s\n", service_urls[1]);
#endif
    
  oscoap_ctx_store_init();
  init_token_seq_store();

//if(oscoap_derrive_ctx(master_secret, 35, NULL, 0, 12, 1,sender_id, 6, receiver_id, 6, 32) == 0) {
//  printf("Error: Could not derive new Context!\n");
//}
if(oscoap_new_ctx( sender_key, sender_iv, receiver_key, receiver_iv, sender_id, 6, receiver_id, 6, 32) == 0){
  	printf("Error: Could not create new Context!\n");
}

/*	
  oscoap_ctx_t* c = NULL;
  uint8_t rid2[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
  c = oscoap_find_ctx_by_rid(rid2, 6);
  PRINTF("COAP max size %d\n", COAP_MAX_PACKET_SIZE);
  if(c == NULL){
    printf("could not fetch cid\n");
  }else{
    printf("Context sucessfully added to DB!\n");
  }
*/

  char const *const msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789101112113141516171819202122232425262728293031323334353637383940";

  printf("CPU, Low-Power-Mode, Transmit, Listen\n");

 // printf("Start!\n");
 // coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0); 
 // coap_set_header_uri_path(request, service_urls[2]);
//  COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request, client_chunk_handler);
  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND*15);


  while(1) {
    PROCESS_YIELD();
  

    if(etimer_expired(&et)) {

//      etimer_reset(&et);
        if(payload_len > 256){
                printf("END!\n");
                ctr = 0;
                payload_len = 0;
                //while(1){
                //}
                //break; //while(1)
        }
        // prepare request, TID is set by COAP_BLOCKING_REQUEST() 
        if(ctr % 10 == 0){
                coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
        } else {
                coap_init_message(request, COAP_TYPE_CON, COAP_PUT, 0);
                if(ctr > 20){
                        coap_set_payload(request, msg, payload_len);
                }
        }

        coap_set_header_uri_path(request, service_urls[2]);
        if(ctr >= 10 || ctr == 0){
//              PRINT6ADDR(&server_ipaddr);
//                      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));
                if(request->code == COAP_GET){
                        printf("GET");
                } else {
                        printf("PUT");
                }
		uint8_t rid3[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
      		request->context = oscoap_find_ctx_by_rid(rid3, 6);
     
    		coap_set_header_object_security(request);
      
                coap_set_token(request, token, 2);
		printf(" to %s, sending %d bytes\n", service_urls[2], payload_len);
                COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request,
                            client_chunk_handler);
      		token[1]++;
        } else {
                printf("pass!\n");
        }

        if(ctr % 10 == 0){
                if(payload_len == 0 && ctr >= 20){
                        payload_len++;
                } else {
                        payload_len *= 2;
                }
        }
         etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
        ctr++;

    }
  } //while(1)

  PROCESS_END();
}
