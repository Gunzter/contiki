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
 *      Erbium (Er) REST Engine example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "rest-engine.h"
#include "hw_interface.h"
#include "er-oscoap.h"

#include "rest2-engine.h"
#if PLATFORM_HAS_BUTTON
#include "dev/button-sensor.h"
#endif

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

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern resource_t coap_lock, oscoap_lock, oscoap2_lock;
extern resource2_t coaps_lock;
const uint8_t sender_id[] =  { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
const uint8_t sender_key[] = {0xd5, 0xcb, 0x37, 0x10, 0x37, 0x15, 0x34, 0xa1, 0xca, 0x22, 0x4e, 0x19, 0xeb, 0x96, 0xe9, 0x6d };
const uint8_t sender_iv[] = {0x20, 0x75, 0x0b, 0x95, 0xf9, 0x78, 0xc8 };

const uint8_t receiver_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
const uint8_t receiver_key[] = {0x21, 0x64, 0x42, 0xda, 0x60, 0x3c, 0x51, 0x59, 0x2d, 0xf4, 0xc3, 0xd0, 0xcd, 0x1d, 0x0d, 0x48 };
const uint8_t receiver_iv[] = {0x01, 0x53, 0xdd, 0xfe, 0xde, 0x44, 0x19 };


PROCESS(er_example_server, "Erbium Example Server");
AUTOSTART_PROCESSES(&er_example_server);

PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  PRINTF("Starting Erbium Example Server\n");

#ifdef RF_CHANNEL
  PRINTF("RF channel: %u\n", RF_CHANNEL);
#endif
#ifdef IEEE802154_PANID
  PRINTF("PAN ID: 0x%04X\n", IEEE802154_PANID);
#endif

  PRINTF("uIP buffer: %u\n", UIP_BUFSIZE);
  PRINTF("LL header: %u\n", UIP_LLH_LEN);
  PRINTF("IP+UDP header: %u\n", UIP_IPUDPH_LEN);
  PRINTF("REST max chunk: %u\n", REST_MAX_CHUNK_SIZE);
  PRINTF("WATCHDOG_CONF_ENABLE %d\n", WATCHDOG_CONF_ENABLE);
  /* Initialize the REST engine. */
  rest_init_engine();
  rest2_init_engine();
  initiate_hw_interface();

  rest_activate_resource(&coap_lock, "coap/lock");
  rest_activate_resource(&oscoap_lock, "coap2coap/oscoap/lock");
  rest_activate_resource(&oscoap2_lock, "oscoap/lock");
  rest2_activate_resource(&coaps_lock, "coaps/lock");

   
  oscoap_ctx_store_init();
  if(oscoap_new_ctx( sender_key, sender_iv, receiver_key, receiver_iv, sender_id, 6, receiver_id, 6, 32) == 0){
    printf("Error: Could not create new Context!\n");
  }


  oscoap_ctx_t* c = NULL;
 uint8_t rid2[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };

  c = oscoap_find_ctx_by_rid(rid2, 6);
  if(c == NULL){
    PRINTF("could not fetch cid\n");
  } else {
  	PRINTF("Context sucessfully added to DB!\n");
    //oscoap_print_context(c);
  }



/* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
  }                             /* while (1) */

  PROCESS_END();
}