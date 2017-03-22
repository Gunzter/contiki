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
#include "er-oscoap.h"


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
extern resource_t
  res_hello,
  res_mirror,
  res_chunks,
  res_separate,
  res_push,
  res_event,
	  res_sub,
	  res_b1_sep_b2;
#if PLATFORM_HAS_LEDS
extern resource_t res_leds, res_toggle;
#endif
#if PLATFORM_HAS_LIGHT
#include "dev/light-sensor.h"
extern resource_t res_light;
#endif
#if PLATFORM_HAS_BATTERY
#include "dev/battery-sensor.h"
extern resource_t res_battery;
#endif
#if PLATFORM_HAS_TEMPERATURE
#include "dev/temperature-sensor.h"
extern resource_t res_temperature;
#endif



/*
extern resource_t res_battery;
#endif
#if PLATFORM_HAS_RADIO
#include "dev/radio-sensor.h"
extern resource_t res_radio;
#endif
#if PLATFORM_HAS_SHT11
#include "dev/sht11/sht11-sensor.h"
extern resource_t res_sht11;
#endif
*/

uint8_t receiver_key[] = {0xEB,0x43,0x09,0x8A,0x0F,0x6F,0x7B,0x69,0xCE,0xDF,0x29,0xE0,0x80,0x50,0x95,0x82};
uint8_t receiver_iv[] = {0x58,0xF9,0x1A,0x5C,0xDF,0xF4,0xF5};

uint8_t sender_key[] =  {0xF8,0x20,0x1E,0xD1,0x5E,0x10,0x37,0xBC,0xAF,0x69,0x06,0x07,0x9A,0xD3,0x0B,0x4F};
uint8_t sender_iv[] =  {0xE8,0x28,0xA4,0x79,0xD0,0x88,0xC4};

uint8_t sender_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
uint8_t receiver_id[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };

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

  /* Initialize the REST engine. */
  rest_init_engine();

  /*
   * Bind the resources to their Uri-Path.
   * WARNING: Activating twice only means alternate path, not two instances!
   * All static variables are the same for each URI path.
   */
  rest_activate_resource(&res_hello, "hello");
/*  rest_activate_resource(&res_mirror, "debug/mirror"); */
/*  rest_activate_resource(&res_chunks, "test/chunks"); */
/*  rest_activate_resource(&res_separate, "test/separate"); */
 // rest_activate_resource(&res_push, "test/push");
/*  rest_activate_resource(&res_event, "sensors/button"); */
/*  rest_activate_resource(&res_sub, "test/sub"); */
/*  rest_activate_resource(&res_b1_sep_b2, "test/b1sepb2"); */
#if PLATFORM_HAS_LEDS
/*  rest_activate_resource(&res_leds, "actuators/leds"); */
  rest_activate_resource(&res_toggle, "actuators/toggle");
#endif
#if PLATFORM_HAS_LIGHT
 // rest_activate_resource(&res_light, "sensors/light"); 
 // SENSORS_ACTIVATE(light_sensor);  
#endif
#if PLATFORM_HAS_BATTERY
  rest_activate_resource(&res_battery, "sensors/battery");  
  SENSORS_ACTIVATE(battery_sensor);  
#endif
#if PLATFORM_HAS_TEMPERATURE
  //rest_activate_resource(&res_temperature, "sensors/temperature");  
 // SENSORS_ACTIVATE(temperature_sensor);  
#endif


oscoap_ctx_store_init();


//Interop

if(oscoap_new_ctx( sender_key, sender_iv, receiver_key, receiver_iv, sender_id, 6, receiver_id, 6, 32) == 0){
  printf("Error: Could not create new Context!\n");
}


/*
//Martin's demo
uint8_t cid[CONTEXT_ID_LEN] = { 0xCA, 0xFE, 0xF0, 0x0D, 0xBA, 0xAD, 0xC0, 0xDE};
char receiver_key[] = {0x91,0x16,0x33,0x57,0x36,0xA9,0x33,0xCA,0x26,0x8C,0xB6,0x2B,0xD6,0xE4,0xDD,0x36};
char receiver_iv[] = {0x11,0x2C,0xF8,0x2D,0xD0,0xC9,0x43};

char sender_key[] =  {0xA8,0xFF,0x80,0xB6,0x5C,0xA4,0x15,0xFD,0x48,0x62,0x54,0x0E,0x59,0xC6,0xC0,0x68};
char sender_iv[] =  {0x13,0xC6,0xA8,0x98,0xCB,0xCC,0xAD};

char sender_id[] = { 0x01 };
char receiver_id[] = { 0x00 };
if(oscoap_new_ctx( cid, sender_key, sender_iv, receiver_key, receiver_iv, sender_id, 1, receiver_id, 1, 64) == 0){
  printf("Error: Could not create new Context!\n");
}
*/
/*
uint8_t master_secret[24] = { 0xfe, 0x29, 0x32, 0xc5, 0x06, 0xde, 0x98, 0xe5, 0x4f, 0xf2, 0x20, 0xf5, 0xbe, 0xb4, 0x73, 0x3b, 
0x24, 0xc5, 0x67, 0x1d, 0x6c, 0x3a, 0xd5, 0x7f };
uint8_t context_id[CONTEXT_ID_LEN] = {0xCA, 0xFE, 0xF0, 0x0D, 0xBA, 0xAD, 0xC0, 0xDE };
uint8_t sid[1] = { 0x01};
uint8_t rid[1] = { 0x00};
uint8_t replay_window = 64;
if(oscoap_derrive_ctx(context_id, CONTEXT_ID_LEN, master_secret, 24, 12 , 1,
            sid, 1, rid, 1, 64) == 0){
  printf("Error: Could not create new Context!\n");
}
*/

OscoapCommonContext* c = NULL;
uint8_t rid2[] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
c = oscoap_find_ctx_by_rid(rid2, 6);
PRINTF("COAP max size %d\n", COAP_MAX_PACKET_SIZE);
if(c == NULL){
    PRINTF("could not fetch cid\n");
} else {
  	PRINTF("Context sucessfully added to DB!\n");
  //  oscoap_print_context(c);
}
//PRINTF("UIP_CONF_BUFFER_SIZE = %d\n", UIP_CONF_BUFFER_SIZE);
//#ifndef WATCHDOG_CONF_ENABLE
//PRINTF(" WATCHDOG_CONF_ENABLE 1\n");
//#endif

/* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
#if PLATFORM_HAS_BUTTON
    if(ev == sensors_event && data == &button_sensor) {
      PRINTF("*******BUTTON*******\n");

      /* Call the event_handler for this application-specific event. */
      res_event.trigger();

      /* Also call the separate response example handler. */
      res_separate.resume();
    }
#endif /* PLATFORM_HAS_BUTTON */
  }                             /* while (1) */

  PROCESS_END();
}
