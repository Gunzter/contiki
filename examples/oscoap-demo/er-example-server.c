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
  res_temperature,
 // res_oscoap_temperature,
  res_coap_light,
  res_oscoap_light;

/*  res_mirror,
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

*/


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

uint8_t sender_id[] =  { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
//uint8_t sender_key[] = {0xd5, 0xcb, 0x37, 0x10, 0x37, 0x15, 0x34, 0xa1, 0xca, 0x22, 0x4e, 0x19, 0xeb, 0x96, 0xe9, 0x6d };
//uint8_t sender_iv[] = {0x20, 0x75, 0x0b, 0x95, 0xf9, 0x78, 0xc8 };

uint8_t receiver_key[]  = {0x21, 0x64, 0x42, 0xDA, 0x60, 0x3C, 0x51, 0x59, 0x2D, 0xF4, 0xC3, 0xD0, 0xCD, 0x1D, 0x0D, 0x48};
uint8_t receiver_iv[]   = {0x01, 0x53, 0xDD, 0xFE, 0xDE, 0x44, 0x19};
 
uint8_t sender_key[]  = {0xD5, 0xCB, 0x37, 0x10, 0x37, 0x15, 0x34, 0xA1, 0xCA, 0x22, 0x4E, 0x19, 0xEB, 0x96, 0xE9, 0x6D};
uint8_t sender_iv[]   = {0x20, 0x75, 0x0B, 0x95, 0xF9, 0x78, 0xC8};

uint8_t receiver_id[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
//uint8_t receiver_key[] = {0x21, 0x64, 0x42, 0xda, 0x60, 0x3c, 0x51, 0x59, 0x2d, 0xf4, 0xc3, 0xd0, 0xcd, 0x1d, 0x0d, 0x48 };
//uint8_t receiver_iv[] = {0x01, 0x53, 0xdd, 0xfe, 0xde, 0x44, 0x19 };

uint8_t master_secret[35] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23}; 

/*Sender Context: {
  Sender ID: 73 65 72 76 65 72 
  Sender Key: d5 cb 37 10 37 15 34 a1 ca 22 4e 19 eb 96 e9 6d 
  Sender IV: 20 75 0b 95 f9 78 c8 
}
Recipient Context: {
  Recipient ID: 63 6c 69 65 6e 74 
  Recipient Key: 21 64 42 da 60 3c 51 59 2d f4 c3 d0 cd 1d 0d 48 
  Recipient IV: 01 53 dd fe de 44 19 
} */


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
//  rest_activate_resource(&res_temperature, "coap/temp");
 // rest_activate_resource(&res_oscoap_temperature, "oscoap/temp");
  rest_activate_resource(&res_coap_light, "coap/light");
  rest_activate_resource(&res_oscoap_light, "oscoap/light");
  rest_activate_resource(&res_hello, "hello/coap");

/*  rest_activate_resource(&res_mirror, "debug/mirror"); */
/*  rest_activate_resource(&res_chunks, "test/chunks"); */
/*  rest_activate_resource(&res_separate, "test/separate"); */
 // rest_activate_resource(&res_push, "test/push");
/*  rest_activate_resource(&res_event, "sensors/button"); */
/*  rest_activate_resource(&res_sub, "test/sub"); */
/*  rest_activate_resource(&res_b1_sep_b2, "test/b1sepb2"); */
#if PLATFORM_HAS_LEDS
/*  rest_activate_resource(&res_leds, "actuators/leds"); */
 // rest_activate_resource(&res_toggle, "actuators/toggle");
#endif
#if PLATFORM_HAS_LIGHT
 // rest_activate_resource(&res_light, "sensors/light"); 
 // SENSORS_ACTIVATE(light_sensor);  
#endif
#if PLATFORM_HAS_BATTERY
 // rest_activate_resource(&res_battery, "sensors/battery");  
 // SENSORS_ACTIVATE(battery_sensor);  
#endif
#if PLATFORM_HAS_TEMPERATURE
  //rest_activate_resource(&res_temperature, "sensors/temperature");  
 // SENSORS_ACTIVATE(temperature_sensor);  
#endif


oscoap_ctx_store_init();

//Interop


//if(oscoap_derrive_ctx(master_secret, 35, NULL, 0, 12, 1,sender_id, 6, receiver_id, 6, 32) == 0) {
//  printf("Error: Could not derive new Context!\n");
//}

if(oscoap_new_ctx( sender_key, sender_iv, receiver_key, receiver_iv, sender_id, 6, receiver_id, 6, 32) == 0){
  printf("Error: Could not create new Context!\n");
}


OscoapCommonContext* c = NULL;
uint8_t rid2[] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
c = oscoap_find_ctx_by_rid(rid2, 6);
PRINTF("COAP max size %d\n", COAP_MAX_PACKET_SIZE);
if(c == NULL){
    PRINTF("could not fetch cid\n");
} else {
  	PRINTF("Context sucessfully added to DB!\n");
  //  oscoap_print_context(c);
}



/* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
#if PLATFORM_HAS_BUTTON
    if(ev == sensors_event && data == &button_sensor) {
      PRINTF("*******BUTTON*******\n");

      /* Call the event_handler for this application-specific event. */
    //  res_event.trigger();

      /* Also call the separate response example handler. */
   //   res_separate.resume();
    }
#endif /* PLATFORM_HAS_BUTTON */
  }                             /* while (1) */

  PROCESS_END();
}
