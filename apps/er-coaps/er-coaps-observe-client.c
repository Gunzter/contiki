/*
 * Copyright (c) 2014, Daniele Alessandrelli.
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
 *
 */

/*
 * \file
 *        Extension to Erbium for enabling CoAP observe clients
 * \author
 *        Daniele Alessandrelli <daniele.alessandrelli@gmail.com>
 */

#include <stdio.h>
#include <string.h>

#include "er-coaps.h"
#include "er-coaps-observe-client.h"

/* Compile this code only if client-side support for CoAP Observe is required */
#if COAP_OBSERVE_CLIENT

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
                                "%02x%02x:%02x%02x:%02x%02x:%02x%02x]", \
                                ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], \
                                ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], \
                                ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], \
                                ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], \
                                ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], \
                                ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], \
                                ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], \
                                ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", \
                                   (lladdr)->addr[0], (lladdr)->addr[1], \
                                   (lladdr)->addr[2], (lladdr)->addr[3], \
                                   (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

MEMB(obs_subjects_memb, coaps_observee_t, COAP_MAX_OBSERVEES);
LIST(obs_subjects_list);

/*----------------------------------------------------------------------------*/
static size_t
get_token(void *packet, const uint8_t **token)
{
  coaps_packet_t *const coaps_pkt = (coaps_packet_t *)packet;

  *token = coaps_pkt->token;

  return coaps_pkt->token_len;
}
/*----------------------------------------------------------------------------*/
static int
set_token(void *packet, const uint8_t *token, size_t token_len)
{
  coaps_packet_t *const coaps_pkt = (coaps_packet_t *)packet;

  coaps_pkt->token_len = MIN(COAP_TOKEN_LEN, token_len);
  memcpy(coaps_pkt->token, token, coaps_pkt->token_len);

  return coaps_pkt->token_len;
}
/*----------------------------------------------------------------------------*/
coaps_observee_t *
coaps_obs_add_observee(uip_ipaddr_t *addr, uint16_t port,
                      const uint8_t *token, size_t token_len, const char *url,
                      notification_callback_t notification_callback,
                      void *data)
{
  coaps_observee_t *o;

  /* Remove existing observe relationship, if any. */
  coaps_obs_remove_observee_by_url(addr, port, url);
  o = memb_alloc(&obs_subjects_memb);
  if(o) {
    o->url = url;
    uip_ipaddr_copy(&o->addr, addr);
    o->port = port;
    o->token_len = token_len;
    memcpy(o->token, token, token_len);
    /* o->last_mid = 0; */
    o->notification_callback = notification_callback;
    o->data = data;
    /* stimer_set(&o->refresh_timer, COAP_OBSERVING_REFRESH_INTERVAL); */
    PRINTF("Adding obs_subject for /%s [0x%02X%02X]\n", o->url, o->token[0],
           o->token[1]);
    list_add(obs_subjects_list, o);
  }

  return o;
}
/*----------------------------------------------------------------------------*/
void
coaps_obs_remove_observee(coaps_observee_t *o)
{
  PRINTF("Removing obs_subject for /%s [0x%02X%02X]\n", o->url, o->token[0],
         o->token[1]);
  memb_free(&obs_subjects_memb, o);
  list_remove(obs_subjects_list, o);
}
/*----------------------------------------------------------------------------*/
coaps_observee_t *
coaps_get_obs_subject_by_token(const uint8_t *token, size_t token_len)
{
  coaps_observee_t *obs = NULL;

  for(obs = (coaps_observee_t *)list_head(obs_subjects_list); obs;
      obs = obs->next) {
    PRINTF("Looking for token 0x%02X%02X\n", token[0], token[1]);
    if(obs->token_len == token_len
       && memcmp(obs->token, token, token_len) == 0) {
      return obs;
    }
  }

  return NULL;
}
/*----------------------------------------------------------------------------*/
int
coaps_obs_remove_observee_by_token(uip_ipaddr_t *addr, uint16_t port,
                                  uint8_t *token, size_t token_len)
{
  int removed = 0;
  coaps_observee_t *obs = NULL;

  for(obs = (coaps_observee_t *)list_head(obs_subjects_list); obs;
      obs = obs->next) {
    PRINTF("Remove check Token 0x%02X%02X\n", token[0], token[1]);
    if(uip_ipaddr_cmp(&obs->addr, addr)
       && obs->port == port
       && obs->token_len == token_len
       && memcmp(obs->token, token, token_len) == 0) {
      coaps_obs_remove_observee(obs);
      removed++;
    }
  }
  return removed;
}
/*----------------------------------------------------------------------------*/
int
coaps_obs_remove_observee_by_url(uip_ipaddr_t *addr, uint16_t port,
                                const char *url)
{
  int removed = 0;
  coaps_observee_t *obs = NULL;

  for(obs = (coaps_observee_t *)list_head(obs_subjects_list); obs;
      obs = obs->next) {
    PRINTF("Remove check URL %s\n", url);
    if(uip_ipaddr_cmp(&obs->addr, addr)
       && obs->port == port
       && (obs->url == url || memcmp(obs->url, url, strlen(obs->url)) == 0)) {
      coaps_obs_remove_observee(obs);
      removed++;
    }
  }
  return removed;
}
/*----------------------------------------------------------------------------*/
static void
simple_reply(coaps_message_type_t type, context_t *ctx, uip_ip6addr_t *addr, uint16_t port,
             coaps_packet_t *notification)
{
  static coaps_packet_t response[1];
  size_t len;

  coaps_init_message(response, type, NO_ERROR, notification->mid);
  len = coaps_serialize_message(response, uip_appdata);
  coaps_send_message(ctx, addr, port, uip_appdata, len);
}
/*----------------------------------------------------------------------------*/
static coaps_notification_flag_t
classify_notification(void *response, int first)
{
  coaps_packet_t *pkt;

  pkt = (coaps_packet_t *)response;
  if(!pkt) {
    PRINTF("no response\n");
    return NO_REPLY_FROM_SERVER;
  }
  PRINTF("server replied\n");
  if(!IS_RESPONSE_CODE_2_XX(pkt)) {
    PRINTF("error response code\n");
    return ERROR_RESPONSE_CODE;
  }
  if(!IS_OPTION(pkt, COAP_OPTION_OBSERVE)) {
    PRINTF("server does not support observe\n");
    return OBSERVE_NOT_SUPPORTED;
  }
  if(first) {
    return OBSERVE_OK;
  }
  return NOTIFICATION_OK;
}
/*----------------------------------------------------------------------------*/
void
coaps_handle_notification(context_t *ctx, uip_ipaddr_t *addr, uint16_t port,
                         coaps_packet_t *notification)
{
  coaps_packet_t *pkt;
  const uint8_t *token;
  int token_len;
  coaps_observee_t *obs;
  coaps_notification_flag_t flag;
  uint32_t observe;

  PRINTF("coaps_handle_notification()\n");
  pkt = (coaps_packet_t *)notification;
  token_len = get_token(pkt, &token);
  PRINTF("Getting token\n");
  if(0 == token_len) {
    PRINTF("Error while handling coaps observe notification: "
           "no token in message\n");
    return;
  }
  PRINTF("Getting observee info\n");
  obs = coaps_get_obs_subject_by_token(token, token_len);
  if(NULL == obs) {
    PRINTF("Error while handling coaps observe notification: "
           "no matching token found\n");
    simple_reply(COAP_TYPE_RST, ctx, addr, port, notification);
    return;
  }
  if(notification->type == COAP_TYPE_CON) {
    simple_reply(COAP_TYPE_ACK, ctx, addr, port, notification);
  }
  if(obs->notification_callback != NULL) {
    flag = classify_notification(notification, 0);
    /* TODO: the following mechanism for discarding duplicates is too trivial */
    /* refer to Observe RFC for a better solution */
    if(flag == NOTIFICATION_OK) {
      coaps_get_header_observe(notification, &observe);
      if(observe == obs->last_observe) {
        PRINTF("Discarding duplicate\n");
        return;
      }
      obs->last_observe = observe;
    }
    obs->notification_callback(obs, notification, flag);
  }
}
/*----------------------------------------------------------------------------*/
static void
handle_obs_registration_response(void *data, void *response)
{
  coaps_observee_t *obs;
  notification_callback_t notification_callback;
  coaps_notification_flag_t flag;

  PRINTF("handle_obs_registration_response(): ");
  obs = (coaps_observee_t *)data;
  notification_callback = obs->notification_callback;
  flag = classify_notification(response, 1);
  if(notification_callback) {
    notification_callback(obs, response, flag);
  }
  if(flag != OBSERVE_OK) {
    coaps_obs_remove_observee(obs);
  }
}
/*----------------------------------------------------------------------------*/
uint8_t
coaps_generate_token(uint8_t **token_ptr)
{
  static uint8_t token = 0;

  token++;
  /* FIXME: we should check that this token is not already used */
  *token_ptr = (uint8_t *)&token;
  return sizeof(token);
}
/*----------------------------------------------------------------------------*/
coaps_observee_t *
coaps_obs_request_registration(uip_ipaddr_t *addr, uint16_t port, char *uri,
                              notification_callback_t notification_callback,
                              void *data)
{
  coaps_packet_t request[1];
  coaps_transaction_t *t;
  uint8_t *token;
  uint8_t token_len;
  coaps_observee_t *obs;

  obs = NULL;
  coaps_init_message(request, COAP_TYPE_CON, COAP_GET, coaps_get_mid());
  coaps_set_header_uri_path(request, uri);
  coaps_set_header_observe(request, 0);
  token_len = coaps_generate_token(&token);
  set_token(request, token, token_len);
  t = coaps_new_transaction(request->mid, addr, port);
  if(t) {
    obs = coaps_obs_add_observee(addr, port, (uint8_t *)token, token_len, uri,
                                notification_callback, data);
    if(obs) {
      t->callback = handle_obs_registration_response;
      t->callback_data = obs;
      t->packet_len = coaps_serialize_message(request, t->packet);
      coaps_send_transaction(t);
    } else {
      PRINTF("Could not allocate obs_subject resource buffer");
      coaps_clear_transaction(t);
    }
  } else {
    PRINTF("Could not allocate transaction buffer");
  }
  return obs;
}
#endif /* COAP_OBSERVE_CLIENT */
