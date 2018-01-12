/* pdu.c -- CoAP message structure
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "coap_config.h"
//#include "internals.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "debug.h"
#include "pdu.h"
#include "option.h"
#include "encode.h"
#include "mem.h"

#ifdef WITH_LWIP
#include "lwip/def.h"
#endif

const char *coap_error_message = "";

void
coap_pdu_clear(coap_pdu_t *pdu, size_t size) {
  assert(pdu);

#ifdef WITH_LWIP
  /* the pdu itself is not wiped as opposed to the other implementations,
   * because we have to rely on the pbuf to be set there. */
  pdu->hdr = pdu->pbuf->payload;
#else
  pdu->max_delta = 0;
  pdu->data = NULL;
#endif
  memset(pdu->hdr, 0, size);
  pdu->max_size = size;
  pdu->hdr->version = COAP_DEFAULT_VERSION;

  /* data is NULL unless explicitly set by coap_add_data() */
  pdu->length = sizeof(coap_hdr_t);

  pdu->uri_path      = NULL;
  pdu->uri_query     = NULL;
  pdu->location_path = NULL;
}

#ifdef WITH_LWIP
coap_pdu_t *
coap_pdu_from_pbuf(struct pbuf *pbuf)
{
  if (pbuf == NULL) return NULL;

  LWIP_ASSERT("Can only deal with contiguous PBUFs", pbuf->tot_len == pbuf->len);
  LWIP_ASSERT("coap_read needs to receive an exclusive copy of the incoming pbuf", pbuf->ref == 1);

  coap_pdu_t *result = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!result) {
	  pbuf_free(pbuf);
	  return NULL;
  }

  memset(result, 0, sizeof(coap_pdu_t));

  result->max_size = pbuf->tot_len;
  result->length = pbuf->tot_len;
  result->hdr = pbuf->payload;
  result->pbuf = pbuf;

  return result;
}
#endif

coap_pdu_t *
coap_pdu_init(unsigned char type, unsigned char code, 
	      unsigned short id, size_t size) {
  coap_pdu_t *pdu;
#ifdef WITH_LWIP
    struct pbuf *p;
#endif

  assert(size <= COAP_MAX_PDU_SIZE);
  /* Size must be large enough to fit the header. */
  if (size < sizeof(coap_hdr_t) || size > COAP_MAX_PDU_SIZE)
    return NULL;

  /* size must be large enough for hdr */
#if defined(WITH_POSIX) || defined(WITH_CONTIKI)
  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) return NULL;
  pdu->hdr = coap_malloc_type(COAP_PDU_BUF, size);
  if (pdu->hdr == NULL) {
    coap_free_type(COAP_PDU, pdu);
    pdu = NULL;
  }
#endif /* WITH_POSIX or WITH_CONTIKI */
#ifdef WITH_LWIP
  pdu = (coap_pdu_t*)coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) return NULL;
  p = pbuf_alloc(PBUF_TRANSPORT, size, PBUF_RAM);
  if (p == NULL) {
    coap_free_type(COAP_PDU, pdu);
    pdu = NULL;
  }
#endif
  if (pdu) {
#ifdef WITH_LWIP
    pdu->pbuf = p;
#endif
    coap_pdu_clear(pdu, size);
    pdu->hdr->id = lwip_htons(id);//modified by zjk;
    pdu->hdr->type = type;
    pdu->hdr->code = code;
  } 
  return pdu;
}

coap_pdu_t *
coap_new_pdu(void) {
  coap_pdu_t *pdu;
  
#ifndef WITH_CONTIKI
  pdu = coap_pdu_init(0, 0, ntohs((unsigned short)COAP_INVALID_TID), COAP_MAX_PDU_SIZE);
#else /* WITH_CONTIKI */
  pdu = coap_pdu_init(0, 0, uip_ntohs(COAP_INVALID_TID), COAP_MAX_PDU_SIZE);
#endif /* WITH_CONTIKI */

#ifndef NDEBUG
  if (!pdu)
    coap_log(LOG_CRIT, "coap_new_pdu: cannot allocate memory for new PDU\n");
#endif
  return pdu;
}

void
coap_delete_pdu(coap_pdu_t *pdu) {
#if defined(WITH_POSIX) || defined(WITH_CONTIKI)
  if (pdu != NULL) {
    if (pdu->hdr != NULL) {
      coap_free_type(COAP_PDU_BUF, pdu->hdr);
    }
    coap_free_type(COAP_PDU, pdu);
  }
#endif
#ifdef WITH_LWIP
  if (pdu != NULL) /* accepting double free as the other implementation accept that too */
    pbuf_free(pdu->pbuf);
  coap_free_type(COAP_PDU, pdu);
#endif
}

int
coap_add_token(coap_pdu_t *pdu, size_t len, const unsigned char *data) {
  const size_t HEADERLENGTH = len + 4;
  /* must allow for pdu == NULL as callers may rely on this */
  if (!pdu || len > 8 || pdu->max_size < HEADERLENGTH)
    return 0;

  pdu->hdr->token_length = len;
  if (len)
    memcpy(pdu->hdr->token, data, len);
  pdu->max_delta = 0;
  pdu->length = HEADERLENGTH;
  pdu->data = NULL;

  return 1;
}


int
coap_set_header_uri_query(void *packet, const char *query)
{
    int length = 0;
    coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

    free_multi_option(coap_pkt->uri_query);
    coap_pkt->uri_query = NULL;

    if (query[0]=='?') ++query;

    do
    {
        int i = 0;

        while (query[i] != 0 && query[i] != '&') i++;
        coap_add_multi_option(&(coap_pkt->uri_query), (uint8_t *)query, i, 0);
		coap_add_option(coap_pkt, COAP_OPTION_URI_QUERY, i, (unsigned char *)query);

        if (query[i] == '&') i++;
        query += i;
        length += i;
    } while (query[0] != 0);

    //SET_OPTION(coap_pkt, COAP_OPTION_URI_QUERY);
    return length;
 }


/** @FIXME de-duplicate code with coap_add_option_later */
size_t
coap_add_option(coap_pdu_t *pdu, unsigned short type, unsigned int len, const unsigned char *data) {
  size_t optsize;
  coap_opt_t *opt;
  
  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    warn("coap_add_option: options are not in correct order\n");
    return 0;
  }

  opt = (unsigned char *)pdu->hdr + pdu->length;

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->max_size - pdu->length, 
			    type - pdu->max_delta, data, len);

  if (!optsize) {
    warn("coap_add_option: cannot add option\n");
    /* error */
    return 0;
  } else {
    pdu->max_delta = type;
    pdu->length += optsize;
  }

  return optsize;
}

/** @FIXME de-duplicate code with coap_add_option */
unsigned char*
coap_add_option_later(coap_pdu_t *pdu, unsigned short type, unsigned int len) {
  size_t optsize;
  coap_opt_t *opt;

  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    warn("coap_add_option: options are not in correct order\n");
    return NULL;
  }

  opt = (unsigned char *)pdu->hdr + pdu->length;

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->max_size - pdu->length,
			    type - pdu->max_delta, NULL, len);

  if (!optsize) {
    warn("coap_add_option: cannot add option\n");
    /* error */
    return NULL;
  } else {
    pdu->max_delta = type;
    pdu->length += optsize;
  }

  return ((unsigned char*)opt) + optsize - len;
}

int
coap_add_data(coap_pdu_t *pdu, unsigned int len, const unsigned char *data) {
  assert(pdu);
  assert(pdu->data == NULL);

  if (len == 0)
    return 1;

  if (pdu->length + len + 1 > pdu->max_size) {
    warn("coap_add_data: cannot add: data too large for PDU\n");
    assert(pdu->data == NULL);
    return 0;
  }

  pdu->data = (unsigned char *)pdu->hdr + pdu->length;
  *pdu->data = COAP_PAYLOAD_START;
  pdu->data++;

  memcpy(pdu->data, data, len);
  pdu->length += len + 1;
  return 1;
}

int
coap_get_data(coap_pdu_t *pdu, size_t *len, unsigned char **data) {
  assert(pdu);
  assert(len);
  assert(data);

  if (pdu->data) {
    *len = (unsigned char *)pdu->hdr + pdu->length - pdu->data;
    *data = pdu->data;
  } else {			/* no data, clear everything */
    *len = 0;
    *data = NULL;
  }

  return *data != NULL;
}

#ifndef SHORT_ERROR_RESPONSE
typedef struct {
  unsigned char code;
  char *phrase;
} error_desc_t;

/* if you change anything here, make sure, that the longest string does not 
 * exceed COAP_ERROR_PHRASE_LENGTH. */
error_desc_t coap_error[] = {
  { COAP_RESPONSE_CODE(201), "Created" },
  { COAP_RESPONSE_CODE(202), "Deleted" },
  { COAP_RESPONSE_CODE(203), "Valid" },
  { COAP_RESPONSE_CODE(204), "Changed" },
  { COAP_RESPONSE_CODE(205), "Content" },
  { COAP_RESPONSE_CODE(231), "Continue" },
  { COAP_RESPONSE_CODE(400), "Bad Request" },
  { COAP_RESPONSE_CODE(401), "Unauthorized" },
  { COAP_RESPONSE_CODE(402), "Bad Option" },
  { COAP_RESPONSE_CODE(403), "Forbidden" },
  { COAP_RESPONSE_CODE(404), "Not Found" },
  { COAP_RESPONSE_CODE(405), "Method Not Allowed" },
  { COAP_RESPONSE_CODE(406), "Not Acceptable" },
  { COAP_RESPONSE_CODE(408), "Request Entity Incomplete" },
  { COAP_RESPONSE_CODE(412), "Precondition Failed" },
  { COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
  { COAP_RESPONSE_CODE(415), "Unsupported Content-Format" },
  { COAP_RESPONSE_CODE(500), "Internal Server Error" },
  { COAP_RESPONSE_CODE(501), "Not Implemented" },
  { COAP_RESPONSE_CODE(502), "Bad Gateway" },
  { COAP_RESPONSE_CODE(503), "Service Unavailable" },
  { COAP_RESPONSE_CODE(504), "Gateway Timeout" },
  { COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
  { 0, NULL }			/* end marker */
};

char *
coap_response_phrase(unsigned char code) {
  int i;
  for (i = 0; coap_error[i].code; ++i) {
    if (coap_error[i].code == code)
      return coap_error[i].phrase;
  }
  return NULL;
}
#endif

static
uint32_t
coap_parse_int_option(uint8_t *bytes, size_t length)
{
  uint32_t var = 0;
  size_t i = 0;
  while (i<length)
  {
    var <<= 8;
    var |= bytes[i++];
  }
  return var;
}

/**
 * Advances *optp to next option if still in PDU. This function 
 * returns the number of bytes opt has been advanced or @c 0
 * on error.
 */
static size_t
next_option_safe(coap_opt_t **optp, size_t *length, coap_pdu_t *pdu) {
  coap_option_t option;
  size_t optsize;

  assert(optp); assert(*optp); 
  assert(length);

  optsize = coap_opt_parse(*optp, *length, &option);
  if(option.delta == COAP_OPTION_URI_PATH) {
  	coap_add_multi_option( &(pdu->uri_path), *optp, option.length, 1);
  }
	
  if(option.delta == COAP_OPTION_CONTENT_FORMAT) {
		pdu->content_type = (coap_content_type_t)coap_parse_int_option(*optp, option.length);
	}
	
  if(option.delta == COAP_OPTION_ACCEPT) {
  	if (pdu->accept_num < COAP_MAX_ACCEPT_NUM)
    {
      pdu->accept[pdu->accept_num] = coap_parse_int_option(*optp, option.length);
      pdu->accept_num += 1;
    }
  }

  if (optsize) {
    assert(optsize <= *length);

    *optp += optsize;
    *length -= optsize;
  }

  return optsize;
}

coap_status_t
coap_parse_message(void *packet, uint8_t *data, uint16_t data_len)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;
  uint8_t *current_option;
  unsigned int option_number = 0;
  unsigned int option_delta = 0;
  size_t option_length = 0;
  unsigned int *x;

  /* Initialize packet */
  //memset(coap_pkt, 0, sizeof(coap_pdu_t));

  /* pointer to packet bytes */
  coap_pkt->pbuf->payload = (void *)data;
	char * payload = (char *)data;

  /* parse header fields */
  coap_pkt->hdr->version = (COAP_HEADER_VERSION_MASK & payload[0])>>COAP_HEADER_VERSION_POSITION;
  coap_pkt->hdr->type = (COAP_HEADER_TYPE_MASK & payload[0])>>COAP_HEADER_TYPE_POSITION;
  coap_pkt->hdr->token_length = MIN(COAP_TOKEN_LEN, (COAP_HEADER_TOKEN_LEN_MASK & payload[0])>>COAP_HEADER_TOKEN_LEN_POSITION);
  coap_pkt->hdr->code = payload[1];
  coap_pkt->hdr->id = payload[2]<<8 | payload[3];

  if (coap_pkt->hdr->version != 1)
  {
    coap_error_message = "CoAP version must be 1";
    return BAD_REQUEST_4_00;
  }

  current_option = data + COAP_HEADER_LEN;

  if (coap_pkt->hdr->token_length!= 0)
  {
      memcpy(coap_pkt->hdr->token, current_option, coap_pkt->hdr->token_length);
      //SET_OPTION(coap_pkt, COAP_OPTION_TOKEN);

      printf("Token (len %u) [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n", coap_pkt->hdr->token_length,
        coap_pkt->hdr->token[0],
        coap_pkt->hdr->token[1],
        coap_pkt->hdr->token[2],
        coap_pkt->hdr->token[3],
        coap_pkt->hdr->token[4],
        coap_pkt->hdr->token[5],
        coap_pkt->hdr->token[6],
        coap_pkt->hdr->token[7]
      ); /*FIXME always prints 8 bytes */
  }

  /* parse options */
  current_option += coap_pkt->hdr->token_length;

  while (current_option < data+data_len)
  {
    /* Payload marker 0xFF, currently only checking for 0xF* because rest is reserved */
    if ((current_option[0] & 0xF0)==0xF0)
    {
      coap_pkt->data = ++current_option;
      coap_pkt->payload_len = data_len - (coap_pkt->data - data);

      break;
    }

    option_delta = current_option[0]>>4;
    option_length = current_option[0] & 0x0F;
    ++current_option;

    /* avoids code duplication without function overhead */
    x = &option_delta;
    do
    {
      if (*x==13)
      {
        *x += current_option[0];
        ++current_option;
      }
      else if (*x==14)
      {
        *x += 255;
        *x += current_option[0]<<8;
        ++current_option;
        *x += current_option[0];
        ++current_option;
      }
    }
    while (x!=(unsigned int *)&option_length && (x=(unsigned int *)&option_length)!=NULL);

    option_number += option_delta;

    if (current_option + option_length > data + data_len)
    {
        printf("OPTION %u (delta %u, len %u) has invalid length.\n", option_number, option_delta, option_length);
        return BAD_REQUEST_4_00;
    }
    else
    {
        printf("OPTION %u (delta %u, len %u): ", option_number, option_delta, option_length);
    }

    //SET_OPTION(coap_pkt, option_number);

    switch (option_number)
    {
      case COAP_OPTION_CONTENT_TYPE:
        coap_pkt->content_type = (coap_content_type_t)coap_parse_int_option(current_option, option_length);
        printf("Content-Format [%u]\n", coap_pkt->content_type);
        break;
      case COAP_OPTION_MAXAGE:
        coap_pkt->max_age = coap_parse_int_option(current_option, option_length);
        printf("Max-Age [%lu]\n", coap_pkt->max_age);
        break;
      case COAP_OPTION_ETAG:
        coap_pkt->etag_len = (uint8_t)(MIN(COAP_ETAG_LEN, option_length));
        memcpy(coap_pkt->etag, current_option, coap_pkt->etag_len);
        printf("ETag %u [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n", coap_pkt->etag_len,
          coap_pkt->etag[0],
          coap_pkt->etag[1],
          coap_pkt->etag[2],
          coap_pkt->etag[3],
          coap_pkt->etag[4],
          coap_pkt->etag[5],
          coap_pkt->etag[6],
          coap_pkt->etag[7]
        ); /*FIXME always prints 8 bytes */
        break;
      case COAP_OPTION_ACCEPT:
        if (coap_pkt->accept_num < COAP_MAX_ACCEPT_NUM)
        {
          coap_pkt->accept[coap_pkt->accept_num] = coap_parse_int_option(current_option, option_length);
          coap_pkt->accept_num += 1;
          printf("Accept [%u]\n", coap_pkt->content_type);
        }
        break;
      case COAP_OPTION_IF_MATCH:
        /*FIXME support multiple ETags */
        coap_pkt->if_match_len = (uint8_t)(MIN(COAP_ETAG_LEN, option_length));
        memcpy(coap_pkt->if_match, current_option, coap_pkt->if_match_len);
        printf("If-Match %u [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n", coap_pkt->if_match_len,
          coap_pkt->if_match[0],
          coap_pkt->if_match[1],
          coap_pkt->if_match[2],
          coap_pkt->if_match[3],
          coap_pkt->if_match[4],
          coap_pkt->if_match[5],
          coap_pkt->if_match[6],
          coap_pkt->if_match[7]
        ); /*FIXME always prints 8 bytes */
        break;
      case COAP_OPTION_IF_NONE_MATCH:
        coap_pkt->if_none_match = 1;
        printf("If-None-Match\n");
        break;

      case COAP_OPTION_URI_HOST:
        coap_pkt->uri_host = current_option;
        coap_pkt->uri_host_len = option_length;
        printf("Uri-Host [%.*s]\n", coap_pkt->uri_host_len, coap_pkt->uri_host);
        break;
      case COAP_OPTION_URI_PORT:
        coap_pkt->uri_port = coap_parse_int_option(current_option, option_length);
        printf("Uri-Port [%u]\n", coap_pkt->uri_port);
        break;
      case COAP_OPTION_URI_PATH:
        /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
        // coap_merge_multi_option( (char **) &(coap_pkt->uri_path), &(coap_pkt->uri_path_len), current_option, option_length, 0);
        coap_add_multi_option( &(coap_pkt->uri_path), current_option, option_length, 1);
        printf("Uri-Path [%.*s]\n", option_length, current_option);
        break;
      case COAP_OPTION_URI_QUERY:
        /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
        // coap_merge_multi_option( (char **) &(coap_pkt->uri_query), &(coap_pkt->uri_query_len), current_option, option_length, '&');
        coap_add_multi_option( &(coap_pkt->uri_query), current_option, option_length, 1);
        printf("Uri-Query [%.*s]\n", option_length, current_option);
        break;

      case COAP_OPTION_LOCATION_PATH:
        coap_add_multi_option( &(coap_pkt->location_path), current_option, option_length, 1);
        break;
      case COAP_OPTION_LOCATION_QUERY:
        /* coap_merge_multi_option() operates in-place on the IPBUF, but final packet field should be const string -> cast to string */
        //coap_merge_multi_option( &(coap_pkt->location_query), &(coap_pkt->location_query_len), current_option, option_length, '&');
        printf("Location-Query [%.*s]\n", option_length, current_option);
        break;

      case COAP_OPTION_PROXY_URI:
        /*FIXME check for own end-point */
        //coap_pkt->proxy_uri = current_option;
        //coap_pkt->proxy_uri_len = option_length;
        /*TODO length > 270 not implemented (actually not required) */
        //PRINTF("Proxy-Uri NOT IMPLEMENTED [%.*s]\n", coap_pkt->proxy_uri_len, coap_pkt->proxy_uri);
        coap_error_message = "This is a constrained server (Contiki)";
        return PROXYING_NOT_SUPPORTED_5_05;
//        break;

      case COAP_OPTION_OBSERVE:
        coap_pkt->observe = coap_parse_int_option(current_option, option_length);
        printf("Observe [%lu]\n", coap_pkt->observe);
        break;
      case COAP_OPTION_BLOCK2:
        coap_pkt->block2_num = coap_parse_int_option(current_option, option_length);
        coap_pkt->block2_more = (coap_pkt->block2_num & 0x08)>>3;
        coap_pkt->block2_size = 16 << (coap_pkt->block2_num & 0x07);
        coap_pkt->block2_offset = (coap_pkt->block2_num & ~0x0000000F)<<(coap_pkt->block2_num & 0x07);
        coap_pkt->block2_num >>= 4;
        printf("Block2 [%lu%s (%u B/blk)]\n", coap_pkt->block2_num, coap_pkt->block2_more ? "+" : "", coap_pkt->block2_size);
        break;
      case COAP_OPTION_BLOCK1:
        coap_pkt->block1_num = coap_parse_int_option(current_option, option_length);
        coap_pkt->block1_more = (coap_pkt->block1_num & 0x08)>>3;
        coap_pkt->block1_size = 16 << (coap_pkt->block1_num & 0x07);
        coap_pkt->block1_offset = (coap_pkt->block1_num & ~0x0000000F)<<(coap_pkt->block1_num & 0x07);
        coap_pkt->block1_num >>= 4;
        printf("Block1 [%lu%s (%u B/blk)]\n", coap_pkt->block1_num, coap_pkt->block1_more ? "+" : "", coap_pkt->block1_size);
        break;
      case COAP_OPTION_SIZE:
        coap_pkt->size = coap_parse_int_option(current_option, option_length);
        printf("Size [%lu]\n", coap_pkt->size);
        break;
      default:
        printf("unknown (%u)\n", option_number);
        /* Check if critical (odd) */
        if (option_number & 1)
        {
          coap_error_message = "Unsupported critical option";
          return BAD_OPTION_4_02;
        }
    }

    current_option += option_length;
  } /* for */
  printf("-Done parsing-------\n");



  return NO_ERROR;
}


int
coap_pdu_parse(unsigned char *data, size_t length, coap_pdu_t *pdu) {
  coap_opt_t *opt;

  assert(data);
  assert(pdu);

  if (pdu->max_size < length) {
    debug("insufficient space to store parsed PDU\n");
    return 0;
  }

  if (length < sizeof(coap_hdr_t)) {
    debug("discarded invalid PDU\n");
  }

#ifdef WITH_LWIP
  /* this verifies that with the classical copy-at-parse-time and lwip's
   * zerocopy-into-place approaches, both share the same idea of destination
   * addresses */
  LWIP_ASSERT("coap_pdu_parse with unexpected addresses", data == (void*)pdu->hdr);
  LWIP_ASSERT("coap_pdu_parse with unexpected length", length == pdu->length);
#else

  pdu->hdr->version = data[0] >> 6;
  pdu->hdr->type = (data[0] >> 4) & 0x03;
  pdu->hdr->token_length = data[0] & 0x0f;
  pdu->hdr->code = data[1];
#endif
  pdu->data = NULL;

  /* sanity checks */
  if (pdu->hdr->code == 0) {
    if (length != sizeof(coap_hdr_t) || pdu->hdr->token_length) {
      debug("coap_pdu_parse: empty message is not empty\n");
      goto discard;
    }
  }

  if (length < sizeof(coap_hdr_t) + pdu->hdr->token_length
      || pdu->hdr->token_length > 8) {
    debug("coap_pdu_parse: invalid Token\n");
    goto discard;
  }

#ifndef WITH_LWIP
  /* Copy message id in network byte order, so we can easily write the
   * response back to the network. */
  memcpy(&pdu->hdr->id, data + 2, 2);

  /* Append data (including the Token) to pdu structure, if any. */
  if (length > sizeof(coap_hdr_t)) {
    memcpy(pdu->hdr + 1, data + sizeof(coap_hdr_t), length - sizeof(coap_hdr_t));
  }
  pdu->length = length;
 
  /* Finally calculate beginning of data block and thereby check integrity
   * of the PDU structure. */
#endif

  /* skip header + token */
  length -= (pdu->hdr->token_length + sizeof(coap_hdr_t));
  opt = (unsigned char *)(pdu->hdr + 1) + pdu->hdr->token_length;

  while (length && *opt != COAP_PAYLOAD_START) {
    if (!next_option_safe(&opt, (size_t *)&length,pdu)) {
      debug("coap_pdu_parse: drop\n");
      goto discard;
    }
  }

  /* end of packet or start marker */
  if (length) {
    assert(*opt == COAP_PAYLOAD_START);
    opt++; length--;

    if (!length) {
      debug("coap_pdu_parse: message ending in payload start marker\n");
      goto discard;
    }

    debug("set data to %p (pdu ends at %p)\n", (unsigned char *)opt, 
	  (unsigned char *)pdu->hdr + pdu->length);
    pdu->data = (unsigned char *)opt;
  }

  return 1;

 discard:
  return 0;
}

void
coap_add_multi_option(multi_option_t **dst, uint8_t *option, size_t option_len, uint8_t is_static)
{
  multi_option_t *opt = (multi_option_t *)coap_malloc(sizeof(multi_option_t));

  if (opt)
  {
    opt->next = NULL;
    opt->len = (uint8_t)option_len;
    if (is_static)
    {
      opt->data = option;
      opt->is_static = 1;
    }
    else
    {
        opt->is_static = 0;
        opt->data = (uint8_t *)coap_malloc(option_len);
        if (opt->data == NULL)
        {
            coap_free(opt);
            return;
        }
        memcpy(opt->data, option, option_len);
    }

    if (*dst)
    {
      multi_option_t * i = *dst;
      while (i->next)
      {
        i = i->next;
      }
      i->next = opt;
    }
    else
    {
      *dst = opt;
    }
  }
}

int
coap_set_status_code(void *packet, unsigned int code)
{
  if (code <= 0xFF)
  {
    ((coap_pdu_t *)packet)->hdr->code = (uint8_t) code;
    return 1;
  }
  else
  {
    return 0;
  }
}

void
free_multi_option(multi_option_t *dst)
{
  if (dst)
  {
    multi_option_t *n = dst->next;
    dst->next = NULL;
    if (dst->is_static == 0)
    {
        coap_free(dst->data);
    }
    coap_free(dst);
    free_multi_option(n);
  }
}

void
coap_free_header(void *packet)
{
    coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

    free_multi_option(coap_pkt->uri_path);
    free_multi_option(coap_pkt->uri_query);
    //free_multi_option(coap_pkt->location_path);
    coap_pkt->uri_path = NULL;
    coap_pkt->uri_query = NULL;
    //coap_pkt->location_path = NULL;
}

int
coap_get_header_token(void *packet, const uint8_t **token)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  if (coap_pkt->hdr->token_length == 0) return 0;

  *token = coap_pkt->hdr->token;
  return coap_pkt->hdr->token_length;
}

int
coap_set_header_content_type(void *packet, unsigned int content_type)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  coap_pkt->content_type = (coap_content_type_t) content_type;
  //SET_OPTION(coap_pkt, COAP_OPTION_CONTENT_TYPE);
  const unsigned char data[1] = {(unsigned char)content_type};
  coap_add_option(coap_pkt, COAP_OPTION_CONTENT_TYPE, 1, data);
  return 1;
}

int
coap_set_header_location_path(void *packet, const char *path)
{
    coap_pdu_t *coap_pkt = (coap_pdu_t *) packet;
    int length = 0;

    free_multi_option(coap_pkt->location_path);
    coap_pkt->location_path = NULL;

    if (path[0]=='/') ++path;

    do
    {
        int i = 0;

        while (path[i] != 0 && path[i] != '/') i++;
        coap_add_multi_option(&(coap_pkt->location_path), (uint8_t *)path, i, 0);

        if (path[i] == '/') i++;
        path += i;
        length += i;
    } while (path[0] != 0);

    //SET_OPTION(coap_pkt, COAP_OPTION_LOCATION_PATH);
    coap_add_option(coap_pkt, COAP_OPTION_LOCATION_PATH, length, (unsigned char *)path);
    return length;
}

int
coap_set_header_uri_path(void *packet, const char *path)
{
  coap_pdu_t *coap_pkt = (coap_pdu_t *) packet;
  int length = 0;

  free_multi_option(coap_pkt->uri_path);
  coap_pkt->uri_path = NULL;

  if (path[0]=='/') ++path;

  do
  {
      int i = 0;

      while (path[i] != 0 && path[i] != '/') i++;
      coap_add_option(coap_pkt, COAP_OPTION_URI_PATH, i, (unsigned char *)path);
      if (path[i] == '/') i++;
      path += i;
      length += i;
  } while (path[0] != 0);

  
  return length;
}

char * coap_get_multi_option_as_string(multi_option_t * option)
{
    size_t len = 0;
    multi_option_t * opt;
    char * output;

    for (opt = option; opt != NULL; opt = opt->next)
    {
       len += opt->len + 1;     // for separator
    }

    output = (char *)coap_malloc(len + 1); // for String terminator
    if (output != NULL)
    {
        size_t i = 0;

        for (opt = option; opt != NULL; opt = opt->next)
        {
            output[i] = '/';
            i += 1;

            memmove(output + i, opt->data, opt->len);
            i += opt->len;
        }
        output[i] = 0;
    }

    return output;
}

int
coap_get_header_observe(void *packet, uint32_t *observe)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  //if (!IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE)) return 0;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  block_opt = coap_check_option(coap_pkt, COAP_OPTION_OBSERVE, &opt_iter);
	if(!block_opt) return 0;
  *observe = coap_pkt->observe;
  return 1;
}

int
coap_set_header_observe(void *packet, uint32_t observe)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  coap_pkt->observe = 0x00FFFFFF & observe;
  //SET_OPTION(coap_pkt, COAP_OPTION_OBSERVE);
  return 1;
}

int
coap_set_header_block2(void *packet, uint32_t num, uint8_t more, uint16_t size)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  if (size<16) return 0;
  if (size>2048) return 0;
  if (num>0x0FFFFF) return 0;

  coap_pkt->block2_num = num;
  coap_pkt->block2_more = more ? 1 : 0;
  coap_pkt->block2_size = size;
  //code
  //coap_add_option(coap_pkt, COAP_OPTION_BLOCK2, unsigned int len, const unsigned char *data)

  //SET_OPTION(coap_pkt, COAP_OPTION_BLOCK2);
  return 1;
}

int
coap_get_header_block2(void *packet, uint32_t *num, uint8_t *more, uint16_t *size, uint32_t *offset)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  //if (!IS_OPTION(coap_pkt, COAP_OPTION_BLOCK2)) return 0;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  block_opt = coap_check_option(coap_pkt, COAP_OPTION_BLOCK2, &opt_iter);
	if(!block_opt) return 0;
  /* pointers may be NULL to get only specific block parameters */
  if (num!=NULL) *num = coap_pkt->block2_num;
  if (more!=NULL) *more = coap_pkt->block2_more;
  if (size!=NULL) *size = coap_pkt->block2_size;
  if (offset!=NULL) *offset = coap_pkt->block2_offset;

  return 1;
}

int
coap_set_header_block1(void *packet, uint32_t num, uint8_t more, uint16_t size)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  if (size<16) return 0;
  if (size>2048) return 0;
  if (num>0x0FFFFF) return 0;

  coap_pkt->block1_num = num;
  coap_pkt->block1_more = more;
  coap_pkt->block1_size = size;

  //SET_OPTION(coap_pkt, COAP_OPTION_BLOCK1);
  return 1;
}

int
coap_get_header_block1(void *packet, uint32_t *num, uint8_t *more, uint16_t *size, uint32_t *offset)
{
  coap_pdu_t *const coap_pkt = (coap_pdu_t *) packet;

  //if (!IS_OPTION(coap_pkt, COAP_OPTION_BLOCK1)) return 0;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  block_opt = coap_check_option(coap_pkt, COAP_OPTION_BLOCK1, &opt_iter);
	if(!block_opt) return 0;
  /* pointers may be NULL to get only specific block parameters */
  if (num!=NULL) *num = coap_pkt->block1_num;
  if (more!=NULL) *more = coap_pkt->block1_more;
  if (size!=NULL) *size = coap_pkt->block1_size;
  if (offset!=NULL) *offset = coap_pkt->block1_offset;

  return 1;
}
