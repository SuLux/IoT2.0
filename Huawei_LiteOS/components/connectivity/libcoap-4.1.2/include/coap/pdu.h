/*
 * pdu.h -- CoAP message structure
 *
 * Copyright (C) 2010-2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file pdu.h
 * @brief Pre-defined constants that reflect defaults for CoAP
 */

#ifndef _COAP_PDU_H_
#define _COAP_PDU_H_

#include "uri.h"

#ifdef WITH_LWIP
#include <lwip/pbuf.h>
#endif

#define COAP_DEFAULT_PORT      5683 /* CoAP default UDP port */
#define COAP_DEFAULT_MAX_AGE     60 /* default maximum object lifetime in seconds */
#ifndef COAP_MAX_PDU_SIZE
#define COAP_MAX_PDU_SIZE      1400 /* maximum size of a CoAP PDU */
#endif /* COAP_MAX_PDU_SIZE */

//add from er-coap-13.h
#ifndef REST_MAX_CHUNK_SIZE
#define REST_MAX_CHUNK_SIZE     128
#endif

#define COAP_HEADER_LEN                      4 /* | version:0x03 type:0x0C tkl:0xF0 | code | mid:0x00FF | mid:0xFF00 | */
#define COAP_MAX_ACCEPT_NUM                  2 /* The maximum number of accept preferences to parse/store */
#define COAP_MAX_RETRANSMIT                  4
#define COAP_RESPONSE_TIMEOUT                2
#define COAP_TOKEN_LEN                       8 /* The maximum number of bytes for the Token */
#define COAP_ETAG_LEN                        8 /* The maximum number of bytes for the ETag */

#define COAP_ACK_RANDOM_FACTOR               1.5
#define COAP_MAX_TRANSMIT_WAIT               ((COAP_RESPONSE_TIMEOUT * ( (1 << (COAP_MAX_RETRANSMIT + 1) ) - 1) * COAP_ACK_RANDOM_FACTOR))

#define COAP_MAX_OPTION_HEADER_LEN           5

#define COAP_HEADER_VERSION_MASK             0xC0
#define COAP_HEADER_VERSION_POSITION         6
#define COAP_HEADER_TYPE_MASK                0x30
#define COAP_HEADER_TYPE_POSITION            4
#define COAP_HEADER_TOKEN_LEN_MASK           0x0F
#define COAP_HEADER_TOKEN_LEN_POSITION       0

#define COAP_HEADER_OPTION_DELTA_MASK        0xF0
#define COAP_HEADER_OPTION_SHORT_LENGTH_MASK 0x0F


#ifndef MIN
#define MIN(a, b) ((a) < (b)? (a) : (b))
#endif /* MIN */

#define COAP_DEFAULT_VERSION      1 /* version of CoAP supported */
#define COAP_DEFAULT_SCHEME  "coap" /* the default scheme for CoAP URIs */

/** well-known resources URI */
#define COAP_DEFAULT_URI_WELLKNOWN ".well-known/core"

#ifdef __COAP_DEFAULT_HASH
/* pre-calculated hash key for the default well-known URI */
#define COAP_DEFAULT_WKC_HASHKEY   "\345\130\144\245"
#endif

/* CoAP message types */

#define COAP_MESSAGE_CON       0 /* confirmable message (requires ACK/RST) */
#define COAP_MESSAGE_NON       1 /* non-confirmable message (one-shot message) */
#define COAP_MESSAGE_ACK       2 /* used to acknowledge confirmable messages */
#define COAP_MESSAGE_RST       3 /* indicates error in received messages */

/* CoAP request methods */

/* CoAP request method codes */
typedef enum {
  COAP_REQUEST_GET = 1,
  COAP_REQUEST_POST,
  COAP_REQUEST_PUT,
  COAP_REQUEST_DELETE
} coap_method_t;

#if 0
#define COAP_REQUEST_GET       1
#define COAP_REQUEST_POST      2
#define COAP_REQUEST_PUT       3
#define COAP_REQUEST_DELETE    4
#endif

/* CoAP option types (be sure to update check_critical when adding options */

#define COAP_OPTION_IF_MATCH        1 /* C, opaque, 0-8 B, (none) */
#define COAP_OPTION_URI_HOST        3 /* C, String, 1-255 B, destination address */
#define COAP_OPTION_ETAG            4 /* E, opaque, 1-8 B, (none) */
#define COAP_OPTION_IF_NONE_MATCH   5 /* empty, 0 B, (none) */
#define COAP_OPTION_URI_PORT        7 /* C, uint, 0-2 B, destination port */
#define COAP_OPTION_LOCATION_PATH   8 /* E, String, 0-255 B, - */
#define COAP_OPTION_URI_PATH       11 /* C, String, 0-255 B, (none) */
#define COAP_OPTION_CONTENT_FORMAT 12 /* E, uint, 0-2 B, (none) */
#define COAP_OPTION_CONTENT_TYPE COAP_OPTION_CONTENT_FORMAT
#define COAP_OPTION_MAXAGE         14 /* E, uint, 0--4 B, 60 Seconds */
#define COAP_OPTION_URI_QUERY      15 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_ACCEPT         17 /* C, uint,   0-2 B, (none) */
#define COAP_OPTION_LOCATION_QUERY 20 /* E, String,   0-255 B, (none) */
#define COAP_OPTION_SIZE           28 /* 0-4 B */
#define COAP_OPTION_PROXY_URI      35 /* C, String, 1-1034 B, (none) */
#define COAP_OPTION_PROXY_SCHEME   39 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_SIZE1          60 /* E, uint, 0-4 B, (none) */

#define COAP_OPTION_TOKEN          19         /* 1-8 B */

/* option types from RFC 7641 */

#define COAP_OPTION_OBSERVE         6 /* E, empty/uint, 0 B/0-3 B, (none) */
#define COAP_OPTION_SUBSCRIPTION  COAP_OPTION_OBSERVE

/* selected option types from RFC 7959 */

#define COAP_OPTION_BLOCK2         23 /* C, uint, 0--3 B, (none) */
#define COAP_OPTION_BLOCK1         27 /* C, uint, 0--3 B, (none) */

/* selected option types from RFC 7967 */

#define COAP_OPTION_NORESPONSE    258 /* N, uint, 0--1 B, 0 */

#define COAP_MAX_OPT            65535 /**< the highest option number we know */
#define COAP_MAX_ACCEPT_NUM                  2 /* The maximum number of accept preferences to parse/store */

/* CoAP result codes (HTTP-Code / 100 * 40 + HTTP-Code % 100) */

/* As of draft-ietf-core-coap-04, response codes are encoded to base
 * 32, i.e.  the three upper bits determine the response class while
 * the remaining five fine-grained information specific to that class.
 */
#define COAP_RESPONSE_CODE(N) (((N)/100 << 5) | (N)%100)

/* Determines the class of response code C */
#define COAP_RESPONSE_CLASS(C) (((C) >> 5) & 0xFF)

#ifndef SHORT_ERROR_RESPONSE
/**
 * Returns a human-readable response phrase for the specified CoAP response @p
 * code. This function returns @c NULL if not found.
 *
 * @param code The response code for which the literal phrase should be
 *             retrieved.
 *
 * @return     A zero-terminated string describing the error, or @c NULL if not
 *             found.
 */
char *coap_response_phrase(unsigned char code);

#define COAP_ERROR_PHRASE_LENGTH   32 /**< maximum length of error phrase */

#else
#define coap_response_phrase(x) ((char *)NULL)

#define COAP_ERROR_PHRASE_LENGTH    0 /**< maximum length of error phrase */
#endif /* SHORT_ERROR_RESPONSE */

/* The following definitions exist for backwards compatibility */
#if 0 /* this does not exist any more */
#define COAP_RESPONSE_100      40 /* 100 Continue */
#endif
#define COAP_RESPONSE_200      COAP_RESPONSE_CODE(200)  /* 2.00 OK */
#define COAP_RESPONSE_201      COAP_RESPONSE_CODE(201)  /* 2.01 Created */
#define COAP_RESPONSE_304      COAP_RESPONSE_CODE(203)  /* 2.03 Valid */
#define COAP_RESPONSE_400      COAP_RESPONSE_CODE(400)  /* 4.00 Bad Request */
#define COAP_RESPONSE_404      COAP_RESPONSE_CODE(404)  /* 4.04 Not Found */
#define COAP_RESPONSE_405      COAP_RESPONSE_CODE(405)  /* 4.05 Method Not Allowed */
#define COAP_RESPONSE_415      COAP_RESPONSE_CODE(415)  /* 4.15 Unsupported Media Type */
#define COAP_RESPONSE_500      COAP_RESPONSE_CODE(500)  /* 5.00 Internal Server Error */
#define COAP_RESPONSE_501      COAP_RESPONSE_CODE(501)  /* 5.01 Not Implemented */
#define COAP_RESPONSE_503      COAP_RESPONSE_CODE(503)  /* 5.03 Service Unavailable */
#define COAP_RESPONSE_504      COAP_RESPONSE_CODE(504)  /* 5.04 Gateway Timeout */
#if 0  /* these response codes do not have a valid code any more */
#  define COAP_RESPONSE_X_240    240   /* Token Option required by server */
#  define COAP_RESPONSE_X_241    241   /* Uri-Authority Option required by server */
#endif
#define COAP_RESPONSE_X_242    COAP_RESPONSE_CODE(402)  /* Critical Option not supported */

/* CoAP response codes */
typedef enum {
  NO_ERROR = 0,

  CREATED_2_01 = 65,                    /* CREATED */
  DELETED_2_02 = 66,                    /* DELETED */
  VALID_2_03 = 67,                      /* NOT_MODIFIED */
  CHANGED_2_04 = 68,                    /* CHANGED */
  CONTENT_2_05 = 69,                    /* OK */

  BAD_REQUEST_4_00 = 128,               /* BAD_REQUEST */
  UNAUTHORIZED_4_01 = 129,              /* UNAUTHORIZED */
  BAD_OPTION_4_02 = 130,                /* BAD_OPTION */
  FORBIDDEN_4_03 = 131,                 /* FORBIDDEN */
  NOT_FOUND_4_04 = 132,                 /* NOT_FOUND */
  METHOD_NOT_ALLOWED_4_05 = 133,        /* METHOD_NOT_ALLOWED */
  NOT_ACCEPTABLE_4_06 = 134,            /* NOT_ACCEPTABLE */
  PRECONDITION_FAILED_4_12 = 140,       /* BAD_REQUEST */
  REQUEST_ENTITY_TOO_LARGE_4_13 = 141,  /* REQUEST_ENTITY_TOO_LARGE */
  UNSUPPORTED_MEDIA_TYPE_4_15 = 143,    /* UNSUPPORTED_MEDIA_TYPE */

  INTERNAL_SERVER_ERROR_5_00 = 160,     /* INTERNAL_SERVER_ERROR */
  NOT_IMPLEMENTED_5_01 = 161,           /* NOT_IMPLEMENTED */
  BAD_GATEWAY_5_02 = 162,               /* BAD_GATEWAY */
  SERVICE_UNAVAILABLE_5_03 = 163,       /* SERVICE_UNAVAILABLE */
  GATEWAY_TIMEOUT_5_04 = 164,           /* GATEWAY_TIMEOUT */
  PROXYING_NOT_SUPPORTED_5_05 = 165,    /* PROXYING_NOT_SUPPORTED */

  /* Erbium errors */
  MEMORY_ALLOCATION_ERROR = 192,
  PACKET_SERIALIZATION_ERROR,

  /* Erbium hooks */
  MANUAL_RESPONSE

} coap_status_t;


/* CoAP media type encoding */

#define COAP_MEDIATYPE_TEXT_PLAIN                 0 /* text/plain (UTF-8) */
#define COAP_MEDIATYPE_APPLICATION_LINK_FORMAT   40 /* application/link-format */
#define COAP_MEDIATYPE_APPLICATION_XML           41 /* application/xml */
#define COAP_MEDIATYPE_APPLICATION_OCTET_STREAM  42 /* application/octet-stream */
#define COAP_MEDIATYPE_APPLICATION_RDF_XML       43 /* application/rdf+xml */
#define COAP_MEDIATYPE_APPLICATION_EXI           47 /* application/exi  */
#define COAP_MEDIATYPE_APPLICATION_JSON          50 /* application/json  */
#define COAP_MEDIATYPE_APPLICATION_CBOR          60 /* application/cbor  */

/* CoAP Content-Types */
typedef enum {
  TEXT_PLAIN = 0,
  TEXT_XML = 1, /* Indented types are not in the initial registry. */
  TEXT_CSV = 2,
  TEXT_HTML = 3,
  IMAGE_GIF = 21,
  IMAGE_JPEG = 22,
  IMAGE_PNG = 23,
  IMAGE_TIFF = 24,
  AUDIO_RAW = 25,
  VIDEO_RAW = 26,
  APPLICATION_LINK_FORMAT = 40,
  APPLICATION_XML = 41,
  APPLICATION_OCTET_STREAM = 42,
  APPLICATION_RDF_XML = 43,
  APPLICATION_SOAP_XML = 44,
  APPLICATION_ATOM_XML = 45,
  APPLICATION_XMPP_XML = 46,
  APPLICATION_EXI = 47,
  APPLICATION_FASTINFOSET = 48,
  APPLICATION_SOAP_FASTINFOSET = 49,
  APPLICATION_JSON = 50,
  APPLICATION_X_OBIX_BINARY = 51,
  CONTENT_MAX_VALUE = 0xFFFF
} coap_content_type_t;

/* Note that identifiers for registered media types are in the range 0-65535. We
 * use an unallocated type here and hope for the best. */
#define COAP_MEDIATYPE_ANY                         0xff /* any media type */

/**
 * coap_tid_t is used to store CoAP transaction id, i.e. a hash value
 * built from the remote transport address and the message id of a
 * CoAP PDU.  Valid transaction ids are greater or equal zero.
 */
typedef int coap_tid_t;

/** Indicates an invalid transaction id. */
#define COAP_INVALID_TID -1

/**
 * Indicates that a response is suppressed. This will occur for error
 * responses if the request was received via IP multicast.
 */
#define COAP_DROPPED_RESPONSE -2

#ifdef WORDS_BIGENDIAN
typedef struct {
  unsigned int version:2;      /* protocol version */
  unsigned int type:2;         /* type flag */
  unsigned int token_length:4; /* length of Token */
  unsigned int code:8;         /* request method (value 1--10) or response
                                  code (value 40-255) */
  unsigned short id;           /* message id */
  unsigned char token[];       /* the actual token, if any */
} coap_hdr_t;
#else
typedef struct {
  unsigned int token_length:4; /* length of Token */
  unsigned int type:2;         /* type flag */
  unsigned int version:2;      /* protocol version */
  unsigned int code:8;         /* request method (value 1--10) or response
                                  code (value 40-255) */
  unsigned short id;           /* transaction id (network byte order!) */
  unsigned char token[];       /* the actual token, if any */
} coap_hdr_t;
#endif

#define COAP_MESSAGE_IS_EMPTY(MSG)    ((MSG)->code == 0)
#define COAP_MESSAGE_IS_REQUEST(MSG)  (!COAP_MESSAGE_IS_EMPTY(MSG) \
                                       && ((MSG)->code < 32))
#define COAP_MESSAGE_IS_RESPONSE(MSG) ((MSG)->code >= 64)

#define COAP_OPT_LONG 0x0F      /* OC == 0b1111 indicates that the option list
                                 * in a CoAP message is limited by 0b11110000
                                 * marker */

#define COAP_OPT_END 0xF0       /* end marker */

#define COAP_PAYLOAD_START 0xFF /* payload marker */

/**
 * Structures for more convenient handling of options. (To be used with ordered
 * coap_list_t.) The option's data will be added to the end of the coap_option
 * structure (see macro COAP_OPTION_DATA).
 */
typedef struct {
  unsigned short key;           /* the option key (no delta coding) */
  unsigned int length;
} coap_option;

#define COAP_OPTION_KEY(option) (option).key
#define COAP_OPTION_LENGTH(option) (option).length
#define COAP_OPTION_DATA(option) ((unsigned char *)&(option) + sizeof(coap_option))


typedef struct _multi_option_t {
  struct _multi_option_t *next;
  uint8_t is_static;
  uint8_t len;
  uint8_t *data;
} multi_option_t;

/**
 * Header structure for CoAP PDUs
 */

typedef struct {
  size_t max_size;          /**< allocated storage for options and data */
  coap_hdr_t *hdr;        /**< Address of the first byte of the CoAP message.
                             *   This may or may not equal (coap_hdr_t*)(pdu+1)
                             *   depending on the memory management
                             *   implementation. */
  unsigned short max_delta; /**< highest option number */
  unsigned short length;    /**< PDU length (including header, options, data) */
  unsigned char *data;      /**< payload */
  uint16_t payload_len;
  multi_option_t *uri_path;
	multi_option_t *uri_query;
	multi_option_t *location_path;
	uint32_t observe;
	uint8_t accept_num;
  uint16_t accept[COAP_MAX_ACCEPT_NUM];
	coap_content_type_t content_type; /* Parse options once and store; allows setting options in random order  */
  uint32_t block2_num;
  uint8_t block2_more;
  uint16_t block2_size;
  uint32_t block2_offset;
  uint32_t block1_num;
  uint8_t block1_more;
  uint16_t block1_size;
  uint32_t block1_offset;
  uint32_t max_age;
  uint8_t etag_len;
  uint8_t etag[COAP_ETAG_LEN];
  uint8_t if_match_len;
  uint8_t if_match[COAP_ETAG_LEN];
  uint8_t if_none_match;
  uint16_t uri_port;
  size_t uri_host_len;
  const uint8_t *uri_host;
  uint32_t size;   //option size
#ifdef WITH_LWIP
  struct pbuf *pbuf;        /**< lwIP PBUF. The package data will always reside
                             *    inside the pbuf's payload, but this pointer
                             *    has to be kept because no exact offset can be
                             *    given. This field must not be accessed from
                             *    outside, because the pbuf's reference count
                             *    is checked to be 1 when the pbuf is assigned
                             *    to the pdu, and the pbuf stays exclusive to
                             *    this pdu. */
#endif
} coap_pdu_t;


/**
 * Options in coap_pdu_t are accessed with the macro COAP_OPTION.
 */
#define COAP_OPTION(node) ((coap_option *)(node)->options)

#ifdef WITH_LWIP
/**
 * Creates a CoAP PDU from an lwIP @p pbuf, whose reference is passed on to this
 * function.
 *
 * The pbuf is checked for being contiguous, and for having only one reference.
 * The reference is stored in the PDU and will be freed when the PDU is freed.
 *
 * (For now, these are fatal errors; in future, a new pbuf might be allocated,
 * the data copied and the passed pbuf freed).
 *
 * This behaves like coap_pdu_init(0, 0, 0, pbuf->tot_len), and afterwards
 * copying the contents of the pbuf to the pdu.
 *
 * @return A pointer to the new PDU object or @c NULL on error.
 */
coap_pdu_t * coap_pdu_from_pbuf(struct pbuf *pbuf);
#endif

/**
 * Creates a new CoAP PDU of given @p size (must be large enough to hold the
 * basic CoAP message header (coap_hdr_t). The function returns a pointer to the
 * node coap_pdu_t object on success, or @c NULL on error. The storage allocated
 * for the result must be released with coap_delete_pdu().
 *
 * @param type The type of the PDU (one of COAP_MESSAGE_CON, COAP_MESSAGE_NON,
 *             COAP_MESSAGE_ACK, COAP_MESSAGE_RST).
 * @param code The message code.
 * @param id   The message id to set or COAP_INVALID_TID if unknown.
 * @param size The number of bytes to allocate for the actual message.
 *
 * @return     A pointer to the new PDU object or @c NULL on error.
 */
coap_pdu_t *
coap_pdu_init(unsigned char type,
              unsigned char code,
              unsigned short id,
              size_t size);

/**
 * Clears any contents from @p pdu and resets @c version field, @c
 * length and @c data pointers. @c max_size is set to @p size, any
 * other field is set to @c 0. Note that @p pdu must be a valid
 * pointer to a coap_pdu_t object created e.g. by coap_pdu_init().
 */
void coap_pdu_clear(coap_pdu_t *pdu, size_t size);

/**
 * Creates a new CoAP PDU.
 * The object is created on the heap and must be released using
 * coap_delete_pdu();
 *
 * @deprecated This function allocates the maximum storage for each
 * PDU. Use coap_pdu_init() instead.
 */
coap_pdu_t *coap_new_pdu(void);

void coap_delete_pdu(coap_pdu_t *);

/**
 * Parses @p data into the CoAP PDU structure given in @p result.
 * This function returns @c 0 on error or a number greater than zero on success.
 *
 * @param data   The raw data to parse as CoAP PDU.
 * @param length The actual size of @p data.
 * @param result The PDU structure to fill. Note that the structure must
 *               provide space for at least @p length bytes to hold the
 *               entire CoAP PDU.
 *
 * @return       A value greater than zero on success or @c 0 on error.
 */
int coap_pdu_parse(unsigned char *data,
                   size_t length,
                   coap_pdu_t *result);
coap_status_t coap_parse_message(void *packet, uint8_t *data, uint16_t data_len);
int coap_set_status_code(void *packet, unsigned int code);
void coap_add_multi_option(multi_option_t **dst, uint8_t *option, size_t option_len, uint8_t is_static);
void free_multi_option(multi_option_t *dst);
void coap_free_header(void *packet);
int coap_get_header_token(void *packet, const uint8_t **token);
int coap_set_header_content_type(void *packet, unsigned int content_type);
int coap_set_header_location_path(void *packet, const char *path);
int coap_set_header_uri_path(void *packet, const char *path);
char * coap_get_multi_option_as_string(multi_option_t * option);
int coap_get_header_observe(void *packet, uint32_t *observe);
int coap_set_header_observe(void *packet, uint32_t observe);
int coap_set_header_block2(void *packet, uint32_t num, uint8_t more, uint16_t size);
int coap_get_header_block2(void *packet, uint32_t *num, uint8_t *more, uint16_t *size, uint32_t *offset);
int coap_set_header_block1(void *packet, uint32_t num, uint8_t more, uint16_t size);
int coap_get_header_block1(void *packet, uint32_t *num, uint8_t *more, uint16_t *size, uint32_t *offset);
int coap_set_header_uri_query(void *packet, const char *query);
int coap_set_header_uri_path_segment(void *packet, const char *segment);

/**
 * Adds token of length @p len to @p pdu.
 * Adding the token destroys any following contents of the pdu. Hence options
 * and data must be added after coap_add_token() has been called. In @p pdu,
 * length is set to @p len + @c 4, and max_delta is set to @c 0. This funtion
 * returns @c 0 on error or a value greater than zero on success.
 *
 * @param pdu  The PDU where the token is to be added.
 * @param len  The length of the new token.
 * @param data The token to add.
 *
 * @return     A value greater than zero on success, or @c 0 on error.
 */
int coap_add_token(coap_pdu_t *pdu,
                  size_t len,
                  const unsigned char *data);

/**
 * Adds option of given type to pdu that is passed as first
 * parameter.
 * coap_add_option() destroys the PDU's data, so coap_add_data() must be called
 * after all options have been added. As coap_add_token() destroys the options
 * following the token, the token must be added before coap_add_option() is
 * called. This function returns the number of bytes written or @c 0 on error.
 */
size_t coap_add_option(coap_pdu_t *pdu,
                       unsigned short type,
                       unsigned int len,
                       const unsigned char *data);

/**
 * Adds option of given type to pdu that is passed as first parameter, but does
 * not write a value. It works like coap_add_option with respect to calling
 * sequence (i.e. after token and before data). This function returns a memory
 * address to which the option data has to be written before the PDU can be
 * sent, or @c NULL on error.
 */
unsigned char *coap_add_option_later(coap_pdu_t *pdu,
                                     unsigned short type,
                                     unsigned int len);

/**
 * Adds given data to the pdu that is passed as first parameter. Note that the
 * PDU's data is destroyed by coap_add_option(). coap_add_data() must be called
 * only once per PDU, otherwise the result is undefined.
 */
int coap_add_data(coap_pdu_t *pdu,
                  unsigned int len,
                  const unsigned char *data);

/**
 * Retrieves the length and data pointer of specified PDU. Returns 0 on error or
 * 1 if *len and *data have correct values. Note that these values are destroyed
 * with the pdu.
 */
int coap_get_data(coap_pdu_t *pdu,
                  size_t *len,
                  unsigned char **data);

#endif /* _COAP_PDU_H_ */
