/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_MSG_NETWORK_HOST_PB_H_INCLUDED
#define PB_ARANYA_MSG_NETWORK_HOST_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _aranya_HostNetworkInterface {
    pb_callback_t name;
    pb_callback_t hardware_address;
    pb_callback_t ip_addresses;
} aranya_HostNetworkInterface;

typedef struct _aranya_HostNetworkStatusMsg {
    pb_callback_t interfaces;
} aranya_HostNetworkStatusMsg;


/* Initializer values for message structs */
#define aranya_HostNetworkInterface_init_default {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_HostNetworkStatusMsg_init_default {{{NULL}, NULL}}
#define aranya_HostNetworkInterface_init_zero    {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_HostNetworkStatusMsg_init_zero    {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_HostNetworkInterface_name_tag     1
#define aranya_HostNetworkInterface_hardware_address_tag 2
#define aranya_HostNetworkInterface_ip_addresses_tag 3
#define aranya_HostNetworkStatusMsg_interfaces_tag 1

/* Struct field encoding specification for nanopb */
#define aranya_HostNetworkInterface_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   name,              1) \
X(a, CALLBACK, SINGULAR, STRING,   hardware_address,   2) \
X(a, CALLBACK, REPEATED, STRING,   ip_addresses,      3)
#define aranya_HostNetworkInterface_CALLBACK pb_default_field_callback
#define aranya_HostNetworkInterface_DEFAULT NULL

#define aranya_HostNetworkStatusMsg_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, MESSAGE,  interfaces,        1)
#define aranya_HostNetworkStatusMsg_CALLBACK pb_default_field_callback
#define aranya_HostNetworkStatusMsg_DEFAULT NULL
#define aranya_HostNetworkStatusMsg_interfaces_MSGTYPE aranya_HostNetworkInterface

extern const pb_msgdesc_t aranya_HostNetworkInterface_msg;
extern const pb_msgdesc_t aranya_HostNetworkStatusMsg_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_HostNetworkInterface_fields &aranya_HostNetworkInterface_msg
#define aranya_HostNetworkStatusMsg_fields &aranya_HostNetworkStatusMsg_msg

/* Maximum encoded size of messages (where known) */
/* aranya_HostNetworkInterface_size depends on runtime parameters */
/* aranya_HostNetworkStatusMsg_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif