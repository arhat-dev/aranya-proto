/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_CMD_CONTAINER_NETWORK_PB_H_INCLUDED
#define PB_ARANYA_CMD_CONTAINER_NETWORK_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _aranya_ContainerNetworkEnsureCmd {
    pb_callback_t cidr_ipv4;
    pb_callback_t cidr_ipv6;
} aranya_ContainerNetworkEnsureCmd;


/* Initializer values for message structs */
#define aranya_ContainerNetworkEnsureCmd_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_ContainerNetworkEnsureCmd_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_ContainerNetworkEnsureCmd_cidr_ipv4_tag 1
#define aranya_ContainerNetworkEnsureCmd_cidr_ipv6_tag 2

/* Struct field encoding specification for nanopb */
#define aranya_ContainerNetworkEnsureCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   cidr_ipv4,         1) \
X(a, CALLBACK, SINGULAR, STRING,   cidr_ipv6,         2)
#define aranya_ContainerNetworkEnsureCmd_CALLBACK pb_default_field_callback
#define aranya_ContainerNetworkEnsureCmd_DEFAULT NULL

extern const pb_msgdesc_t aranya_ContainerNetworkEnsureCmd_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_ContainerNetworkEnsureCmd_fields &aranya_ContainerNetworkEnsureCmd_msg

/* Maximum encoded size of messages (where known) */
/* aranya_ContainerNetworkEnsureCmd_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
