/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_MSG_PERIPHERAL_PB_H_INCLUDED
#define PB_ARANYA_MSG_PERIPHERAL_PB_H_INCLUDED
#include <pb.h>
#include "peripheral.pb.h"

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _aranya_PeripheralState {
    aranya_PeripheralState_PERIPHERAL_STATE_UNKNOWN = 0,
    aranya_PeripheralState_PERIPHERAL_STATE_CREATED = 1,
    aranya_PeripheralState_PERIPHERAL_STATE_CONNECTED = 2,
    aranya_PeripheralState_PERIPHERAL_STATE_ERRORED = 3,
    aranya_PeripheralState_PERIPHERAL_STATE_REMOVED = 4
} aranya_PeripheralState;

/* Struct definitions */
typedef struct _aranya_PeripheralOperationResultMsg {
    pb_callback_t data;
} aranya_PeripheralOperationResultMsg;

typedef struct _aranya_PeripheralStatusListMsg {
    pb_callback_t peripherals;
} aranya_PeripheralStatusListMsg;

typedef struct _aranya_PeripheralStatusMsg {
    aranya_PeripheralType kind;
    pb_callback_t name;
    aranya_PeripheralState state;
    pb_callback_t message;
} aranya_PeripheralStatusMsg;


/* Helper constants for enums */
#define _aranya_PeripheralState_MIN aranya_PeripheralState_PERIPHERAL_STATE_UNKNOWN
#define _aranya_PeripheralState_MAX aranya_PeripheralState_PERIPHERAL_STATE_REMOVED
#define _aranya_PeripheralState_ARRAYSIZE ((aranya_PeripheralState)(aranya_PeripheralState_PERIPHERAL_STATE_REMOVED+1))


/* Initializer values for message structs */
#define aranya_PeripheralStatusMsg_init_default  {_aranya_PeripheralType_MIN, {{NULL}, NULL}, _aranya_PeripheralState_MIN, {{NULL}, NULL}}
#define aranya_PeripheralStatusListMsg_init_default {{{NULL}, NULL}}
#define aranya_PeripheralOperationResultMsg_init_default {{{NULL}, NULL}}
#define aranya_PeripheralStatusMsg_init_zero     {_aranya_PeripheralType_MIN, {{NULL}, NULL}, _aranya_PeripheralState_MIN, {{NULL}, NULL}}
#define aranya_PeripheralStatusListMsg_init_zero {{{NULL}, NULL}}
#define aranya_PeripheralOperationResultMsg_init_zero {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_PeripheralOperationResultMsg_data_tag 1
#define aranya_PeripheralStatusListMsg_peripherals_tag 1
#define aranya_PeripheralStatusMsg_kind_tag      1
#define aranya_PeripheralStatusMsg_name_tag      2
#define aranya_PeripheralStatusMsg_state_tag     3
#define aranya_PeripheralStatusMsg_message_tag   4

/* Struct field encoding specification for nanopb */
#define aranya_PeripheralStatusMsg_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, CALLBACK, SINGULAR, STRING,   name,              2) \
X(a, STATIC,   SINGULAR, UENUM,    state,             3) \
X(a, CALLBACK, SINGULAR, STRING,   message,           4)
#define aranya_PeripheralStatusMsg_CALLBACK pb_default_field_callback
#define aranya_PeripheralStatusMsg_DEFAULT NULL

#define aranya_PeripheralStatusListMsg_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, MESSAGE,  peripherals,       1)
#define aranya_PeripheralStatusListMsg_CALLBACK pb_default_field_callback
#define aranya_PeripheralStatusListMsg_DEFAULT NULL
#define aranya_PeripheralStatusListMsg_peripherals_MSGTYPE aranya_PeripheralStatusMsg

#define aranya_PeripheralOperationResultMsg_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, BYTES,    data,              1)
#define aranya_PeripheralOperationResultMsg_CALLBACK pb_default_field_callback
#define aranya_PeripheralOperationResultMsg_DEFAULT NULL

extern const pb_msgdesc_t aranya_PeripheralStatusMsg_msg;
extern const pb_msgdesc_t aranya_PeripheralStatusListMsg_msg;
extern const pb_msgdesc_t aranya_PeripheralOperationResultMsg_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_PeripheralStatusMsg_fields &aranya_PeripheralStatusMsg_msg
#define aranya_PeripheralStatusListMsg_fields &aranya_PeripheralStatusListMsg_msg
#define aranya_PeripheralOperationResultMsg_fields &aranya_PeripheralOperationResultMsg_msg

/* Maximum encoded size of messages (where known) */
/* aranya_PeripheralStatusMsg_size depends on runtime parameters */
/* aranya_PeripheralStatusListMsg_size depends on runtime parameters */
/* aranya_PeripheralOperationResultMsg_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
