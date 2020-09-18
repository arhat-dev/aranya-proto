/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_MSG_DEVICE_PB_H_INCLUDED
#define PB_ARANYA_MSG_DEVICE_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _aranya_DeviceStatusMsg_State {
    aranya_DeviceStatusMsg_State_DEVICE_STATE_UNKNOWN = 0,
    aranya_DeviceStatusMsg_State_DEVICE_STATE_CREATED = 1,
    aranya_DeviceStatusMsg_State_DEVICE_STATE_CONNECTED = 2,
    aranya_DeviceStatusMsg_State_DEVICE_STATE_ERRORED = 3
} aranya_DeviceStatusMsg_State;

/* Struct definitions */
typedef struct _aranya_DeviceStatusListMsg {
    pb_callback_t devices;
} aranya_DeviceStatusListMsg;

typedef struct _aranya_DeviceStatusMsg {
    pb_callback_t device_id;
    aranya_DeviceStatusMsg_State state;
    pb_callback_t message;
} aranya_DeviceStatusMsg;


/* Helper constants for enums */
#define _aranya_DeviceStatusMsg_State_MIN aranya_DeviceStatusMsg_State_DEVICE_STATE_UNKNOWN
#define _aranya_DeviceStatusMsg_State_MAX aranya_DeviceStatusMsg_State_DEVICE_STATE_ERRORED
#define _aranya_DeviceStatusMsg_State_ARRAYSIZE ((aranya_DeviceStatusMsg_State)(aranya_DeviceStatusMsg_State_DEVICE_STATE_ERRORED+1))


/* Initializer values for message structs */
#define aranya_DeviceStatusMsg_init_default      {{{NULL}, NULL}, _aranya_DeviceStatusMsg_State_MIN, {{NULL}, NULL}}
#define aranya_DeviceStatusListMsg_init_default  {{{NULL}, NULL}}
#define aranya_DeviceStatusMsg_init_zero         {{{NULL}, NULL}, _aranya_DeviceStatusMsg_State_MIN, {{NULL}, NULL}}
#define aranya_DeviceStatusListMsg_init_zero     {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_DeviceStatusListMsg_devices_tag   1
#define aranya_DeviceStatusMsg_device_id_tag     1
#define aranya_DeviceStatusMsg_state_tag         2
#define aranya_DeviceStatusMsg_message_tag       3

/* Struct field encoding specification for nanopb */
#define aranya_DeviceStatusMsg_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   device_id,         1) \
X(a, STATIC,   SINGULAR, UENUM,    state,             2) \
X(a, CALLBACK, SINGULAR, STRING,   message,           3)
#define aranya_DeviceStatusMsg_CALLBACK pb_default_field_callback
#define aranya_DeviceStatusMsg_DEFAULT NULL

#define aranya_DeviceStatusListMsg_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, MESSAGE,  devices,           1)
#define aranya_DeviceStatusListMsg_CALLBACK pb_default_field_callback
#define aranya_DeviceStatusListMsg_DEFAULT NULL
#define aranya_DeviceStatusListMsg_devices_MSGTYPE aranya_DeviceStatusMsg

extern const pb_msgdesc_t aranya_DeviceStatusMsg_msg;
extern const pb_msgdesc_t aranya_DeviceStatusListMsg_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_DeviceStatusMsg_fields &aranya_DeviceStatusMsg_msg
#define aranya_DeviceStatusListMsg_fields &aranya_DeviceStatusListMsg_msg

/* Maximum encoded size of messages (where known) */
/* aranya_DeviceStatusMsg_size depends on runtime parameters */
/* aranya_DeviceStatusListMsg_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
