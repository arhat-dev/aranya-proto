/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_RUNTIME_RUNTIME_RUNTIME_PB_H_INCLUDED
#define PB_RUNTIME_RUNTIME_RUNTIME_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _runtime_PacketType {
    runtime_PacketType__INVALID_RUNTIME_DATA = 0,
    runtime_PacketType_CMD_GET_INFO = 1,
    runtime_PacketType_CMD_EXEC = 2,
    runtime_PacketType_CMD_ATTACH = 3,
    runtime_PacketType_CMD_LOGS = 4,
    runtime_PacketType_CMD_TTY_RESIZE = 5,
    runtime_PacketType_CMD_PORT_FORWARD = 6,
    runtime_PacketType_MSG_RUNTIME_INFO = 9,
    runtime_PacketType_MSG_ERROR = 10,
    runtime_PacketType_CMD_IMAGE_LIST = 11,
    runtime_PacketType_CMD_IMAGE_ENSURE = 12,
    runtime_PacketType_CMD_IMAGE_DELETE = 13,
    runtime_PacketType_MSG_IMAGE_STATUS = 21,
    runtime_PacketType_MSG_IMAGE_STATUS_LIST = 22,
    runtime_PacketType_CMD_POD_LIST = 31,
    runtime_PacketType_CMD_POD_ENSURE = 32,
    runtime_PacketType_CMD_POD_DELETE = 33,
    runtime_PacketType_MSG_POD_STATUS = 41,
    runtime_PacketType_MSG_POD_STATUS_LIST = 42,
    runtime_PacketType_CMD_METRICS_CONFIG = 51,
    runtime_PacketType_CMD_METRICS_COLLECT = 52
} runtime_PacketType;

/* Struct definitions */
typedef struct _runtime_RuntimeInfo {
    pb_callback_t name;
    pb_callback_t version;
    pb_callback_t os;
    pb_callback_t os_image;
    pb_callback_t arch;
    pb_callback_t kernel_version;
} runtime_RuntimeInfo;

typedef struct _runtime_Packet {
    runtime_PacketType kind;
    pb_callback_t payload;
} runtime_Packet;


/* Helper constants for enums */
#define _runtime_PacketType_MIN runtime_PacketType__INVALID_RUNTIME_DATA
#define _runtime_PacketType_MAX runtime_PacketType_CMD_METRICS_COLLECT
#define _runtime_PacketType_ARRAYSIZE ((runtime_PacketType)(runtime_PacketType_CMD_METRICS_COLLECT+1))


/* Initializer values for message structs */
#define runtime_Packet_init_default              {_runtime_PacketType_MIN, {{NULL}, NULL}}
#define runtime_RuntimeInfo_init_default         {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define runtime_Packet_init_zero                 {_runtime_PacketType_MIN, {{NULL}, NULL}}
#define runtime_RuntimeInfo_init_zero            {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define runtime_RuntimeInfo_name_tag             1
#define runtime_RuntimeInfo_version_tag          2
#define runtime_RuntimeInfo_os_tag               3
#define runtime_RuntimeInfo_os_image_tag         4
#define runtime_RuntimeInfo_arch_tag             5
#define runtime_RuntimeInfo_kernel_version_tag   6
#define runtime_Packet_kind_tag                  1
#define runtime_Packet_payload_tag               2

/* Struct field encoding specification for nanopb */
#define runtime_Packet_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, CALLBACK, SINGULAR, BYTES,    payload,           2)
#define runtime_Packet_CALLBACK pb_default_field_callback
#define runtime_Packet_DEFAULT NULL

#define runtime_RuntimeInfo_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   name,              1) \
X(a, CALLBACK, SINGULAR, STRING,   version,           2) \
X(a, CALLBACK, SINGULAR, STRING,   os,                3) \
X(a, CALLBACK, SINGULAR, STRING,   os_image,          4) \
X(a, CALLBACK, SINGULAR, STRING,   arch,              5) \
X(a, CALLBACK, SINGULAR, STRING,   kernel_version,    6)
#define runtime_RuntimeInfo_CALLBACK pb_default_field_callback
#define runtime_RuntimeInfo_DEFAULT NULL

extern const pb_msgdesc_t runtime_Packet_msg;
extern const pb_msgdesc_t runtime_RuntimeInfo_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define runtime_Packet_fields &runtime_Packet_msg
#define runtime_RuntimeInfo_fields &runtime_RuntimeInfo_msg

/* Maximum encoded size of messages (where known) */
/* runtime_Packet_size depends on runtime parameters */
/* runtime_RuntimeInfo_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
