/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_PROTO_PB_H_INCLUDED
#define PB_ARANYA_PROTO_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _aranya_Kind {
    aranya_Kind_EMPTY = 0,
    aranya_Kind_MSG_DATA_DEFAULT = 1,
    aranya_Kind_MSG_DATA_STDOUT = 1,
    aranya_Kind_MSG_DATA_METRICS = 1,
    aranya_Kind_MSG_DATA_STDERR = 2,
    aranya_Kind_CMD_DATA_UPSTREAM = 3,
    aranya_Kind_CMD_REJECT = 10,
    aranya_Kind_CMD_SESSION_CLOSE = 11,
    aranya_Kind_CMD_POD_CTR_EXEC = 12,
    aranya_Kind_CMD_POD_CTR_ATTACH = 13,
    aranya_Kind_CMD_POD_CTR_LOGS = 14,
    aranya_Kind_CMD_POD_CTR_TTY_RESIZE = 15,
    aranya_Kind_CMD_POD_PORT_FORWARD = 16,
    aranya_Kind_CMD_NODE_INFO_GET = 17,
    aranya_Kind_CMD_METRICS_CONFIG = 21,
    aranya_Kind_CMD_METRICS_COLLECT = 22,
    aranya_Kind_CMD_NET_UPDATE_POD_NET = 25,
    aranya_Kind_CMD_CRED_ENSURE = 31,
    aranya_Kind_CMD_IMAGE_LIST = 41,
    aranya_Kind_CMD_IMAGE_ENSURE = 42,
    aranya_Kind_CMD_IMAGE_DELETE = 43,
    aranya_Kind_CMD_STORAGE_LIST = 51,
    aranya_Kind_CMD_STORAGE_ENSURE = 52,
    aranya_Kind_CMD_STORAGE_DELETE = 53,
    aranya_Kind_CMD_POD_LIST = 61,
    aranya_Kind_CMD_POD_ENSURE = 62,
    aranya_Kind_CMD_POD_DELETE = 63,
    aranya_Kind_CMD_DEVICE_LIST = 71,
    aranya_Kind_CMD_DEVICE_ENSURE = 72,
    aranya_Kind_CMD_DEVICE_DELETE = 73,
    aranya_Kind_MSG_DONE = 100,
    aranya_Kind_MSG_STATE = 101,
    aranya_Kind_MSG_ERROR = 102,
    aranya_Kind_MSG_NODE_STATUS = 111,
    aranya_Kind_MSG_NETWORK_STATUS = 121,
    aranya_Kind_MSG_CRED_STATUS = 131,
    aranya_Kind_MSG_IMAGE_STATUS = 141,
    aranya_Kind_MSG_IMAGE_STATUS_LIST = 142,
    aranya_Kind_MSG_STORAGE_STATUS = 151,
    aranya_Kind_MSG_STORAGE_STATUS_LIST = 152,
    aranya_Kind_MSG_POD_STATUS = 161,
    aranya_Kind_MSG_POD_STATUS_LIST = 162,
    aranya_Kind_MSG_DEVICE_STATUS = 171,
    aranya_Kind_MSG_DEVICE_STATUS_LIST = 172
} aranya_Kind;

typedef enum _aranya_NodeInfoGetCmd_Kind {
    aranya_NodeInfoGetCmd_Kind_NODE_INFO_DYN = 0,
    aranya_NodeInfoGetCmd_Kind_NODE_INFO_ALL = 1
} aranya_NodeInfoGetCmd_Kind;

typedef enum _aranya_RejectCmd_Reason {
    aranya_RejectCmd_Reason__INVALID_REJECTION_REASON = 0,
    aranya_RejectCmd_Reason_REJECTION_ALREADY_CONNECTED = 1,
    aranya_RejectCmd_Reason_REJECTION_POD_STATUS_SYNC_ERROR = 2,
    aranya_RejectCmd_Reason_REJECTION_NODE_STATUS_SYNC_ERROR = 3,
    aranya_RejectCmd_Reason_REJECTION_NETWORK_UPDATE_FAILURE = 4,
    aranya_RejectCmd_Reason_REJECTION_CREDENTIAL_FAILURE = 5,
    aranya_RejectCmd_Reason_REJECTION_INTERNAL_SERVER_ERROR = 6,
    aranya_RejectCmd_Reason_REJECTION_INVALID_PROTO = 7
} aranya_RejectCmd_Reason;

typedef enum _aranya_ErrorMsg_Kind {
    aranya_ErrorMsg_Kind_ERR_COMMON = 0,
    aranya_ErrorMsg_Kind_ERR_NOT_FOUND = 1,
    aranya_ErrorMsg_Kind_ERR_ALREADY_EXISTS = 2,
    aranya_ErrorMsg_Kind_ERR_NOT_SUPPORTED = 3,
    aranya_ErrorMsg_Kind_ERR_TIMEOUT = 4
} aranya_ErrorMsg_Kind;

typedef enum _aranya_StateMsg_Kind {
    aranya_StateMsg_Kind__INVALID_STATE = 0,
    aranya_StateMsg_Kind_STATE_ONLINE = 1,
    aranya_StateMsg_Kind_STATE_OFFLINE = 2
} aranya_StateMsg_Kind;

/* Struct definitions */
typedef struct _aranya_ContainerExecOrAttachCmd_EnvsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_ContainerExecOrAttachCmd_EnvsEntry;

typedef struct _aranya_Empty {
    char dummy_field;
} aranya_Empty;

typedef struct _aranya_ContainerExecOrAttachCmd {
    pb_callback_t pod_uid;
    pb_callback_t container;
    bool stdin;
    bool stdout;
    bool stderr;
    bool tty;
    pb_callback_t command;
    pb_callback_t envs;
} aranya_ContainerExecOrAttachCmd;

typedef struct _aranya_ContainerLogsCmd {
    pb_callback_t pod_uid;
    pb_callback_t container;
    bool follow;
    bool timestamp;
    pb_callback_t since;
    int64_t tail_lines;
    int64_t bytes_limit;
    bool previous;
    pb_callback_t path;
} aranya_ContainerLogsCmd;

typedef struct _aranya_ContainerTerminalResizeCmd {
    uint32_t cols;
    uint32_t rows;
} aranya_ContainerTerminalResizeCmd;

typedef struct _aranya_ErrorMsg {
    aranya_ErrorMsg_Kind kind;
    pb_callback_t description;
    int64_t code;
} aranya_ErrorMsg;

typedef struct _aranya_Header {
    aranya_Kind kind;
    uint64_t sid;
    uint64_t seq;
    bool completed;
    uint64_t sub_seq;
} aranya_Header;

typedef struct _aranya_NodeInfoGetCmd {
    aranya_NodeInfoGetCmd_Kind kind;
} aranya_NodeInfoGetCmd;

typedef struct _aranya_PodPortForwardCmd {
    pb_callback_t pod_uid;
    int32_t port;
    pb_callback_t protocol;
} aranya_PodPortForwardCmd;

typedef struct _aranya_RejectCmd {
    aranya_RejectCmd_Reason reason;
    pb_callback_t message;
} aranya_RejectCmd;

typedef struct _aranya_SessionCloseCmd {
    uint64_t sid;
} aranya_SessionCloseCmd;

typedef struct _aranya_StateMsg {
    aranya_StateMsg_Kind kind;
    pb_callback_t device_id;
} aranya_StateMsg;

typedef struct _aranya_Cmd {
    bool has_header;
    aranya_Header header;
    pb_callback_t body;
} aranya_Cmd;

typedef struct _aranya_Msg {
    bool has_header;
    aranya_Header header;
    pb_callback_t online_id;
    pb_callback_t body;
} aranya_Msg;


/* Helper constants for enums */
#define _aranya_Kind_MIN aranya_Kind_EMPTY
#define _aranya_Kind_MAX aranya_Kind_MSG_DEVICE_STATUS_LIST
#define _aranya_Kind_ARRAYSIZE ((aranya_Kind)(aranya_Kind_MSG_DEVICE_STATUS_LIST+1))

#define _aranya_NodeInfoGetCmd_Kind_MIN aranya_NodeInfoGetCmd_Kind_NODE_INFO_DYN
#define _aranya_NodeInfoGetCmd_Kind_MAX aranya_NodeInfoGetCmd_Kind_NODE_INFO_ALL
#define _aranya_NodeInfoGetCmd_Kind_ARRAYSIZE ((aranya_NodeInfoGetCmd_Kind)(aranya_NodeInfoGetCmd_Kind_NODE_INFO_ALL+1))

#define _aranya_RejectCmd_Reason_MIN aranya_RejectCmd_Reason__INVALID_REJECTION_REASON
#define _aranya_RejectCmd_Reason_MAX aranya_RejectCmd_Reason_REJECTION_INVALID_PROTO
#define _aranya_RejectCmd_Reason_ARRAYSIZE ((aranya_RejectCmd_Reason)(aranya_RejectCmd_Reason_REJECTION_INVALID_PROTO+1))

#define _aranya_ErrorMsg_Kind_MIN aranya_ErrorMsg_Kind_ERR_COMMON
#define _aranya_ErrorMsg_Kind_MAX aranya_ErrorMsg_Kind_ERR_TIMEOUT
#define _aranya_ErrorMsg_Kind_ARRAYSIZE ((aranya_ErrorMsg_Kind)(aranya_ErrorMsg_Kind_ERR_TIMEOUT+1))

#define _aranya_StateMsg_Kind_MIN aranya_StateMsg_Kind__INVALID_STATE
#define _aranya_StateMsg_Kind_MAX aranya_StateMsg_Kind_STATE_OFFLINE
#define _aranya_StateMsg_Kind_ARRAYSIZE ((aranya_StateMsg_Kind)(aranya_StateMsg_Kind_STATE_OFFLINE+1))


/* Initializer values for message structs */
#define aranya_Empty_init_default                {0}
#define aranya_Header_init_default               {_aranya_Kind_MIN, 0, 0, 0, 0}
#define aranya_Cmd_init_default                  {false, aranya_Header_init_default, {{NULL}, NULL}}
#define aranya_Msg_init_default                  {false, aranya_Header_init_default, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_NodeInfoGetCmd_init_default       {_aranya_NodeInfoGetCmd_Kind_MIN}
#define aranya_SessionCloseCmd_init_default      {0}
#define aranya_RejectCmd_init_default            {_aranya_RejectCmd_Reason_MIN, {{NULL}, NULL}}
#define aranya_ContainerLogsCmd_init_default     {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, {{NULL}, NULL}, 0, 0, 0, {{NULL}, NULL}}
#define aranya_ContainerExecOrAttachCmd_init_default {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, 0, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_ContainerExecOrAttachCmd_EnvsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_PodPortForwardCmd_init_default    {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define aranya_ContainerTerminalResizeCmd_init_default {0, 0}
#define aranya_ErrorMsg_init_default             {_aranya_ErrorMsg_Kind_MIN, {{NULL}, NULL}, 0}
#define aranya_StateMsg_init_default             {_aranya_StateMsg_Kind_MIN, {{NULL}, NULL}}
#define aranya_Empty_init_zero                   {0}
#define aranya_Header_init_zero                  {_aranya_Kind_MIN, 0, 0, 0, 0}
#define aranya_Cmd_init_zero                     {false, aranya_Header_init_zero, {{NULL}, NULL}}
#define aranya_Msg_init_zero                     {false, aranya_Header_init_zero, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_NodeInfoGetCmd_init_zero          {_aranya_NodeInfoGetCmd_Kind_MIN}
#define aranya_SessionCloseCmd_init_zero         {0}
#define aranya_RejectCmd_init_zero               {_aranya_RejectCmd_Reason_MIN, {{NULL}, NULL}}
#define aranya_ContainerLogsCmd_init_zero        {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, {{NULL}, NULL}, 0, 0, 0, {{NULL}, NULL}}
#define aranya_ContainerExecOrAttachCmd_init_zero {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, 0, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_ContainerExecOrAttachCmd_EnvsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_PodPortForwardCmd_init_zero       {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define aranya_ContainerTerminalResizeCmd_init_zero {0, 0}
#define aranya_ErrorMsg_init_zero                {_aranya_ErrorMsg_Kind_MIN, {{NULL}, NULL}, 0}
#define aranya_StateMsg_init_zero                {_aranya_StateMsg_Kind_MIN, {{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_ContainerExecOrAttachCmd_EnvsEntry_key_tag 1
#define aranya_ContainerExecOrAttachCmd_EnvsEntry_value_tag 2
#define aranya_ContainerExecOrAttachCmd_pod_uid_tag 1
#define aranya_ContainerExecOrAttachCmd_container_tag 2
#define aranya_ContainerExecOrAttachCmd_stdin_tag 3
#define aranya_ContainerExecOrAttachCmd_stdout_tag 4
#define aranya_ContainerExecOrAttachCmd_stderr_tag 5
#define aranya_ContainerExecOrAttachCmd_tty_tag  6
#define aranya_ContainerExecOrAttachCmd_command_tag 7
#define aranya_ContainerExecOrAttachCmd_envs_tag 8
#define aranya_ContainerLogsCmd_pod_uid_tag      1
#define aranya_ContainerLogsCmd_container_tag    2
#define aranya_ContainerLogsCmd_follow_tag       3
#define aranya_ContainerLogsCmd_timestamp_tag    4
#define aranya_ContainerLogsCmd_since_tag        5
#define aranya_ContainerLogsCmd_tail_lines_tag   6
#define aranya_ContainerLogsCmd_bytes_limit_tag  7
#define aranya_ContainerLogsCmd_previous_tag     8
#define aranya_ContainerLogsCmd_path_tag         9
#define aranya_ContainerTerminalResizeCmd_cols_tag 1
#define aranya_ContainerTerminalResizeCmd_rows_tag 2
#define aranya_ErrorMsg_kind_tag                 1
#define aranya_ErrorMsg_description_tag          2
#define aranya_ErrorMsg_code_tag                 3
#define aranya_Header_kind_tag                   1
#define aranya_Header_sid_tag                    2
#define aranya_Header_seq_tag                    3
#define aranya_Header_completed_tag              4
#define aranya_Header_sub_seq_tag                5
#define aranya_NodeInfoGetCmd_kind_tag           1
#define aranya_PodPortForwardCmd_pod_uid_tag     1
#define aranya_PodPortForwardCmd_port_tag        2
#define aranya_PodPortForwardCmd_protocol_tag    3
#define aranya_RejectCmd_reason_tag              1
#define aranya_RejectCmd_message_tag             2
#define aranya_SessionCloseCmd_sid_tag           1
#define aranya_StateMsg_kind_tag                 1
#define aranya_StateMsg_device_id_tag            2
#define aranya_Cmd_header_tag                    1
#define aranya_Cmd_body_tag                      11
#define aranya_Msg_header_tag                    1
#define aranya_Msg_online_id_tag                 4
#define aranya_Msg_body_tag                      11

/* Struct field encoding specification for nanopb */
#define aranya_Empty_FIELDLIST(X, a) \

#define aranya_Empty_CALLBACK NULL
#define aranya_Empty_DEFAULT NULL

#define aranya_Header_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, STATIC,   SINGULAR, UINT64,   sid,               2) \
X(a, STATIC,   SINGULAR, UINT64,   seq,               3) \
X(a, STATIC,   SINGULAR, BOOL,     completed,         4) \
X(a, STATIC,   SINGULAR, UINT64,   sub_seq,           5)
#define aranya_Header_CALLBACK NULL
#define aranya_Header_DEFAULT NULL

#define aranya_Cmd_FIELDLIST(X, a) \
X(a, STATIC,   OPTIONAL, MESSAGE,  header,            1) \
X(a, CALLBACK, SINGULAR, BYTES,    body,             11)
#define aranya_Cmd_CALLBACK pb_default_field_callback
#define aranya_Cmd_DEFAULT NULL
#define aranya_Cmd_header_MSGTYPE aranya_Header

#define aranya_Msg_FIELDLIST(X, a) \
X(a, STATIC,   OPTIONAL, MESSAGE,  header,            1) \
X(a, CALLBACK, SINGULAR, STRING,   online_id,         4) \
X(a, CALLBACK, SINGULAR, BYTES,    body,             11)
#define aranya_Msg_CALLBACK pb_default_field_callback
#define aranya_Msg_DEFAULT NULL
#define aranya_Msg_header_MSGTYPE aranya_Header

#define aranya_NodeInfoGetCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1)
#define aranya_NodeInfoGetCmd_CALLBACK NULL
#define aranya_NodeInfoGetCmd_DEFAULT NULL

#define aranya_SessionCloseCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT64,   sid,               1)
#define aranya_SessionCloseCmd_CALLBACK NULL
#define aranya_SessionCloseCmd_DEFAULT NULL

#define aranya_RejectCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    reason,            1) \
X(a, CALLBACK, SINGULAR, STRING,   message,           2)
#define aranya_RejectCmd_CALLBACK pb_default_field_callback
#define aranya_RejectCmd_DEFAULT NULL

#define aranya_ContainerLogsCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   pod_uid,           1) \
X(a, CALLBACK, SINGULAR, STRING,   container,         2) \
X(a, STATIC,   SINGULAR, BOOL,     follow,            3) \
X(a, STATIC,   SINGULAR, BOOL,     timestamp,         4) \
X(a, CALLBACK, SINGULAR, STRING,   since,             5) \
X(a, STATIC,   SINGULAR, INT64,    tail_lines,        6) \
X(a, STATIC,   SINGULAR, INT64,    bytes_limit,       7) \
X(a, STATIC,   SINGULAR, BOOL,     previous,          8) \
X(a, CALLBACK, SINGULAR, STRING,   path,              9)
#define aranya_ContainerLogsCmd_CALLBACK pb_default_field_callback
#define aranya_ContainerLogsCmd_DEFAULT NULL

#define aranya_ContainerExecOrAttachCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   pod_uid,           1) \
X(a, CALLBACK, SINGULAR, STRING,   container,         2) \
X(a, STATIC,   SINGULAR, BOOL,     stdin,             3) \
X(a, STATIC,   SINGULAR, BOOL,     stdout,            4) \
X(a, STATIC,   SINGULAR, BOOL,     stderr,            5) \
X(a, STATIC,   SINGULAR, BOOL,     tty,               6) \
X(a, CALLBACK, REPEATED, STRING,   command,           7) \
X(a, CALLBACK, REPEATED, MESSAGE,  envs,              8)
#define aranya_ContainerExecOrAttachCmd_CALLBACK pb_default_field_callback
#define aranya_ContainerExecOrAttachCmd_DEFAULT NULL
#define aranya_ContainerExecOrAttachCmd_envs_MSGTYPE aranya_ContainerExecOrAttachCmd_EnvsEntry

#define aranya_ContainerExecOrAttachCmd_EnvsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_ContainerExecOrAttachCmd_EnvsEntry_CALLBACK pb_default_field_callback
#define aranya_ContainerExecOrAttachCmd_EnvsEntry_DEFAULT NULL

#define aranya_PodPortForwardCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   pod_uid,           1) \
X(a, STATIC,   SINGULAR, INT32,    port,              2) \
X(a, CALLBACK, SINGULAR, STRING,   protocol,          3)
#define aranya_PodPortForwardCmd_CALLBACK pb_default_field_callback
#define aranya_PodPortForwardCmd_DEFAULT NULL

#define aranya_ContainerTerminalResizeCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   cols,              1) \
X(a, STATIC,   SINGULAR, UINT32,   rows,              2)
#define aranya_ContainerTerminalResizeCmd_CALLBACK NULL
#define aranya_ContainerTerminalResizeCmd_DEFAULT NULL

#define aranya_ErrorMsg_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, CALLBACK, SINGULAR, STRING,   description,       2) \
X(a, STATIC,   SINGULAR, INT64,    code,              3)
#define aranya_ErrorMsg_CALLBACK pb_default_field_callback
#define aranya_ErrorMsg_DEFAULT NULL

#define aranya_StateMsg_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, CALLBACK, SINGULAR, STRING,   device_id,         2)
#define aranya_StateMsg_CALLBACK pb_default_field_callback
#define aranya_StateMsg_DEFAULT NULL

extern const pb_msgdesc_t aranya_Empty_msg;
extern const pb_msgdesc_t aranya_Header_msg;
extern const pb_msgdesc_t aranya_Cmd_msg;
extern const pb_msgdesc_t aranya_Msg_msg;
extern const pb_msgdesc_t aranya_NodeInfoGetCmd_msg;
extern const pb_msgdesc_t aranya_SessionCloseCmd_msg;
extern const pb_msgdesc_t aranya_RejectCmd_msg;
extern const pb_msgdesc_t aranya_ContainerLogsCmd_msg;
extern const pb_msgdesc_t aranya_ContainerExecOrAttachCmd_msg;
extern const pb_msgdesc_t aranya_ContainerExecOrAttachCmd_EnvsEntry_msg;
extern const pb_msgdesc_t aranya_PodPortForwardCmd_msg;
extern const pb_msgdesc_t aranya_ContainerTerminalResizeCmd_msg;
extern const pb_msgdesc_t aranya_ErrorMsg_msg;
extern const pb_msgdesc_t aranya_StateMsg_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_Empty_fields &aranya_Empty_msg
#define aranya_Header_fields &aranya_Header_msg
#define aranya_Cmd_fields &aranya_Cmd_msg
#define aranya_Msg_fields &aranya_Msg_msg
#define aranya_NodeInfoGetCmd_fields &aranya_NodeInfoGetCmd_msg
#define aranya_SessionCloseCmd_fields &aranya_SessionCloseCmd_msg
#define aranya_RejectCmd_fields &aranya_RejectCmd_msg
#define aranya_ContainerLogsCmd_fields &aranya_ContainerLogsCmd_msg
#define aranya_ContainerExecOrAttachCmd_fields &aranya_ContainerExecOrAttachCmd_msg
#define aranya_ContainerExecOrAttachCmd_EnvsEntry_fields &aranya_ContainerExecOrAttachCmd_EnvsEntry_msg
#define aranya_PodPortForwardCmd_fields &aranya_PodPortForwardCmd_msg
#define aranya_ContainerTerminalResizeCmd_fields &aranya_ContainerTerminalResizeCmd_msg
#define aranya_ErrorMsg_fields &aranya_ErrorMsg_msg
#define aranya_StateMsg_fields &aranya_StateMsg_msg

/* Maximum encoded size of messages (where known) */
#define aranya_Empty_size                        0
#define aranya_Header_size                       38
/* aranya_Cmd_size depends on runtime parameters */
/* aranya_Msg_size depends on runtime parameters */
#define aranya_NodeInfoGetCmd_size               2
#define aranya_SessionCloseCmd_size              11
/* aranya_RejectCmd_size depends on runtime parameters */
/* aranya_ContainerLogsCmd_size depends on runtime parameters */
/* aranya_ContainerExecOrAttachCmd_size depends on runtime parameters */
/* aranya_ContainerExecOrAttachCmd_EnvsEntry_size depends on runtime parameters */
/* aranya_PodPortForwardCmd_size depends on runtime parameters */
#define aranya_ContainerTerminalResizeCmd_size   12
/* aranya_ErrorMsg_size depends on runtime parameters */
/* aranya_StateMsg_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
