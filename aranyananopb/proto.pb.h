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
typedef enum _aranya_CmdType {
    aranya_CmdType_CMD_DATA_UPSTREAM = 0,
    aranya_CmdType_CMD_SESSION_CLOSE = 5,
    aranya_CmdType_CMD_REJECT = 6,
    aranya_CmdType_CMD_NET = 10,
    aranya_CmdType_CMD_NODE_INFO_GET = 11,
    aranya_CmdType_CMD_EXEC = 12,
    aranya_CmdType_CMD_ATTACH = 13,
    aranya_CmdType_CMD_LOGS = 14,
    aranya_CmdType_CMD_TTY_RESIZE = 15,
    aranya_CmdType_CMD_PORT_FORWARD = 16,
    aranya_CmdType_CMD_METRICS_CONFIG = 21,
    aranya_CmdType_CMD_METRICS_COLLECT = 22,
    aranya_CmdType_CMD_CRED_ENSURE = 31,
    aranya_CmdType_CMD_IMAGE_LIST = 41,
    aranya_CmdType_CMD_IMAGE_ENSURE = 42,
    aranya_CmdType_CMD_IMAGE_DELETE = 43,
    aranya_CmdType_CMD_STORAGE_LIST = 51,
    aranya_CmdType_CMD_STORAGE_ENSURE = 52,
    aranya_CmdType_CMD_STORAGE_DELETE = 53,
    aranya_CmdType_CMD_POD_LIST = 61,
    aranya_CmdType_CMD_POD_ENSURE = 62,
    aranya_CmdType_CMD_POD_DELETE = 63,
    aranya_CmdType_CMD_PERIPHERAL_LIST = 71,
    aranya_CmdType_CMD_PERIPHERAL_ENSURE = 72,
    aranya_CmdType_CMD_PERIPHERAL_DELETE = 73,
    aranya_CmdType_CMD_PERIPHERAL_OPERATE = 74,
    aranya_CmdType_CMD_PERIPHERAL_COLLECT_METRICS = 75
} aranya_CmdType;

typedef enum _aranya_MsgType {
    aranya_MsgType_MSG_DATA = 0,
    aranya_MsgType_MSG_DATA_DEFAULT = 0,
    aranya_MsgType_MSG_DATA_STDOUT = 0,
    aranya_MsgType_MSG_DATA_METRICS = 0,
    aranya_MsgType_MSG_DATA_STDERR = 1,
    aranya_MsgType_MSG_DONE = 5,
    aranya_MsgType_MSG_STATE = 6,
    aranya_MsgType_MSG_ERROR = 7,
    aranya_MsgType_MSG_NET = 10,
    aranya_MsgType_MSG_NODE_STATUS = 11,
    aranya_MsgType_MSG_CRED_STATUS = 31,
    aranya_MsgType_MSG_IMAGE_STATUS = 41,
    aranya_MsgType_MSG_IMAGE_STATUS_LIST = 42,
    aranya_MsgType_MSG_STORAGE_STATUS = 51,
    aranya_MsgType_MSG_STORAGE_STATUS_LIST = 52,
    aranya_MsgType_MSG_POD_STATUS = 61,
    aranya_MsgType_MSG_POD_STATUS_LIST = 62,
    aranya_MsgType_MSG_PERIPHERAL_STATUS = 71,
    aranya_MsgType_MSG_PERIPHERAL_STATUS_LIST = 72,
    aranya_MsgType_MSG_PERIPHERAL_OPERATION_RESULT = 73
} aranya_MsgType;

typedef enum _aranya_RejectionReason {
    aranya_RejectionReason__INVALID_REJECTION_REASON = 0,
    aranya_RejectionReason_REJECTION_INVALID_PROTO = 1,
    aranya_RejectionReason_REJECTION_ALREADY_CONNECTED = 2,
    aranya_RejectionReason_REJECTION_INITIAL_CHECK_FAILURE = 3,
    aranya_RejectionReason_REJECTION_INTERNAL_SERVER_ERROR = 4
} aranya_RejectionReason;

typedef enum _aranya_NodeInfoGetCmd_Kind {
    aranya_NodeInfoGetCmd_Kind_NODE_INFO_DYN = 0,
    aranya_NodeInfoGetCmd_Kind_NODE_INFO_ALL = 1
} aranya_NodeInfoGetCmd_Kind;

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
typedef struct _aranya_Empty {
    char dummy_field;
} aranya_Empty;

typedef struct _aranya_ExecOrAttachCmd_EnvsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_ExecOrAttachCmd_EnvsEntry;

typedef struct _aranya_NetworkCmd {
    pb_callback_t payload;
} aranya_NetworkCmd;

typedef struct _aranya_NetworkMsg {
    pb_callback_t payload;
} aranya_NetworkMsg;

typedef struct _aranya_Cmd {
    aranya_CmdType kind;
    uint64_t sid;
    uint64_t seq;
    bool completed;
    pb_callback_t body;
} aranya_Cmd;

typedef struct _aranya_ErrorMsg {
    aranya_ErrorMsg_Kind kind;
    pb_callback_t description;
    int64_t code;
} aranya_ErrorMsg;

typedef struct _aranya_ExecOrAttachCmd {
    pb_callback_t pod_uid;
    pb_callback_t container;
    bool stdin;
    bool stdout;
    bool stderr;
    bool tty;
    pb_callback_t command;
    pb_callback_t envs;
} aranya_ExecOrAttachCmd;

typedef struct _aranya_LogsCmd {
    pb_callback_t pod_uid;
    pb_callback_t container;
    bool follow;
    bool timestamp;
    pb_callback_t since;
    int64_t tail_lines;
    int64_t bytes_limit;
    bool previous;
    pb_callback_t path;
} aranya_LogsCmd;

typedef struct _aranya_Msg {
    aranya_MsgType kind;
    uint64_t sid;
    uint64_t seq;
    bool completed;
    pb_callback_t body;
} aranya_Msg;

typedef struct _aranya_NodeInfoGetCmd {
    aranya_NodeInfoGetCmd_Kind kind;
} aranya_NodeInfoGetCmd;

typedef struct _aranya_PortForwardCmd {
    pb_callback_t pod_uid;
    int32_t port;
    pb_callback_t protocol;
} aranya_PortForwardCmd;

typedef struct _aranya_RejectCmd {
    aranya_RejectionReason reason;
    pb_callback_t message;
} aranya_RejectCmd;

typedef struct _aranya_SessionCloseCmd {
    uint64_t sid;
} aranya_SessionCloseCmd;

typedef struct _aranya_StateMsg {
    aranya_StateMsg_Kind kind;
    pb_callback_t device_id;
} aranya_StateMsg;

typedef struct _aranya_TerminalResizeCmd {
    uint32_t cols;
    uint32_t rows;
} aranya_TerminalResizeCmd;


/* Helper constants for enums */
#define _aranya_CmdType_MIN aranya_CmdType_CMD_DATA_UPSTREAM
#define _aranya_CmdType_MAX aranya_CmdType_CMD_PERIPHERAL_COLLECT_METRICS
#define _aranya_CmdType_ARRAYSIZE ((aranya_CmdType)(aranya_CmdType_CMD_PERIPHERAL_COLLECT_METRICS+1))

#define _aranya_MsgType_MIN aranya_MsgType_MSG_DATA
#define _aranya_MsgType_MAX aranya_MsgType_MSG_PERIPHERAL_OPERATION_RESULT
#define _aranya_MsgType_ARRAYSIZE ((aranya_MsgType)(aranya_MsgType_MSG_PERIPHERAL_OPERATION_RESULT+1))

#define _aranya_RejectionReason_MIN aranya_RejectionReason__INVALID_REJECTION_REASON
#define _aranya_RejectionReason_MAX aranya_RejectionReason_REJECTION_INTERNAL_SERVER_ERROR
#define _aranya_RejectionReason_ARRAYSIZE ((aranya_RejectionReason)(aranya_RejectionReason_REJECTION_INTERNAL_SERVER_ERROR+1))

#define _aranya_NodeInfoGetCmd_Kind_MIN aranya_NodeInfoGetCmd_Kind_NODE_INFO_DYN
#define _aranya_NodeInfoGetCmd_Kind_MAX aranya_NodeInfoGetCmd_Kind_NODE_INFO_ALL
#define _aranya_NodeInfoGetCmd_Kind_ARRAYSIZE ((aranya_NodeInfoGetCmd_Kind)(aranya_NodeInfoGetCmd_Kind_NODE_INFO_ALL+1))

#define _aranya_ErrorMsg_Kind_MIN aranya_ErrorMsg_Kind_ERR_COMMON
#define _aranya_ErrorMsg_Kind_MAX aranya_ErrorMsg_Kind_ERR_TIMEOUT
#define _aranya_ErrorMsg_Kind_ARRAYSIZE ((aranya_ErrorMsg_Kind)(aranya_ErrorMsg_Kind_ERR_TIMEOUT+1))

#define _aranya_StateMsg_Kind_MIN aranya_StateMsg_Kind__INVALID_STATE
#define _aranya_StateMsg_Kind_MAX aranya_StateMsg_Kind_STATE_OFFLINE
#define _aranya_StateMsg_Kind_ARRAYSIZE ((aranya_StateMsg_Kind)(aranya_StateMsg_Kind_STATE_OFFLINE+1))


/* Initializer values for message structs */
#define aranya_Empty_init_default                {0}
#define aranya_Cmd_init_default                  {_aranya_CmdType_MIN, 0, 0, 0, {{NULL}, NULL}}
#define aranya_Msg_init_default                  {_aranya_MsgType_MIN, 0, 0, 0, {{NULL}, NULL}}
#define aranya_NodeInfoGetCmd_init_default       {_aranya_NodeInfoGetCmd_Kind_MIN}
#define aranya_SessionCloseCmd_init_default      {0}
#define aranya_RejectCmd_init_default            {_aranya_RejectionReason_MIN, {{NULL}, NULL}}
#define aranya_NetworkCmd_init_default           {{{NULL}, NULL}}
#define aranya_LogsCmd_init_default              {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, {{NULL}, NULL}, 0, 0, 0, {{NULL}, NULL}}
#define aranya_ExecOrAttachCmd_init_default      {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, 0, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_ExecOrAttachCmd_EnvsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_PortForwardCmd_init_default       {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define aranya_TerminalResizeCmd_init_default    {0, 0}
#define aranya_ErrorMsg_init_default             {_aranya_ErrorMsg_Kind_MIN, {{NULL}, NULL}, 0}
#define aranya_StateMsg_init_default             {_aranya_StateMsg_Kind_MIN, {{NULL}, NULL}}
#define aranya_NetworkMsg_init_default           {{{NULL}, NULL}}
#define aranya_Empty_init_zero                   {0}
#define aranya_Cmd_init_zero                     {_aranya_CmdType_MIN, 0, 0, 0, {{NULL}, NULL}}
#define aranya_Msg_init_zero                     {_aranya_MsgType_MIN, 0, 0, 0, {{NULL}, NULL}}
#define aranya_NodeInfoGetCmd_init_zero          {_aranya_NodeInfoGetCmd_Kind_MIN}
#define aranya_SessionCloseCmd_init_zero         {0}
#define aranya_RejectCmd_init_zero               {_aranya_RejectionReason_MIN, {{NULL}, NULL}}
#define aranya_NetworkCmd_init_zero              {{{NULL}, NULL}}
#define aranya_LogsCmd_init_zero                 {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, {{NULL}, NULL}, 0, 0, 0, {{NULL}, NULL}}
#define aranya_ExecOrAttachCmd_init_zero         {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, 0, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_ExecOrAttachCmd_EnvsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_PortForwardCmd_init_zero          {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define aranya_TerminalResizeCmd_init_zero       {0, 0}
#define aranya_ErrorMsg_init_zero                {_aranya_ErrorMsg_Kind_MIN, {{NULL}, NULL}, 0}
#define aranya_StateMsg_init_zero                {_aranya_StateMsg_Kind_MIN, {{NULL}, NULL}}
#define aranya_NetworkMsg_init_zero              {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_ExecOrAttachCmd_EnvsEntry_key_tag 1
#define aranya_ExecOrAttachCmd_EnvsEntry_value_tag 2
#define aranya_NetworkCmd_payload_tag            1
#define aranya_NetworkMsg_payload_tag            1
#define aranya_Cmd_kind_tag                      1
#define aranya_Cmd_sid_tag                       2
#define aranya_Cmd_seq_tag                       3
#define aranya_Cmd_completed_tag                 4
#define aranya_Cmd_body_tag                      11
#define aranya_ErrorMsg_kind_tag                 1
#define aranya_ErrorMsg_description_tag          2
#define aranya_ErrorMsg_code_tag                 3
#define aranya_ExecOrAttachCmd_pod_uid_tag       1
#define aranya_ExecOrAttachCmd_container_tag     2
#define aranya_ExecOrAttachCmd_stdin_tag         3
#define aranya_ExecOrAttachCmd_stdout_tag        4
#define aranya_ExecOrAttachCmd_stderr_tag        5
#define aranya_ExecOrAttachCmd_tty_tag           6
#define aranya_ExecOrAttachCmd_command_tag       7
#define aranya_ExecOrAttachCmd_envs_tag          8
#define aranya_LogsCmd_pod_uid_tag               1
#define aranya_LogsCmd_container_tag             2
#define aranya_LogsCmd_follow_tag                3
#define aranya_LogsCmd_timestamp_tag             4
#define aranya_LogsCmd_since_tag                 5
#define aranya_LogsCmd_tail_lines_tag            6
#define aranya_LogsCmd_bytes_limit_tag           7
#define aranya_LogsCmd_previous_tag              8
#define aranya_LogsCmd_path_tag                  9
#define aranya_Msg_kind_tag                      1
#define aranya_Msg_sid_tag                       2
#define aranya_Msg_seq_tag                       3
#define aranya_Msg_completed_tag                 4
#define aranya_Msg_body_tag                      11
#define aranya_NodeInfoGetCmd_kind_tag           1
#define aranya_PortForwardCmd_pod_uid_tag        1
#define aranya_PortForwardCmd_port_tag           2
#define aranya_PortForwardCmd_protocol_tag       3
#define aranya_RejectCmd_reason_tag              1
#define aranya_RejectCmd_message_tag             2
#define aranya_SessionCloseCmd_sid_tag           1
#define aranya_StateMsg_kind_tag                 1
#define aranya_StateMsg_device_id_tag            2
#define aranya_TerminalResizeCmd_cols_tag        1
#define aranya_TerminalResizeCmd_rows_tag        2

/* Struct field encoding specification for nanopb */
#define aranya_Empty_FIELDLIST(X, a) \

#define aranya_Empty_CALLBACK NULL
#define aranya_Empty_DEFAULT NULL

#define aranya_Cmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, STATIC,   SINGULAR, UINT64,   sid,               2) \
X(a, STATIC,   SINGULAR, UINT64,   seq,               3) \
X(a, STATIC,   SINGULAR, BOOL,     completed,         4) \
X(a, CALLBACK, SINGULAR, BYTES,    body,             11)
#define aranya_Cmd_CALLBACK pb_default_field_callback
#define aranya_Cmd_DEFAULT NULL

#define aranya_Msg_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, STATIC,   SINGULAR, UINT64,   sid,               2) \
X(a, STATIC,   SINGULAR, UINT64,   seq,               3) \
X(a, STATIC,   SINGULAR, BOOL,     completed,         4) \
X(a, CALLBACK, SINGULAR, BYTES,    body,             11)
#define aranya_Msg_CALLBACK pb_default_field_callback
#define aranya_Msg_DEFAULT NULL

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

#define aranya_NetworkCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, BYTES,    payload,           1)
#define aranya_NetworkCmd_CALLBACK pb_default_field_callback
#define aranya_NetworkCmd_DEFAULT NULL

#define aranya_LogsCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   pod_uid,           1) \
X(a, CALLBACK, SINGULAR, STRING,   container,         2) \
X(a, STATIC,   SINGULAR, BOOL,     follow,            3) \
X(a, STATIC,   SINGULAR, BOOL,     timestamp,         4) \
X(a, CALLBACK, SINGULAR, STRING,   since,             5) \
X(a, STATIC,   SINGULAR, INT64,    tail_lines,        6) \
X(a, STATIC,   SINGULAR, INT64,    bytes_limit,       7) \
X(a, STATIC,   SINGULAR, BOOL,     previous,          8) \
X(a, CALLBACK, SINGULAR, STRING,   path,              9)
#define aranya_LogsCmd_CALLBACK pb_default_field_callback
#define aranya_LogsCmd_DEFAULT NULL

#define aranya_ExecOrAttachCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   pod_uid,           1) \
X(a, CALLBACK, SINGULAR, STRING,   container,         2) \
X(a, STATIC,   SINGULAR, BOOL,     stdin,             3) \
X(a, STATIC,   SINGULAR, BOOL,     stdout,            4) \
X(a, STATIC,   SINGULAR, BOOL,     stderr,            5) \
X(a, STATIC,   SINGULAR, BOOL,     tty,               6) \
X(a, CALLBACK, REPEATED, STRING,   command,           7) \
X(a, CALLBACK, REPEATED, MESSAGE,  envs,              8)
#define aranya_ExecOrAttachCmd_CALLBACK pb_default_field_callback
#define aranya_ExecOrAttachCmd_DEFAULT NULL
#define aranya_ExecOrAttachCmd_envs_MSGTYPE aranya_ExecOrAttachCmd_EnvsEntry

#define aranya_ExecOrAttachCmd_EnvsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_ExecOrAttachCmd_EnvsEntry_CALLBACK pb_default_field_callback
#define aranya_ExecOrAttachCmd_EnvsEntry_DEFAULT NULL

#define aranya_PortForwardCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   pod_uid,           1) \
X(a, STATIC,   SINGULAR, INT32,    port,              2) \
X(a, CALLBACK, SINGULAR, STRING,   protocol,          3)
#define aranya_PortForwardCmd_CALLBACK pb_default_field_callback
#define aranya_PortForwardCmd_DEFAULT NULL

#define aranya_TerminalResizeCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   cols,              1) \
X(a, STATIC,   SINGULAR, UINT32,   rows,              2)
#define aranya_TerminalResizeCmd_CALLBACK NULL
#define aranya_TerminalResizeCmd_DEFAULT NULL

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

#define aranya_NetworkMsg_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, BYTES,    payload,           1)
#define aranya_NetworkMsg_CALLBACK pb_default_field_callback
#define aranya_NetworkMsg_DEFAULT NULL

extern const pb_msgdesc_t aranya_Empty_msg;
extern const pb_msgdesc_t aranya_Cmd_msg;
extern const pb_msgdesc_t aranya_Msg_msg;
extern const pb_msgdesc_t aranya_NodeInfoGetCmd_msg;
extern const pb_msgdesc_t aranya_SessionCloseCmd_msg;
extern const pb_msgdesc_t aranya_RejectCmd_msg;
extern const pb_msgdesc_t aranya_NetworkCmd_msg;
extern const pb_msgdesc_t aranya_LogsCmd_msg;
extern const pb_msgdesc_t aranya_ExecOrAttachCmd_msg;
extern const pb_msgdesc_t aranya_ExecOrAttachCmd_EnvsEntry_msg;
extern const pb_msgdesc_t aranya_PortForwardCmd_msg;
extern const pb_msgdesc_t aranya_TerminalResizeCmd_msg;
extern const pb_msgdesc_t aranya_ErrorMsg_msg;
extern const pb_msgdesc_t aranya_StateMsg_msg;
extern const pb_msgdesc_t aranya_NetworkMsg_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_Empty_fields &aranya_Empty_msg
#define aranya_Cmd_fields &aranya_Cmd_msg
#define aranya_Msg_fields &aranya_Msg_msg
#define aranya_NodeInfoGetCmd_fields &aranya_NodeInfoGetCmd_msg
#define aranya_SessionCloseCmd_fields &aranya_SessionCloseCmd_msg
#define aranya_RejectCmd_fields &aranya_RejectCmd_msg
#define aranya_NetworkCmd_fields &aranya_NetworkCmd_msg
#define aranya_LogsCmd_fields &aranya_LogsCmd_msg
#define aranya_ExecOrAttachCmd_fields &aranya_ExecOrAttachCmd_msg
#define aranya_ExecOrAttachCmd_EnvsEntry_fields &aranya_ExecOrAttachCmd_EnvsEntry_msg
#define aranya_PortForwardCmd_fields &aranya_PortForwardCmd_msg
#define aranya_TerminalResizeCmd_fields &aranya_TerminalResizeCmd_msg
#define aranya_ErrorMsg_fields &aranya_ErrorMsg_msg
#define aranya_StateMsg_fields &aranya_StateMsg_msg
#define aranya_NetworkMsg_fields &aranya_NetworkMsg_msg

/* Maximum encoded size of messages (where known) */
#define aranya_Empty_size                        0
/* aranya_Cmd_size depends on runtime parameters */
/* aranya_Msg_size depends on runtime parameters */
#define aranya_NodeInfoGetCmd_size               2
#define aranya_SessionCloseCmd_size              11
/* aranya_RejectCmd_size depends on runtime parameters */
/* aranya_NetworkCmd_size depends on runtime parameters */
/* aranya_LogsCmd_size depends on runtime parameters */
/* aranya_ExecOrAttachCmd_size depends on runtime parameters */
/* aranya_ExecOrAttachCmd_EnvsEntry_size depends on runtime parameters */
/* aranya_PortForwardCmd_size depends on runtime parameters */
#define aranya_TerminalResizeCmd_size            12
/* aranya_ErrorMsg_size depends on runtime parameters */
/* aranya_StateMsg_size depends on runtime parameters */
/* aranya_NetworkMsg_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
