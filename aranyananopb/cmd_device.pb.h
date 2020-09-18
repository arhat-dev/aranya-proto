/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_CMD_DEVICE_PB_H_INCLUDED
#define PB_ARANYA_CMD_DEVICE_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _aranya_DeviceMetrics_UploadMethod {
    aranya_DeviceMetrics_UploadMethod_UPLOAD_WITH_NODE_METRICS = 0,
    aranya_DeviceMetrics_UploadMethod_UPLOAD_WITH_ARHAT_CONNECTIVITY = 1,
    aranya_DeviceMetrics_UploadMethod_UPLOAD_WITH_STANDALONE_CLIENT = 2
} aranya_DeviceMetrics_UploadMethod;

typedef enum _aranya_DeviceConnectivity_Mode {
    aranya_DeviceConnectivity_Mode_DEVICE_CONNECTIVITY_MODE_CLIENT = 0,
    aranya_DeviceConnectivity_Mode_DEVICE_CONNECTIVITY_MODE_SERVER = 1
} aranya_DeviceConnectivity_Mode;

/* Struct definitions */
typedef struct _aranya_DeviceConnectivityTLSConfig {
    pb_callback_t ca_cert;
    pb_callback_t cert;
    pb_callback_t key;
} aranya_DeviceConnectivityTLSConfig;

typedef struct _aranya_DeviceConnectivity_ParamsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_DeviceConnectivity_ParamsEntry;

typedef struct _aranya_DeviceDeleteCmd {
    pb_callback_t device_ids;
} aranya_DeviceDeleteCmd;

typedef struct _aranya_DeviceListCmd {
    char dummy_field;
} aranya_DeviceListCmd;

typedef struct _aranya_DeviceMetrics_TransportParamsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_DeviceMetrics_TransportParamsEntry;

typedef struct _aranya_DeviceMetrics_UploadParamsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_DeviceMetrics_UploadParamsEntry;

typedef struct _aranya_DeviceOperation {
    pb_callback_t id;
    pb_callback_t transport_params;
} aranya_DeviceOperation;

typedef struct _aranya_DeviceOperation_TransportParamsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_DeviceOperation_TransportParamsEntry;

typedef struct _aranya_DeviceConnectivity {
    pb_callback_t transport;
    aranya_DeviceConnectivity_Mode mode;
    pb_callback_t target;
    pb_callback_t params;
    bool has_tls;
    aranya_DeviceConnectivityTLSConfig tls;
} aranya_DeviceConnectivity;

typedef struct _aranya_DeviceMetrics {
    pb_callback_t name;
    pb_callback_t transport_params;
    aranya_DeviceMetrics_UploadMethod upload_method;
    pb_callback_t upload_params;
} aranya_DeviceMetrics;

typedef struct _aranya_DeviceEnsureCmd {
    pb_callback_t device_id;
    bool has_device_connectivity;
    aranya_DeviceConnectivity device_connectivity;
    bool has_upload_connectivity;
    aranya_DeviceConnectivity upload_connectivity;
    pb_callback_t device_operations;
    pb_callback_t device_metrics;
} aranya_DeviceEnsureCmd;


/* Helper constants for enums */
#define _aranya_DeviceMetrics_UploadMethod_MIN aranya_DeviceMetrics_UploadMethod_UPLOAD_WITH_NODE_METRICS
#define _aranya_DeviceMetrics_UploadMethod_MAX aranya_DeviceMetrics_UploadMethod_UPLOAD_WITH_STANDALONE_CLIENT
#define _aranya_DeviceMetrics_UploadMethod_ARRAYSIZE ((aranya_DeviceMetrics_UploadMethod)(aranya_DeviceMetrics_UploadMethod_UPLOAD_WITH_STANDALONE_CLIENT+1))

#define _aranya_DeviceConnectivity_Mode_MIN aranya_DeviceConnectivity_Mode_DEVICE_CONNECTIVITY_MODE_CLIENT
#define _aranya_DeviceConnectivity_Mode_MAX aranya_DeviceConnectivity_Mode_DEVICE_CONNECTIVITY_MODE_SERVER
#define _aranya_DeviceConnectivity_Mode_ARRAYSIZE ((aranya_DeviceConnectivity_Mode)(aranya_DeviceConnectivity_Mode_DEVICE_CONNECTIVITY_MODE_SERVER+1))


/* Initializer values for message structs */
#define aranya_DeviceOperation_init_default      {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceOperation_TransportParamsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetrics_init_default        {{{NULL}, NULL}, {{NULL}, NULL}, _aranya_DeviceMetrics_UploadMethod_MIN, {{NULL}, NULL}}
#define aranya_DeviceMetrics_TransportParamsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetrics_UploadParamsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceConnectivityTLSConfig_init_default {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceConnectivity_init_default   {{{NULL}, NULL}, _aranya_DeviceConnectivity_Mode_MIN, {{NULL}, NULL}, {{NULL}, NULL}, false, aranya_DeviceConnectivityTLSConfig_init_default}
#define aranya_DeviceConnectivity_ParamsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceEnsureCmd_init_default      {{{NULL}, NULL}, false, aranya_DeviceConnectivity_init_default, false, aranya_DeviceConnectivity_init_default, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceListCmd_init_default        {0}
#define aranya_DeviceDeleteCmd_init_default      {{{NULL}, NULL}}
#define aranya_DeviceOperation_init_zero         {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceOperation_TransportParamsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetrics_init_zero           {{{NULL}, NULL}, {{NULL}, NULL}, _aranya_DeviceMetrics_UploadMethod_MIN, {{NULL}, NULL}}
#define aranya_DeviceMetrics_TransportParamsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetrics_UploadParamsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceConnectivityTLSConfig_init_zero {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceConnectivity_init_zero      {{{NULL}, NULL}, _aranya_DeviceConnectivity_Mode_MIN, {{NULL}, NULL}, {{NULL}, NULL}, false, aranya_DeviceConnectivityTLSConfig_init_zero}
#define aranya_DeviceConnectivity_ParamsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceEnsureCmd_init_zero         {{{NULL}, NULL}, false, aranya_DeviceConnectivity_init_zero, false, aranya_DeviceConnectivity_init_zero, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceListCmd_init_zero           {0}
#define aranya_DeviceDeleteCmd_init_zero         {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_DeviceConnectivityTLSConfig_ca_cert_tag 1
#define aranya_DeviceConnectivityTLSConfig_cert_tag 2
#define aranya_DeviceConnectivityTLSConfig_key_tag 3
#define aranya_DeviceConnectivity_ParamsEntry_key_tag 1
#define aranya_DeviceConnectivity_ParamsEntry_value_tag 2
#define aranya_DeviceDeleteCmd_device_ids_tag    1
#define aranya_DeviceMetrics_TransportParamsEntry_key_tag 1
#define aranya_DeviceMetrics_TransportParamsEntry_value_tag 2
#define aranya_DeviceMetrics_UploadParamsEntry_key_tag 1
#define aranya_DeviceMetrics_UploadParamsEntry_value_tag 2
#define aranya_DeviceOperation_id_tag            1
#define aranya_DeviceOperation_transport_params_tag 2
#define aranya_DeviceOperation_TransportParamsEntry_key_tag 1
#define aranya_DeviceOperation_TransportParamsEntry_value_tag 2
#define aranya_DeviceConnectivity_transport_tag  1
#define aranya_DeviceConnectivity_mode_tag       2
#define aranya_DeviceConnectivity_target_tag     3
#define aranya_DeviceConnectivity_params_tag     4
#define aranya_DeviceConnectivity_tls_tag        5
#define aranya_DeviceMetrics_name_tag            1
#define aranya_DeviceMetrics_transport_params_tag 2
#define aranya_DeviceMetrics_upload_method_tag   3
#define aranya_DeviceMetrics_upload_params_tag   4
#define aranya_DeviceEnsureCmd_device_id_tag     1
#define aranya_DeviceEnsureCmd_device_connectivity_tag 2
#define aranya_DeviceEnsureCmd_upload_connectivity_tag 3
#define aranya_DeviceEnsureCmd_device_operations_tag 4
#define aranya_DeviceEnsureCmd_device_metrics_tag 5

/* Struct field encoding specification for nanopb */
#define aranya_DeviceOperation_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   id,                1) \
X(a, CALLBACK, REPEATED, MESSAGE,  transport_params,   2)
#define aranya_DeviceOperation_CALLBACK pb_default_field_callback
#define aranya_DeviceOperation_DEFAULT NULL
#define aranya_DeviceOperation_transport_params_MSGTYPE aranya_DeviceOperation_TransportParamsEntry

#define aranya_DeviceOperation_TransportParamsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_DeviceOperation_TransportParamsEntry_CALLBACK pb_default_field_callback
#define aranya_DeviceOperation_TransportParamsEntry_DEFAULT NULL

#define aranya_DeviceMetrics_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   name,              1) \
X(a, CALLBACK, REPEATED, MESSAGE,  transport_params,   2) \
X(a, STATIC,   SINGULAR, UENUM,    upload_method,     3) \
X(a, CALLBACK, REPEATED, MESSAGE,  upload_params,     4)
#define aranya_DeviceMetrics_CALLBACK pb_default_field_callback
#define aranya_DeviceMetrics_DEFAULT NULL
#define aranya_DeviceMetrics_transport_params_MSGTYPE aranya_DeviceMetrics_TransportParamsEntry
#define aranya_DeviceMetrics_upload_params_MSGTYPE aranya_DeviceMetrics_UploadParamsEntry

#define aranya_DeviceMetrics_TransportParamsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_DeviceMetrics_TransportParamsEntry_CALLBACK pb_default_field_callback
#define aranya_DeviceMetrics_TransportParamsEntry_DEFAULT NULL

#define aranya_DeviceMetrics_UploadParamsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_DeviceMetrics_UploadParamsEntry_CALLBACK pb_default_field_callback
#define aranya_DeviceMetrics_UploadParamsEntry_DEFAULT NULL

#define aranya_DeviceConnectivityTLSConfig_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, BYTES,    ca_cert,           1) \
X(a, CALLBACK, SINGULAR, BYTES,    cert,              2) \
X(a, CALLBACK, SINGULAR, BYTES,    key,               3)
#define aranya_DeviceConnectivityTLSConfig_CALLBACK pb_default_field_callback
#define aranya_DeviceConnectivityTLSConfig_DEFAULT NULL

#define aranya_DeviceConnectivity_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   transport,         1) \
X(a, STATIC,   SINGULAR, UENUM,    mode,              2) \
X(a, CALLBACK, SINGULAR, STRING,   target,            3) \
X(a, CALLBACK, REPEATED, MESSAGE,  params,            4) \
X(a, STATIC,   OPTIONAL, MESSAGE,  tls,               5)
#define aranya_DeviceConnectivity_CALLBACK pb_default_field_callback
#define aranya_DeviceConnectivity_DEFAULT NULL
#define aranya_DeviceConnectivity_params_MSGTYPE aranya_DeviceConnectivity_ParamsEntry
#define aranya_DeviceConnectivity_tls_MSGTYPE aranya_DeviceConnectivityTLSConfig

#define aranya_DeviceConnectivity_ParamsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_DeviceConnectivity_ParamsEntry_CALLBACK pb_default_field_callback
#define aranya_DeviceConnectivity_ParamsEntry_DEFAULT NULL

#define aranya_DeviceEnsureCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   device_id,         1) \
X(a, STATIC,   OPTIONAL, MESSAGE,  device_connectivity,   2) \
X(a, STATIC,   OPTIONAL, MESSAGE,  upload_connectivity,   3) \
X(a, CALLBACK, REPEATED, MESSAGE,  device_operations,   4) \
X(a, CALLBACK, REPEATED, MESSAGE,  device_metrics,    5)
#define aranya_DeviceEnsureCmd_CALLBACK pb_default_field_callback
#define aranya_DeviceEnsureCmd_DEFAULT NULL
#define aranya_DeviceEnsureCmd_device_connectivity_MSGTYPE aranya_DeviceConnectivity
#define aranya_DeviceEnsureCmd_upload_connectivity_MSGTYPE aranya_DeviceConnectivity
#define aranya_DeviceEnsureCmd_device_operations_MSGTYPE aranya_DeviceOperation
#define aranya_DeviceEnsureCmd_device_metrics_MSGTYPE aranya_DeviceMetrics

#define aranya_DeviceListCmd_FIELDLIST(X, a) \

#define aranya_DeviceListCmd_CALLBACK NULL
#define aranya_DeviceListCmd_DEFAULT NULL

#define aranya_DeviceDeleteCmd_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, STRING,   device_ids,        1)
#define aranya_DeviceDeleteCmd_CALLBACK pb_default_field_callback
#define aranya_DeviceDeleteCmd_DEFAULT NULL

extern const pb_msgdesc_t aranya_DeviceOperation_msg;
extern const pb_msgdesc_t aranya_DeviceOperation_TransportParamsEntry_msg;
extern const pb_msgdesc_t aranya_DeviceMetrics_msg;
extern const pb_msgdesc_t aranya_DeviceMetrics_TransportParamsEntry_msg;
extern const pb_msgdesc_t aranya_DeviceMetrics_UploadParamsEntry_msg;
extern const pb_msgdesc_t aranya_DeviceConnectivityTLSConfig_msg;
extern const pb_msgdesc_t aranya_DeviceConnectivity_msg;
extern const pb_msgdesc_t aranya_DeviceConnectivity_ParamsEntry_msg;
extern const pb_msgdesc_t aranya_DeviceEnsureCmd_msg;
extern const pb_msgdesc_t aranya_DeviceListCmd_msg;
extern const pb_msgdesc_t aranya_DeviceDeleteCmd_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_DeviceOperation_fields &aranya_DeviceOperation_msg
#define aranya_DeviceOperation_TransportParamsEntry_fields &aranya_DeviceOperation_TransportParamsEntry_msg
#define aranya_DeviceMetrics_fields &aranya_DeviceMetrics_msg
#define aranya_DeviceMetrics_TransportParamsEntry_fields &aranya_DeviceMetrics_TransportParamsEntry_msg
#define aranya_DeviceMetrics_UploadParamsEntry_fields &aranya_DeviceMetrics_UploadParamsEntry_msg
#define aranya_DeviceConnectivityTLSConfig_fields &aranya_DeviceConnectivityTLSConfig_msg
#define aranya_DeviceConnectivity_fields &aranya_DeviceConnectivity_msg
#define aranya_DeviceConnectivity_ParamsEntry_fields &aranya_DeviceConnectivity_ParamsEntry_msg
#define aranya_DeviceEnsureCmd_fields &aranya_DeviceEnsureCmd_msg
#define aranya_DeviceListCmd_fields &aranya_DeviceListCmd_msg
#define aranya_DeviceDeleteCmd_fields &aranya_DeviceDeleteCmd_msg

/* Maximum encoded size of messages (where known) */
/* aranya_DeviceOperation_size depends on runtime parameters */
/* aranya_DeviceOperation_TransportParamsEntry_size depends on runtime parameters */
/* aranya_DeviceMetrics_size depends on runtime parameters */
/* aranya_DeviceMetrics_TransportParamsEntry_size depends on runtime parameters */
/* aranya_DeviceMetrics_UploadParamsEntry_size depends on runtime parameters */
/* aranya_DeviceConnectivityTLSConfig_size depends on runtime parameters */
/* aranya_DeviceConnectivity_size depends on runtime parameters */
/* aranya_DeviceConnectivity_ParamsEntry_size depends on runtime parameters */
/* aranya_DeviceEnsureCmd_size depends on runtime parameters */
#define aranya_DeviceListCmd_size                0
/* aranya_DeviceDeleteCmd_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
