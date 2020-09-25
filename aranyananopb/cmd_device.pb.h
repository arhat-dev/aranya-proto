/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_CMD_DEVICE_PB_H_INCLUDED
#define PB_ARANYA_CMD_DEVICE_PB_H_INCLUDED
#include <pb.h>
#include "device.pb.h"
#include "connectivity.pb.h"

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _aranya_DeviceMetric_ReportMethod {
    aranya_DeviceMetric_ReportMethod_REPORT_WITH_NODE_METRICS = 0,
    aranya_DeviceMetric_ReportMethod_REPORT_WITH_ARHAT_CONNECTIVITY = 1,
    aranya_DeviceMetric_ReportMethod_REPORT_WITH_STANDALONE_CLIENT = 2
} aranya_DeviceMetric_ReportMethod;

typedef enum _aranya_DeviceMetric_ValueType {
    aranya_DeviceMetric_ValueType_METRICS_VALUE_TYPE_UNTYPED = 0,
    aranya_DeviceMetric_ValueType_METRICS_VALUE_TYPE_COUNTER = 1,
    aranya_DeviceMetric_ValueType_METRICS_VALUE_TYPE_GAUGE = 2
} aranya_DeviceMetric_ValueType;

/* Struct definitions */
typedef struct _aranya_DeviceDeleteCmd {
    pb_callback_t device_ids;
    pb_callback_t metrics_reporter_hash_hexes;
} aranya_DeviceDeleteCmd;

typedef struct _aranya_DeviceMetric_DeviceParamsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_DeviceMetric_DeviceParamsEntry;

typedef struct _aranya_DeviceMetric_ReporterParamsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_DeviceMetric_ReporterParamsEntry;

typedef struct _aranya_DeviceOperateCmd {
    pb_callback_t operation_id;
    pb_callback_t data;
} aranya_DeviceOperateCmd;

typedef struct _aranya_DeviceOperation {
    pb_callback_t operation_id;
    pb_callback_t params;
} aranya_DeviceOperation;

typedef struct _aranya_DeviceOperation_ParamsEntry {
    pb_callback_t key;
    pb_callback_t value;
} aranya_DeviceOperation_ParamsEntry;

typedef struct _aranya_DeviceEnsureCmd {
    aranya_DeviceType kind;
    pb_callback_t connector_hash_hex;
    bool has_connector;
    aranya_Connectivity connector;
    pb_callback_t device_id;
    pb_callback_t operations;
    pb_callback_t metrics;
} aranya_DeviceEnsureCmd;

typedef struct _aranya_DeviceListCmd {
    aranya_DeviceType kind;
} aranya_DeviceListCmd;

typedef struct _aranya_DeviceMetric {
    pb_callback_t name;
    aranya_DeviceMetric_ReportMethod report_method;
    aranya_DeviceMetric_ValueType value_type;
    pb_callback_t device_params;
    pb_callback_t reporter_hash_hex;
    pb_callback_t reporter_params;
} aranya_DeviceMetric;

typedef struct _aranya_DeviceMetricsCollectCmd {
    bool all;
    pb_callback_t device_ids;
} aranya_DeviceMetricsCollectCmd;


/* Helper constants for enums */
#define _aranya_DeviceMetric_ReportMethod_MIN aranya_DeviceMetric_ReportMethod_REPORT_WITH_NODE_METRICS
#define _aranya_DeviceMetric_ReportMethod_MAX aranya_DeviceMetric_ReportMethod_REPORT_WITH_STANDALONE_CLIENT
#define _aranya_DeviceMetric_ReportMethod_ARRAYSIZE ((aranya_DeviceMetric_ReportMethod)(aranya_DeviceMetric_ReportMethod_REPORT_WITH_STANDALONE_CLIENT+1))

#define _aranya_DeviceMetric_ValueType_MIN aranya_DeviceMetric_ValueType_METRICS_VALUE_TYPE_UNTYPED
#define _aranya_DeviceMetric_ValueType_MAX aranya_DeviceMetric_ValueType_METRICS_VALUE_TYPE_GAUGE
#define _aranya_DeviceMetric_ValueType_ARRAYSIZE ((aranya_DeviceMetric_ValueType)(aranya_DeviceMetric_ValueType_METRICS_VALUE_TYPE_GAUGE+1))


/* Initializer values for message structs */
#define aranya_DeviceOperation_init_default      {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceOperation_ParamsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetric_init_default         {{{NULL}, NULL}, _aranya_DeviceMetric_ReportMethod_MIN, _aranya_DeviceMetric_ValueType_MIN, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetric_DeviceParamsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetric_ReporterParamsEntry_init_default {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceEnsureCmd_init_default      {_aranya_DeviceType_MIN, {{NULL}, NULL}, false, aranya_Connectivity_init_default, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceListCmd_init_default        {_aranya_DeviceType_MIN}
#define aranya_DeviceDeleteCmd_init_default      {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceOperateCmd_init_default     {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetricsCollectCmd_init_default {0, {{NULL}, NULL}}
#define aranya_DeviceOperation_init_zero         {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceOperation_ParamsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetric_init_zero            {{{NULL}, NULL}, _aranya_DeviceMetric_ReportMethod_MIN, _aranya_DeviceMetric_ValueType_MIN, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetric_DeviceParamsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetric_ReporterParamsEntry_init_zero {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceEnsureCmd_init_zero         {_aranya_DeviceType_MIN, {{NULL}, NULL}, false, aranya_Connectivity_init_zero, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceListCmd_init_zero           {_aranya_DeviceType_MIN}
#define aranya_DeviceDeleteCmd_init_zero         {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceOperateCmd_init_zero        {{{NULL}, NULL}, {{NULL}, NULL}}
#define aranya_DeviceMetricsCollectCmd_init_zero {0, {{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define aranya_DeviceDeleteCmd_device_ids_tag    1
#define aranya_DeviceDeleteCmd_metrics_reporter_hash_hexes_tag 2
#define aranya_DeviceMetric_DeviceParamsEntry_key_tag 1
#define aranya_DeviceMetric_DeviceParamsEntry_value_tag 2
#define aranya_DeviceMetric_ReporterParamsEntry_key_tag 1
#define aranya_DeviceMetric_ReporterParamsEntry_value_tag 2
#define aranya_DeviceOperateCmd_operation_id_tag 1
#define aranya_DeviceOperateCmd_data_tag         2
#define aranya_DeviceOperation_operation_id_tag  1
#define aranya_DeviceOperation_params_tag        2
#define aranya_DeviceOperation_ParamsEntry_key_tag 1
#define aranya_DeviceOperation_ParamsEntry_value_tag 2
#define aranya_DeviceEnsureCmd_kind_tag          1
#define aranya_DeviceEnsureCmd_connector_hash_hex_tag 2
#define aranya_DeviceEnsureCmd_connector_tag     3
#define aranya_DeviceEnsureCmd_device_id_tag     4
#define aranya_DeviceEnsureCmd_operations_tag    5
#define aranya_DeviceEnsureCmd_metrics_tag       6
#define aranya_DeviceListCmd_kind_tag            1
#define aranya_DeviceMetric_name_tag             1
#define aranya_DeviceMetric_report_method_tag    2
#define aranya_DeviceMetric_value_type_tag       3
#define aranya_DeviceMetric_device_params_tag    4
#define aranya_DeviceMetric_reporter_hash_hex_tag 5
#define aranya_DeviceMetric_reporter_params_tag  6
#define aranya_DeviceMetricsCollectCmd_all_tag   1
#define aranya_DeviceMetricsCollectCmd_device_ids_tag 2

/* Struct field encoding specification for nanopb */
#define aranya_DeviceOperation_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   operation_id,      1) \
X(a, CALLBACK, REPEATED, MESSAGE,  params,            2)
#define aranya_DeviceOperation_CALLBACK pb_default_field_callback
#define aranya_DeviceOperation_DEFAULT NULL
#define aranya_DeviceOperation_params_MSGTYPE aranya_DeviceOperation_ParamsEntry

#define aranya_DeviceOperation_ParamsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_DeviceOperation_ParamsEntry_CALLBACK pb_default_field_callback
#define aranya_DeviceOperation_ParamsEntry_DEFAULT NULL

#define aranya_DeviceMetric_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   name,              1) \
X(a, STATIC,   SINGULAR, UENUM,    report_method,     2) \
X(a, STATIC,   SINGULAR, UENUM,    value_type,        3) \
X(a, CALLBACK, REPEATED, MESSAGE,  device_params,     4) \
X(a, CALLBACK, SINGULAR, STRING,   reporter_hash_hex,   5) \
X(a, CALLBACK, REPEATED, MESSAGE,  reporter_params,   6)
#define aranya_DeviceMetric_CALLBACK pb_default_field_callback
#define aranya_DeviceMetric_DEFAULT NULL
#define aranya_DeviceMetric_device_params_MSGTYPE aranya_DeviceMetric_DeviceParamsEntry
#define aranya_DeviceMetric_reporter_params_MSGTYPE aranya_DeviceMetric_ReporterParamsEntry

#define aranya_DeviceMetric_DeviceParamsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_DeviceMetric_DeviceParamsEntry_CALLBACK pb_default_field_callback
#define aranya_DeviceMetric_DeviceParamsEntry_DEFAULT NULL

#define aranya_DeviceMetric_ReporterParamsEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, CALLBACK, SINGULAR, STRING,   value,             2)
#define aranya_DeviceMetric_ReporterParamsEntry_CALLBACK pb_default_field_callback
#define aranya_DeviceMetric_ReporterParamsEntry_DEFAULT NULL

#define aranya_DeviceEnsureCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1) \
X(a, CALLBACK, SINGULAR, STRING,   connector_hash_hex,   2) \
X(a, STATIC,   OPTIONAL, MESSAGE,  connector,         3) \
X(a, CALLBACK, SINGULAR, STRING,   device_id,         4) \
X(a, CALLBACK, REPEATED, MESSAGE,  operations,        5) \
X(a, CALLBACK, REPEATED, MESSAGE,  metrics,           6)
#define aranya_DeviceEnsureCmd_CALLBACK pb_default_field_callback
#define aranya_DeviceEnsureCmd_DEFAULT NULL
#define aranya_DeviceEnsureCmd_connector_MSGTYPE aranya_Connectivity
#define aranya_DeviceEnsureCmd_operations_MSGTYPE aranya_DeviceOperation
#define aranya_DeviceEnsureCmd_metrics_MSGTYPE aranya_DeviceMetric

#define aranya_DeviceListCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    kind,              1)
#define aranya_DeviceListCmd_CALLBACK NULL
#define aranya_DeviceListCmd_DEFAULT NULL

#define aranya_DeviceDeleteCmd_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, STRING,   device_ids,        1) \
X(a, CALLBACK, REPEATED, STRING,   metrics_reporter_hash_hexes,   2)
#define aranya_DeviceDeleteCmd_CALLBACK pb_default_field_callback
#define aranya_DeviceDeleteCmd_DEFAULT NULL

#define aranya_DeviceOperateCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   operation_id,      1) \
X(a, CALLBACK, SINGULAR, BYTES,    data,              2)
#define aranya_DeviceOperateCmd_CALLBACK pb_default_field_callback
#define aranya_DeviceOperateCmd_DEFAULT NULL

#define aranya_DeviceMetricsCollectCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BOOL,     all,               1) \
X(a, CALLBACK, REPEATED, STRING,   device_ids,        2)
#define aranya_DeviceMetricsCollectCmd_CALLBACK pb_default_field_callback
#define aranya_DeviceMetricsCollectCmd_DEFAULT NULL

extern const pb_msgdesc_t aranya_DeviceOperation_msg;
extern const pb_msgdesc_t aranya_DeviceOperation_ParamsEntry_msg;
extern const pb_msgdesc_t aranya_DeviceMetric_msg;
extern const pb_msgdesc_t aranya_DeviceMetric_DeviceParamsEntry_msg;
extern const pb_msgdesc_t aranya_DeviceMetric_ReporterParamsEntry_msg;
extern const pb_msgdesc_t aranya_DeviceEnsureCmd_msg;
extern const pb_msgdesc_t aranya_DeviceListCmd_msg;
extern const pb_msgdesc_t aranya_DeviceDeleteCmd_msg;
extern const pb_msgdesc_t aranya_DeviceOperateCmd_msg;
extern const pb_msgdesc_t aranya_DeviceMetricsCollectCmd_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define aranya_DeviceOperation_fields &aranya_DeviceOperation_msg
#define aranya_DeviceOperation_ParamsEntry_fields &aranya_DeviceOperation_ParamsEntry_msg
#define aranya_DeviceMetric_fields &aranya_DeviceMetric_msg
#define aranya_DeviceMetric_DeviceParamsEntry_fields &aranya_DeviceMetric_DeviceParamsEntry_msg
#define aranya_DeviceMetric_ReporterParamsEntry_fields &aranya_DeviceMetric_ReporterParamsEntry_msg
#define aranya_DeviceEnsureCmd_fields &aranya_DeviceEnsureCmd_msg
#define aranya_DeviceListCmd_fields &aranya_DeviceListCmd_msg
#define aranya_DeviceDeleteCmd_fields &aranya_DeviceDeleteCmd_msg
#define aranya_DeviceOperateCmd_fields &aranya_DeviceOperateCmd_msg
#define aranya_DeviceMetricsCollectCmd_fields &aranya_DeviceMetricsCollectCmd_msg

/* Maximum encoded size of messages (where known) */
/* aranya_DeviceOperation_size depends on runtime parameters */
/* aranya_DeviceOperation_ParamsEntry_size depends on runtime parameters */
/* aranya_DeviceMetric_size depends on runtime parameters */
/* aranya_DeviceMetric_DeviceParamsEntry_size depends on runtime parameters */
/* aranya_DeviceMetric_ReporterParamsEntry_size depends on runtime parameters */
/* aranya_DeviceEnsureCmd_size depends on runtime parameters */
#define aranya_DeviceListCmd_size                2
/* aranya_DeviceDeleteCmd_size depends on runtime parameters */
/* aranya_DeviceOperateCmd_size depends on runtime parameters */
/* aranya_DeviceMetricsCollectCmd_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
