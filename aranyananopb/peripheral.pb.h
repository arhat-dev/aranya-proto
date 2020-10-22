/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.2 */

#ifndef PB_ARANYA_PERIPHERAL_PB_H_INCLUDED
#define PB_ARANYA_PERIPHERAL_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _aranya_PeripheralType {
    aranya_PeripheralType__INVALID_PERIPHERAL_TYPE = 0,
    aranya_PeripheralType_PERIPHERAL_TYPE_NORMAL = 1,
    aranya_PeripheralType_PERIPHERAL_TYPE_METRICS_REPORTER = 2
} aranya_PeripheralType;

/* Helper constants for enums */
#define _aranya_PeripheralType_MIN aranya_PeripheralType__INVALID_PERIPHERAL_TYPE
#define _aranya_PeripheralType_MAX aranya_PeripheralType_PERIPHERAL_TYPE_METRICS_REPORTER
#define _aranya_PeripheralType_ARRAYSIZE ((aranya_PeripheralType)(aranya_PeripheralType_PERIPHERAL_TYPE_METRICS_REPORTER+1))


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif