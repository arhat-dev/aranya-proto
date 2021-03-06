/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.4 */

#ifndef PB_RUNTIME_RUNTIME_MSG_IMAGE_PB_H_INCLUDED
#define PB_RUNTIME_RUNTIME_MSG_IMAGE_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Struct definitions */
typedef struct _runtime_ImageStatusListMsg {
    pb_callback_t images;
} runtime_ImageStatusListMsg;

typedef struct _runtime_ImageStatusMsg {
    pb_callback_t sha256;
    uint64_t size;
    pb_callback_t refs;
} runtime_ImageStatusMsg;


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define runtime_ImageStatusMsg_init_default      {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define runtime_ImageStatusListMsg_init_default  {{{NULL}, NULL}}
#define runtime_ImageStatusMsg_init_zero         {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define runtime_ImageStatusListMsg_init_zero     {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define runtime_ImageStatusListMsg_images_tag    1
#define runtime_ImageStatusMsg_sha256_tag        1
#define runtime_ImageStatusMsg_size_tag          2
#define runtime_ImageStatusMsg_refs_tag          3

/* Struct field encoding specification for nanopb */
#define runtime_ImageStatusMsg_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   sha256,            1) \
X(a, STATIC,   SINGULAR, UINT64,   size,              2) \
X(a, CALLBACK, REPEATED, STRING,   refs,              3)
#define runtime_ImageStatusMsg_CALLBACK pb_default_field_callback
#define runtime_ImageStatusMsg_DEFAULT NULL

#define runtime_ImageStatusListMsg_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, MESSAGE,  images,            1)
#define runtime_ImageStatusListMsg_CALLBACK pb_default_field_callback
#define runtime_ImageStatusListMsg_DEFAULT NULL
#define runtime_ImageStatusListMsg_images_MSGTYPE runtime_ImageStatusMsg

extern const pb_msgdesc_t runtime_ImageStatusMsg_msg;
extern const pb_msgdesc_t runtime_ImageStatusListMsg_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define runtime_ImageStatusMsg_fields &runtime_ImageStatusMsg_msg
#define runtime_ImageStatusListMsg_fields &runtime_ImageStatusListMsg_msg

/* Maximum encoded size of messages (where known) */
/* runtime_ImageStatusMsg_size depends on runtime parameters */
/* runtime_ImageStatusListMsg_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
