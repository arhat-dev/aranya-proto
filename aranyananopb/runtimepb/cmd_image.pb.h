/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.4 */

#ifndef PB_RUNTIME_RUNTIME_CMD_IMAGE_PB_H_INCLUDED
#define PB_RUNTIME_RUNTIME_CMD_IMAGE_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Enum definitions */
typedef enum _runtime_ImagePullPolicy {
    runtime_ImagePullPolicy_IMAGE_PULL_ALWAYS = 0,
    runtime_ImagePullPolicy_IMAGE_PULL_IF_NOT_PRESENT = 1,
    runtime_ImagePullPolicy_IMAGE_PULL_NEVER = 2
} runtime_ImagePullPolicy;

/* Struct definitions */
typedef struct _runtime_ImageAuthConfig {
    pb_callback_t username;
    pb_callback_t password;
    pb_callback_t auth;
    pb_callback_t server_address;
    pb_callback_t identity_token;
    pb_callback_t registry_token;
    pb_callback_t email;
} runtime_ImageAuthConfig;

typedef struct _runtime_ImageDeleteCmd {
    pb_callback_t refs;
} runtime_ImageDeleteCmd;

typedef struct _runtime_ImageEnsureCmd {
    pb_callback_t images;
} runtime_ImageEnsureCmd;

typedef struct _runtime_ImageListCmd {
    pb_callback_t refs;
} runtime_ImageListCmd;

typedef struct _runtime_ImagePullSpec {
    bool has_auth_config;
    runtime_ImageAuthConfig auth_config;
    runtime_ImagePullPolicy pull_policy;
} runtime_ImagePullSpec;

typedef struct _runtime_ImageEnsureCmd_ImagesEntry {
    pb_callback_t key;
    bool has_value;
    runtime_ImagePullSpec value;
} runtime_ImageEnsureCmd_ImagesEntry;


/* Helper constants for enums */
#define _runtime_ImagePullPolicy_MIN runtime_ImagePullPolicy_IMAGE_PULL_ALWAYS
#define _runtime_ImagePullPolicy_MAX runtime_ImagePullPolicy_IMAGE_PULL_NEVER
#define _runtime_ImagePullPolicy_ARRAYSIZE ((runtime_ImagePullPolicy)(runtime_ImagePullPolicy_IMAGE_PULL_NEVER+1))


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define runtime_ImageAuthConfig_init_default     {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define runtime_ImagePullSpec_init_default       {false, runtime_ImageAuthConfig_init_default, _runtime_ImagePullPolicy_MIN}
#define runtime_ImageListCmd_init_default        {{{NULL}, NULL}}
#define runtime_ImageEnsureCmd_init_default      {{{NULL}, NULL}}
#define runtime_ImageEnsureCmd_ImagesEntry_init_default {{{NULL}, NULL}, false, runtime_ImagePullSpec_init_default}
#define runtime_ImageDeleteCmd_init_default      {{{NULL}, NULL}}
#define runtime_ImageAuthConfig_init_zero        {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define runtime_ImagePullSpec_init_zero          {false, runtime_ImageAuthConfig_init_zero, _runtime_ImagePullPolicy_MIN}
#define runtime_ImageListCmd_init_zero           {{{NULL}, NULL}}
#define runtime_ImageEnsureCmd_init_zero         {{{NULL}, NULL}}
#define runtime_ImageEnsureCmd_ImagesEntry_init_zero {{{NULL}, NULL}, false, runtime_ImagePullSpec_init_zero}
#define runtime_ImageDeleteCmd_init_zero         {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define runtime_ImageAuthConfig_username_tag     1
#define runtime_ImageAuthConfig_password_tag     2
#define runtime_ImageAuthConfig_auth_tag         3
#define runtime_ImageAuthConfig_server_address_tag 4
#define runtime_ImageAuthConfig_identity_token_tag 5
#define runtime_ImageAuthConfig_registry_token_tag 6
#define runtime_ImageAuthConfig_email_tag        7
#define runtime_ImageDeleteCmd_refs_tag          1
#define runtime_ImageEnsureCmd_images_tag        1
#define runtime_ImageListCmd_refs_tag            1
#define runtime_ImagePullSpec_auth_config_tag    1
#define runtime_ImagePullSpec_pull_policy_tag    2
#define runtime_ImageEnsureCmd_ImagesEntry_key_tag 1
#define runtime_ImageEnsureCmd_ImagesEntry_value_tag 2

/* Struct field encoding specification for nanopb */
#define runtime_ImageAuthConfig_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   username,          1) \
X(a, CALLBACK, SINGULAR, STRING,   password,          2) \
X(a, CALLBACK, SINGULAR, STRING,   auth,              3) \
X(a, CALLBACK, SINGULAR, STRING,   server_address,    4) \
X(a, CALLBACK, SINGULAR, STRING,   identity_token,    5) \
X(a, CALLBACK, SINGULAR, STRING,   registry_token,    6) \
X(a, CALLBACK, SINGULAR, STRING,   email,             7)
#define runtime_ImageAuthConfig_CALLBACK pb_default_field_callback
#define runtime_ImageAuthConfig_DEFAULT NULL

#define runtime_ImagePullSpec_FIELDLIST(X, a) \
X(a, STATIC,   OPTIONAL, MESSAGE,  auth_config,       1) \
X(a, STATIC,   SINGULAR, UENUM,    pull_policy,       2)
#define runtime_ImagePullSpec_CALLBACK NULL
#define runtime_ImagePullSpec_DEFAULT NULL
#define runtime_ImagePullSpec_auth_config_MSGTYPE runtime_ImageAuthConfig

#define runtime_ImageListCmd_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, STRING,   refs,              1)
#define runtime_ImageListCmd_CALLBACK pb_default_field_callback
#define runtime_ImageListCmd_DEFAULT NULL

#define runtime_ImageEnsureCmd_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, MESSAGE,  images,            1)
#define runtime_ImageEnsureCmd_CALLBACK pb_default_field_callback
#define runtime_ImageEnsureCmd_DEFAULT NULL
#define runtime_ImageEnsureCmd_images_MSGTYPE runtime_ImageEnsureCmd_ImagesEntry

#define runtime_ImageEnsureCmd_ImagesEntry_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   key,               1) \
X(a, STATIC,   OPTIONAL, MESSAGE,  value,             2)
#define runtime_ImageEnsureCmd_ImagesEntry_CALLBACK pb_default_field_callback
#define runtime_ImageEnsureCmd_ImagesEntry_DEFAULT NULL
#define runtime_ImageEnsureCmd_ImagesEntry_value_MSGTYPE runtime_ImagePullSpec

#define runtime_ImageDeleteCmd_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, STRING,   refs,              1)
#define runtime_ImageDeleteCmd_CALLBACK pb_default_field_callback
#define runtime_ImageDeleteCmd_DEFAULT NULL

extern const pb_msgdesc_t runtime_ImageAuthConfig_msg;
extern const pb_msgdesc_t runtime_ImagePullSpec_msg;
extern const pb_msgdesc_t runtime_ImageListCmd_msg;
extern const pb_msgdesc_t runtime_ImageEnsureCmd_msg;
extern const pb_msgdesc_t runtime_ImageEnsureCmd_ImagesEntry_msg;
extern const pb_msgdesc_t runtime_ImageDeleteCmd_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define runtime_ImageAuthConfig_fields &runtime_ImageAuthConfig_msg
#define runtime_ImagePullSpec_fields &runtime_ImagePullSpec_msg
#define runtime_ImageListCmd_fields &runtime_ImageListCmd_msg
#define runtime_ImageEnsureCmd_fields &runtime_ImageEnsureCmd_msg
#define runtime_ImageEnsureCmd_ImagesEntry_fields &runtime_ImageEnsureCmd_ImagesEntry_msg
#define runtime_ImageDeleteCmd_fields &runtime_ImageDeleteCmd_msg

/* Maximum encoded size of messages (where known) */
/* runtime_ImageAuthConfig_size depends on runtime parameters */
/* runtime_ImagePullSpec_size depends on runtime parameters */
/* runtime_ImageListCmd_size depends on runtime parameters */
/* runtime_ImageEnsureCmd_size depends on runtime parameters */
/* runtime_ImageEnsureCmd_ImagesEntry_size depends on runtime parameters */
/* runtime_ImageDeleteCmd_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
