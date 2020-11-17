# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: credential.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='credential.proto',
  package='aranya',
  syntax='proto3',
  serialized_options=b'Z!arhat.dev/aranya-proto/aranyagopb',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x10\x63redential.proto\x12\x06\x61ranya\"\x13\n\x11\x43redentialListCmd\".\n\x13\x43redentialEnsureCmd\x12\x17\n\x0fssh_private_key\x18\x01 \x01(\x0c\"\x15\n\x13\x43redentialDeleteCmd\"9\n\x13\x43redentialStatusMsg\x12\"\n\x1assh_private_key_sha256_hex\x18\x01 \x01(\tB#Z!arhat.dev/aranya-proto/aranyagopbb\x06proto3'
)




_CREDENTIALLISTCMD = _descriptor.Descriptor(
  name='CredentialListCmd',
  full_name='aranya.CredentialListCmd',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=28,
  serialized_end=47,
)


_CREDENTIALENSURECMD = _descriptor.Descriptor(
  name='CredentialEnsureCmd',
  full_name='aranya.CredentialEnsureCmd',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='ssh_private_key', full_name='aranya.CredentialEnsureCmd.ssh_private_key', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=49,
  serialized_end=95,
)


_CREDENTIALDELETECMD = _descriptor.Descriptor(
  name='CredentialDeleteCmd',
  full_name='aranya.CredentialDeleteCmd',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=97,
  serialized_end=118,
)


_CREDENTIALSTATUSMSG = _descriptor.Descriptor(
  name='CredentialStatusMsg',
  full_name='aranya.CredentialStatusMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='ssh_private_key_sha256_hex', full_name='aranya.CredentialStatusMsg.ssh_private_key_sha256_hex', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=120,
  serialized_end=177,
)

DESCRIPTOR.message_types_by_name['CredentialListCmd'] = _CREDENTIALLISTCMD
DESCRIPTOR.message_types_by_name['CredentialEnsureCmd'] = _CREDENTIALENSURECMD
DESCRIPTOR.message_types_by_name['CredentialDeleteCmd'] = _CREDENTIALDELETECMD
DESCRIPTOR.message_types_by_name['CredentialStatusMsg'] = _CREDENTIALSTATUSMSG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CredentialListCmd = _reflection.GeneratedProtocolMessageType('CredentialListCmd', (_message.Message,), {
  'DESCRIPTOR' : _CREDENTIALLISTCMD,
  '__module__' : 'credential_pb2'
  # @@protoc_insertion_point(class_scope:aranya.CredentialListCmd)
  })
_sym_db.RegisterMessage(CredentialListCmd)

CredentialEnsureCmd = _reflection.GeneratedProtocolMessageType('CredentialEnsureCmd', (_message.Message,), {
  'DESCRIPTOR' : _CREDENTIALENSURECMD,
  '__module__' : 'credential_pb2'
  # @@protoc_insertion_point(class_scope:aranya.CredentialEnsureCmd)
  })
_sym_db.RegisterMessage(CredentialEnsureCmd)

CredentialDeleteCmd = _reflection.GeneratedProtocolMessageType('CredentialDeleteCmd', (_message.Message,), {
  'DESCRIPTOR' : _CREDENTIALDELETECMD,
  '__module__' : 'credential_pb2'
  # @@protoc_insertion_point(class_scope:aranya.CredentialDeleteCmd)
  })
_sym_db.RegisterMessage(CredentialDeleteCmd)

CredentialStatusMsg = _reflection.GeneratedProtocolMessageType('CredentialStatusMsg', (_message.Message,), {
  'DESCRIPTOR' : _CREDENTIALSTATUSMSG,
  '__module__' : 'credential_pb2'
  # @@protoc_insertion_point(class_scope:aranya.CredentialStatusMsg)
  })
_sym_db.RegisterMessage(CredentialStatusMsg)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)