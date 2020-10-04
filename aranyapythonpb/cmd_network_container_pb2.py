# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: cmd_network_container.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='cmd_network_container.proto',
  package='aranya',
  syntax='proto3',
  serialized_options=b'Z!arhat.dev/aranya-proto/aranyagopb',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1b\x63md_network_container.proto\x12\x06\x61ranya\"\x19\n\x17\x43ontainerNetworkListCmd\"A\n\x19\x43ontainerNetworkEnsureCmd\x12\x11\n\tipv4_cidr\x18\x02 \x01(\t\x12\x11\n\tipv6_cidr\x18\x03 \x01(\tB#Z!arhat.dev/aranya-proto/aranyagopbb\x06proto3'
)




_CONTAINERNETWORKLISTCMD = _descriptor.Descriptor(
  name='ContainerNetworkListCmd',
  full_name='aranya.ContainerNetworkListCmd',
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
  serialized_start=39,
  serialized_end=64,
)


_CONTAINERNETWORKENSURECMD = _descriptor.Descriptor(
  name='ContainerNetworkEnsureCmd',
  full_name='aranya.ContainerNetworkEnsureCmd',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='ipv4_cidr', full_name='aranya.ContainerNetworkEnsureCmd.ipv4_cidr', index=0,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='ipv6_cidr', full_name='aranya.ContainerNetworkEnsureCmd.ipv6_cidr', index=1,
      number=3, type=9, cpp_type=9, label=1,
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
  serialized_start=66,
  serialized_end=131,
)

DESCRIPTOR.message_types_by_name['ContainerNetworkListCmd'] = _CONTAINERNETWORKLISTCMD
DESCRIPTOR.message_types_by_name['ContainerNetworkEnsureCmd'] = _CONTAINERNETWORKENSURECMD
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ContainerNetworkListCmd = _reflection.GeneratedProtocolMessageType('ContainerNetworkListCmd', (_message.Message,), {
  'DESCRIPTOR' : _CONTAINERNETWORKLISTCMD,
  '__module__' : 'cmd_network_container_pb2'
  # @@protoc_insertion_point(class_scope:aranya.ContainerNetworkListCmd)
  })
_sym_db.RegisterMessage(ContainerNetworkListCmd)

ContainerNetworkEnsureCmd = _reflection.GeneratedProtocolMessageType('ContainerNetworkEnsureCmd', (_message.Message,), {
  'DESCRIPTOR' : _CONTAINERNETWORKENSURECMD,
  '__module__' : 'cmd_network_container_pb2'
  # @@protoc_insertion_point(class_scope:aranya.ContainerNetworkEnsureCmd)
  })
_sym_db.RegisterMessage(ContainerNetworkEnsureCmd)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
