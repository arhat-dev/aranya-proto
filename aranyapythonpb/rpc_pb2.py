# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: rpc.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import proto_pb2 as proto__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='rpc.proto',
  package='aranya',
  syntax='proto3',
  serialized_options=b'Z!arhat.dev/aranya-proto/aranyagopb',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\trpc.proto\x12\x06\x61ranya\x1a\x0bproto.proto22\n\nEdgeDevice\x12$\n\x04Sync\x12\x0b.aranya.Msg\x1a\x0b.aranya.Cmd(\x01\x30\x01\x42#Z!arhat.dev/aranya-proto/aranyagopbb\x06proto3'
  ,
  dependencies=[proto__pb2.DESCRIPTOR,])



_sym_db.RegisterFileDescriptor(DESCRIPTOR)


DESCRIPTOR._options = None

_EDGEDEVICE = _descriptor.ServiceDescriptor(
  name='EdgeDevice',
  full_name='aranya.EdgeDevice',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=34,
  serialized_end=84,
  methods=[
  _descriptor.MethodDescriptor(
    name='Sync',
    full_name='aranya.EdgeDevice.Sync',
    index=0,
    containing_service=None,
    input_type=proto__pb2._MSG,
    output_type=proto__pb2._CMD,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_EDGEDEVICE)

DESCRIPTOR.services_by_name['EdgeDevice'] = _EDGEDEVICE

# @@protoc_insertion_point(module_scope)
