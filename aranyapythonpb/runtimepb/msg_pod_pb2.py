# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: runtime/msg_pod.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='runtime/msg_pod.proto',
  package='runtime',
  syntax='proto3',
  serialized_options=b'Z+arhat.dev/aranya-proto/aranyagopb/runtimepb',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x15runtime/msg_pod.proto\x12\x07runtime\"\xc1\x01\n\x0f\x43ontainerStatus\x12\x14\n\x0c\x63ontainer_id\x18\x01 \x01(\t\x12\x10\n\x08image_id\x18\x02 \x01(\t\x12\x12\n\ncreated_at\x18\x04 \x01(\t\x12\x12\n\nstarted_at\x18\x05 \x01(\t\x12\x13\n\x0b\x66inished_at\x18\x06 \x01(\t\x12\x11\n\texit_code\x18\x07 \x01(\x05\x12\x15\n\rrestart_count\x18\x08 \x01(\x05\x12\x0e\n\x06reason\x18\x0b \x01(\t\x12\x0f\n\x07message\x18\x0c \x01(\t\"\xb4\x01\n\x0cPodStatusMsg\x12\x0b\n\x03uid\x18\x01 \x01(\t\x12\x0f\n\x07network\x18\x02 \x01(\x0c\x12\x39\n\ncontainers\x18\x03 \x03(\x0b\x32%.runtime.PodStatusMsg.ContainersEntry\x1aK\n\x0f\x43ontainersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\'\n\x05value\x18\x02 \x01(\x0b\x32\x18.runtime.ContainerStatus:\x02\x38\x01\"7\n\x10PodStatusListMsg\x12#\n\x04pods\x18\x01 \x03(\x0b\x32\x15.runtime.PodStatusMsg*~\n\x08PodState\x12\x15\n\x11POD_STATE_UNKNOWN\x10\x00\x12\x15\n\x11POD_STATE_PENDING\x10\x01\x12\x15\n\x11POD_STATE_RUNNING\x10\x02\x12\x17\n\x13POD_STATE_SUCCEEDED\x10\x03\x12\x14\n\x10POD_STATE_FAILED\x10\x04\x42-Z+arhat.dev/aranya-proto/aranyagopb/runtimepbb\x06proto3'
)

_PODSTATE = _descriptor.EnumDescriptor(
  name='PodState',
  full_name='runtime.PodState',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='POD_STATE_UNKNOWN', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POD_STATE_PENDING', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POD_STATE_RUNNING', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POD_STATE_SUCCEEDED', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POD_STATE_FAILED', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=470,
  serialized_end=596,
)
_sym_db.RegisterEnumDescriptor(_PODSTATE)

PodState = enum_type_wrapper.EnumTypeWrapper(_PODSTATE)
POD_STATE_UNKNOWN = 0
POD_STATE_PENDING = 1
POD_STATE_RUNNING = 2
POD_STATE_SUCCEEDED = 3
POD_STATE_FAILED = 4



_CONTAINERSTATUS = _descriptor.Descriptor(
  name='ContainerStatus',
  full_name='runtime.ContainerStatus',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='container_id', full_name='runtime.ContainerStatus.container_id', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='image_id', full_name='runtime.ContainerStatus.image_id', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='created_at', full_name='runtime.ContainerStatus.created_at', index=2,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='started_at', full_name='runtime.ContainerStatus.started_at', index=3,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='finished_at', full_name='runtime.ContainerStatus.finished_at', index=4,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='exit_code', full_name='runtime.ContainerStatus.exit_code', index=5,
      number=7, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='restart_count', full_name='runtime.ContainerStatus.restart_count', index=6,
      number=8, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='reason', full_name='runtime.ContainerStatus.reason', index=7,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='message', full_name='runtime.ContainerStatus.message', index=8,
      number=12, type=9, cpp_type=9, label=1,
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
  serialized_start=35,
  serialized_end=228,
)


_PODSTATUSMSG_CONTAINERSENTRY = _descriptor.Descriptor(
  name='ContainersEntry',
  full_name='runtime.PodStatusMsg.ContainersEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='runtime.PodStatusMsg.ContainersEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='runtime.PodStatusMsg.ContainersEntry.value', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=336,
  serialized_end=411,
)

_PODSTATUSMSG = _descriptor.Descriptor(
  name='PodStatusMsg',
  full_name='runtime.PodStatusMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='uid', full_name='runtime.PodStatusMsg.uid', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='network', full_name='runtime.PodStatusMsg.network', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='containers', full_name='runtime.PodStatusMsg.containers', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_PODSTATUSMSG_CONTAINERSENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=231,
  serialized_end=411,
)


_PODSTATUSLISTMSG = _descriptor.Descriptor(
  name='PodStatusListMsg',
  full_name='runtime.PodStatusListMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='pods', full_name='runtime.PodStatusListMsg.pods', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  serialized_start=413,
  serialized_end=468,
)

_PODSTATUSMSG_CONTAINERSENTRY.fields_by_name['value'].message_type = _CONTAINERSTATUS
_PODSTATUSMSG_CONTAINERSENTRY.containing_type = _PODSTATUSMSG
_PODSTATUSMSG.fields_by_name['containers'].message_type = _PODSTATUSMSG_CONTAINERSENTRY
_PODSTATUSLISTMSG.fields_by_name['pods'].message_type = _PODSTATUSMSG
DESCRIPTOR.message_types_by_name['ContainerStatus'] = _CONTAINERSTATUS
DESCRIPTOR.message_types_by_name['PodStatusMsg'] = _PODSTATUSMSG
DESCRIPTOR.message_types_by_name['PodStatusListMsg'] = _PODSTATUSLISTMSG
DESCRIPTOR.enum_types_by_name['PodState'] = _PODSTATE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ContainerStatus = _reflection.GeneratedProtocolMessageType('ContainerStatus', (_message.Message,), {
  'DESCRIPTOR' : _CONTAINERSTATUS,
  '__module__' : 'runtime.msg_pod_pb2'
  # @@protoc_insertion_point(class_scope:runtime.ContainerStatus)
  })
_sym_db.RegisterMessage(ContainerStatus)

PodStatusMsg = _reflection.GeneratedProtocolMessageType('PodStatusMsg', (_message.Message,), {

  'ContainersEntry' : _reflection.GeneratedProtocolMessageType('ContainersEntry', (_message.Message,), {
    'DESCRIPTOR' : _PODSTATUSMSG_CONTAINERSENTRY,
    '__module__' : 'runtime.msg_pod_pb2'
    # @@protoc_insertion_point(class_scope:runtime.PodStatusMsg.ContainersEntry)
    })
  ,
  'DESCRIPTOR' : _PODSTATUSMSG,
  '__module__' : 'runtime.msg_pod_pb2'
  # @@protoc_insertion_point(class_scope:runtime.PodStatusMsg)
  })
_sym_db.RegisterMessage(PodStatusMsg)
_sym_db.RegisterMessage(PodStatusMsg.ContainersEntry)

PodStatusListMsg = _reflection.GeneratedProtocolMessageType('PodStatusListMsg', (_message.Message,), {
  'DESCRIPTOR' : _PODSTATUSLISTMSG,
  '__module__' : 'runtime.msg_pod_pb2'
  # @@protoc_insertion_point(class_scope:runtime.PodStatusListMsg)
  })
_sym_db.RegisterMessage(PodStatusListMsg)


DESCRIPTOR._options = None
_PODSTATUSMSG_CONTAINERSENTRY._options = None
# @@protoc_insertion_point(module_scope)
