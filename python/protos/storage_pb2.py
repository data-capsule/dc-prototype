# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: storage.proto
# Protobuf Python Version: 4.25.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rstorage.proto\"\x8f\x01\n\x11StoredDataCapsule\x12\x17\n\x0f\x63reater_pub_key\x18\x01 \x01(\x0c\x12\x16\n\x0ewriter_pub_key\x18\x02 \x01(\x0c\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t\x12\x19\n\x11\x63reater_signature\x18\x04 \x01(\x0c\x12\x19\n\x11latest_seq_number\x18\x05 \x01(\x0c\"\x19\n\tDataBlock\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\"6\n\x0bRecordBlock\x12\x0e\n\x06parent\x18\x01 \x01(\x0c\x12\x17\n\x0fsequence_number\x18\x02 \x01(\x06\"M\n\tTreeBlock\x12\x13\n\x06parent\x18\x01 \x01(\x0cH\x00\x88\x01\x01\x12\x0e\n\x06signed\x18\x02 \x01(\x08\x12\x10\n\x08\x63hildren\x18\x03 \x03(\x0c\x42\t\n\x07_parent\"\x1d\n\x08SigBlock\x12\x11\n\tsignature\x18\x01 \x01(\x0c\"\x1f\n\x08SeqBlock\x12\x13\n\x0brecord_hash\x18\x01 \x01(\x0c\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'storage_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_STOREDDATACAPSULE']._serialized_start=18
  _globals['_STOREDDATACAPSULE']._serialized_end=161
  _globals['_DATABLOCK']._serialized_start=163
  _globals['_DATABLOCK']._serialized_end=188
  _globals['_RECORDBLOCK']._serialized_start=190
  _globals['_RECORDBLOCK']._serialized_end=244
  _globals['_TREEBLOCK']._serialized_start=246
  _globals['_TREEBLOCK']._serialized_end=323
  _globals['_SIGBLOCK']._serialized_start=325
  _globals['_SIGBLOCK']._serialized_end=354
  _globals['_SEQBLOCK']._serialized_start=356
  _globals['_SEQBLOCK']._serialized_end=387
# @@protoc_insertion_point(module_scope)
