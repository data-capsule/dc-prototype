# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: requests.proto
# Protobuf Python Version: 4.25.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0erequests.proto\"-\n\nSignedHash\x12\x0c\n\x04hash\x18\x01 \x01(\x0c\x12\x11\n\tsignature\x18\x02 \x01(\x0c\"\x9a\x01\n\x0bInitRequest\x12\x1f\n\x04type\x18\x01 \x01(\x0e\x32\x11.InitRequest.Type\x12\x1d\n\x10\x64\x61tacapsule_hash\x18\x02 \x01(\x0cH\x00\x88\x01\x01\"6\n\x04Type\x12\n\n\x06\x63reate\x10\x00\x12\t\n\x05write\x10\x01\x12\x08\n\x04read\x10\x02\x12\r\n\tsubscribe\x10\x03\x42\x13\n\x11_datacapsule_hash\"$\n\x0cInitResponse\x12\x14\n\x0cinit_success\x18\x02 \x01(\x08\"}\n\rCreateRequest\x12\x17\n\x0f\x63reater_pub_key\x18\x01 \x01(\x0c\x12\x16\n\x0ewriter_pub_key\x18\x02 \x01(\x0c\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t\x12&\n\x11\x63reater_signature\x18\x04 \x01(\x0b\x32\x0b.SignedHash\"7\n\x0e\x43reateResponse\x12%\n\x10server_signature\x18\x01 \x01(\x0b\x32\x0b.SignedHash\"Y\n\x0bReadRequest\x12\x1f\n\x04type\x18\x01 \x01(\x0e\x32\x11.ReadRequest.Type\x12\x0c\n\x04hash\x18\x02 \x01(\x0c\"\x1b\n\x04Type\x12\x08\n\x04\x64\x61ta\x10\x00\x12\t\n\x05proof\x10\x01\"\x1c\n\x0c\x44\x61taResponse\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\"H\n\rProofResponse\x12\x1e\n\x04root\x18\x01 \x01(\x0b\x32\x0b.SignedHashH\x00\x88\x01\x01\x12\x0e\n\x06hashes\x18\x02 \x03(\x0c\x42\x07\n\x05_root\"\x9e\x01\n\x10SubscribeRequest\x12$\n\x04type\x18\x01 \x01(\x0e\x32\x16.SubscribeRequest.Type\x12\x10\n\x03num\x18\x02 \x01(\x06H\x00\x88\x01\x01\"J\n\x04Type\x12\x0c\n\x08last_num\x10\x00\x12\x11\n\rname_from_num\x10\x01\x12\x11\n\rnum_from_name\x10\x02\x12\x0e\n\nwait_after\x10\x03\x42\x06\n\x04_num\"I\n\x11SubscribeResponse\x12\x10\n\x03num\x18\x01 \x01(\x06H\x00\x88\x01\x01\x12\x11\n\x04hash\x18\x02 \x01(\x0cH\x01\x88\x01\x01\x42\x06\n\x04_numB\x07\n\x05_hash\"\x86\x02\n\x0cWriteRequest\x12 \n\x04type\x18\x01 \x01(\x0e\x32\x12.WriteRequest.Type\x12\x11\n\x04\x64\x61ta\x18\x02 \x01(\x0cH\x00\x88\x01\x01\x12\x1c\n\x0fsequence_number\x18\x03 \x01(\x06H\x01\x88\x01\x01\x12%\n\x0b\x63ommit_root\x18\x04 \x01(\x0b\x32\x0b.SignedHashH\x02\x88\x01\x01\x12\x1c\n\x0f\x61\x64\x64itional_hash\x18\x05 \x01(\x0cH\x03\x88\x01\x01\"\x1d\n\x04Type\x12\t\n\x05write\x10\x00\x12\n\n\x06\x63ommit\x10\x01\x42\x07\n\x05_dataB\x12\n\x10_sequence_numberB\x0e\n\x0c_commit_rootB\x12\n\x10_additional_hash\"P\n\rWriteResponse\x12*\n\x10server_signature\x18\x01 \x01(\x0b\x32\x0b.SignedHashH\x00\x88\x01\x01\x42\x13\n\x11_server_signatureb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'requests_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_SIGNEDHASH']._serialized_start=18
  _globals['_SIGNEDHASH']._serialized_end=63
  _globals['_INITREQUEST']._serialized_start=66
  _globals['_INITREQUEST']._serialized_end=220
  _globals['_INITREQUEST_TYPE']._serialized_start=145
  _globals['_INITREQUEST_TYPE']._serialized_end=199
  _globals['_INITRESPONSE']._serialized_start=222
  _globals['_INITRESPONSE']._serialized_end=258
  _globals['_CREATEREQUEST']._serialized_start=260
  _globals['_CREATEREQUEST']._serialized_end=385
  _globals['_CREATERESPONSE']._serialized_start=387
  _globals['_CREATERESPONSE']._serialized_end=442
  _globals['_READREQUEST']._serialized_start=444
  _globals['_READREQUEST']._serialized_end=533
  _globals['_READREQUEST_TYPE']._serialized_start=506
  _globals['_READREQUEST_TYPE']._serialized_end=533
  _globals['_DATARESPONSE']._serialized_start=535
  _globals['_DATARESPONSE']._serialized_end=563
  _globals['_PROOFRESPONSE']._serialized_start=565
  _globals['_PROOFRESPONSE']._serialized_end=637
  _globals['_SUBSCRIBEREQUEST']._serialized_start=640
  _globals['_SUBSCRIBEREQUEST']._serialized_end=798
  _globals['_SUBSCRIBEREQUEST_TYPE']._serialized_start=716
  _globals['_SUBSCRIBEREQUEST_TYPE']._serialized_end=790
  _globals['_SUBSCRIBERESPONSE']._serialized_start=800
  _globals['_SUBSCRIBERESPONSE']._serialized_end=873
  _globals['_WRITEREQUEST']._serialized_start=876
  _globals['_WRITEREQUEST']._serialized_end=1138
  _globals['_WRITEREQUEST_TYPE']._serialized_start=1044
  _globals['_WRITEREQUEST_TYPE']._serialized_end=1073
  _globals['_WRITERESPONSE']._serialized_start=1140
  _globals['_WRITERESPONSE']._serialized_end=1220
# @@protoc_insertion_point(module_scope)