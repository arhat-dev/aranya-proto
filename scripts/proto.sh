#!/bin/sh

# Copyright 2020 The arhat.dev Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

GOPATH=$(go env GOPATH)
export GOPATH

PROTO_SOURCE="./src/*.proto ./src/rpc/*.proto ./src/runtime/*.proto"

fix_pb_gen_json_name() {
  pb_files="$*"
  cmd_sed="sed"

  command -v gsed && cmd_sed="gsed"

  for f in ${pb_files}; do
    ${cmd_sed} -i -r 's/,json=(\w+?),omitempty,proto3" json:"\w+(,omitempty)?"/,json=\1,omitempty,proto3" json:"\1,omitempty"/g' "${f}"
    ${cmd_sed} -i -r 's/,json=(\w+?),proto3" json:"\w+(,omitempty)?"/,json=\1,proto3" json:"\1"/g' "${f}"
  done
}

_rename_package_names() {
  gen_root="$1"

  mkdir -p "${gen_root}/runtimepb/" "${gen_root}/rpcpb/"
  mv "${gen_root}/runtime/"* "${gen_root}/runtimepb/."
  mv "${gen_root}/rpc/"* "${gen_root}/rpcpb/."

  rm -rf "${gen_root}/runtime" "${gen_root}/rpc"
}

_do_gen_proto_go() {
  rm -rf aranyagopb/*.pb.go aranyagopb/runtime aranyagopb/runtimepb/*.pb.go || true

  for t in ${PROTO_SOURCE}; do
    # shellcheck disable=SC2086
    protoc \
      -I "${GOPATH}/src" \
      -I "${GOPATH}/src/github.com/gogo/protobuf/protobuf" \
      -I ./src \
      -I ./src/rpc \
      -I ./src/runtime \
      --gogoslick_out "plugins=grpc:./aranyagopb" \
      --gogoslick_opt "paths=source_relative" \
      "$t"
  done

  _rename_package_names aranyagopb

  # fix_pb_gen_json_name ./aranyagopb/*.pb.go
}

_do_gen_proto_python() {
  rm aranyapythonpb/*_pb*.py || true

  # shellcheck disable=SC2086
  pipenv run \
  python -m grpc_tools.protoc \
    -I "${GOPATH}/src" \
    -I "${GOPATH}/src/github.com/gogo/protobuf/protobuf" \
    -I ./src \
    -I ./src/rpc \
    -I ./src/runtime \
    --python_out "./aranyapythonpb" \
    --grpc_python_out "./aranyapythonpb" \
    ${PROTO_SOURCE}

  _rename_package_names aranyapythonpb
}

_do_gen_proto_c() {
  rm aranyananopb/*.pb.c aranyananopb/*.pb.h || true

  # shellcheck disable=SC2086
  pipenv run \
  python build/nanopb/generator/nanopb_generator.py \
    --no-timestamp \
    -x github.com/gogo/protobuf/gogoproto/gogo.proto \
    --output-dir ./aranyananopb \
    -I "${GOPATH}/src" \
    -I "${GOPATH}/src/github.com/gogo/protobuf/protobuf" \
    -I ./src \
    -I ./src/rpc \
    -I ./src/runtime \
    ${PROTO_SOURCE}

  rm -rf ./aranyananopb/google ./aranyananopb/github.com

  _rename_package_names aranyananopb
}

_do_gen_proto_rust() {
  rm aranyarustpb/*.pb.rs || true

  # shellcheck disable=SC2086
  pipenv run \
  protoc \
    -I "${GOPATH}/src/github.com/gogo/protobuf/protobuf" \
    -I "${GOPATH}/src" \
    -I ./src \
    -I ./src/rpc \
    -I ./src/runtime \
    --plugin "protoc-gen-rust=$(pwd)/build/pb-jelly/pb-jelly-gen/codegen/codegen.py" \
    --rust_out=./aranyarustpb \
    ${PROTO_SOURCE}

  _rename_package_names aranyarustpb
}

CODE_LANG=$(printf "%s" "$@" | cut -d. -f3)

"_do_gen_proto_${CODE_LANG}"
