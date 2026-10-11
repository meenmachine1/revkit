#!/bin/sh
# Regenerates the protobuf/gRPC stubs in revkit/v1/ from proto/revkit/v1/.
# Needs grpcio-tools (pinned in pyproject.toml's "dev" extra):
#
#   python -m pip install -e 'sdk/python[dev]'
#   sdk/python/generate.sh [python]
#
# The stubs are committed so the package installs without a protoc;
# tests/test_stubs.py fails when they drift from the schema.
#
# Then the script editor's completion index (ui/src/scripts/script-api.json,
# or $OUT/script-api.json) from the SDK's signatures and docstrings;
# tests/test_completion_index.py fails when it drifts from the SDK.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
python=${1:-python3}
out=${OUT:-$here}

rm -f "$out"/revkit/v1/*_pb2.py "$out"/revkit/v1/*_pb2.pyi "$out"/revkit/v1/*_pb2_grpc.py
mkdir -p "$out/revkit/v1"
"$python" -m grpc_tools.protoc \
  --proto_path="$root/proto" \
  --python_out="$out" --pyi_out="$out" --grpc_python_out="$out" \
  "$root"/proto/revkit/v1/*.proto
index=${OUT:+$OUT/script-api.json}
PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}" "$python" -m revkit.script.completion_index \
  --out "${index:-$root/ui/src/scripts/script-api.json}"
