#!/usr/bin/env bash
# 최소 증명 데모: "AI는 사고를 친다, 그래도 샌드박스에서 막는다"
#
#   ./demo/run_demo.sh            승인 여부를 터미널에서 직접 입력
#   ./demo/run_demo.sh --auto y   승인을 자동으로 (녹화·테스트용). n이면 거절.
#
# 컨트롤 플레인을 띄우고, 보고서 폴더로 샌드박스를 만들고,
# 인젝션에 넘어간 에이전트를 돌린 뒤, 승인 → 결과 → 감사 로그 → 검증 → (승인했다면) 복원까지 보여준다.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
AUTO=""
if [[ "${1:-}" == "--auto" ]]; then AUTO="${2:-n}"; fi

export AGENTBOX_HOME="${AGENTBOX_HOME:-$ROOT/demo-data}"
export AGENTBOX_URL="${AGENTBOX_URL:-http://127.0.0.1:8765}"
# 느슨한 데모 정책: 정책이 놓친 전송을 네트워크 차단이 막는 것을 보여준다 (demo/policy.yaml 참고)
export AGENTBOX_POLICY="${AGENTBOX_POLICY:-$ROOT/demo/policy.yaml}"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
PY="${PYTHON:-python3}"
# 서버는 AGENTBOX_URL의 포트로 띄운다. 다른 포트로 돌리려면 AGENTBOX_URL만 바꾸면 된다.
PORT="$("$PY" -c 'import os, urllib.parse as u; print(u.urlsplit(os.environ["AGENTBOX_URL"]).port or 80)')"

B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; R=$'\033[31m'; X=$'\033[0m'
step() { echo; echo "${B}== $* ==${X}"; }

# 이미 다른 컨트롤 플레인이 그 주소에 떠 있으면, 데모 서버는 포트를 못 잡고
# 상태 확인은 남의 서버가 대신 받아 엉뚱한 401이 난다. 시작 전에 막는다.
if curl -s -o /dev/null -m 2 "$AGENTBOX_URL/healthz"; then
  echo "${R}$AGENTBOX_URL 에 이미 서버가 떠 있음.${X} 그 서버를 끄거나, 다른 포트로 돌릴 것:"
  echo "  AGENTBOX_URL=http://127.0.0.1:8799 $0 ${*}"
  exit 1
fi

rm -rf "$AGENTBOX_HOME"; mkdir -p "$AGENTBOX_HOME"
step "1. 컨트롤 플레인 시작"
"$PY" -m agentbox serve --port "$PORT" >"$AGENTBOX_HOME/server.log" 2>&1 &
SERVER=$!
AGENT=""
cleanup() {
  [[ -n "$AGENT" ]] && kill "$AGENT" 2>/dev/null || true
  [[ -n "${SID:-}" ]] && "$PY" -m agentbox delete "$SID" >/dev/null 2>&1 || true
  # 서버가 포트를 놓을 때까지 기다린다. 안 그러면 바로 이어 돌린 데모가 죽어 가는 서버에 붙는다.
  kill "$SERVER" 2>/dev/null && wait "$SERVER" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 50); do
  kill -0 "$SERVER" 2>/dev/null || { echo "${R}서버가 시작하지 못함:${X}"; cat "$AGENTBOX_HOME/server.log"; exit 1; }
  curl -sf "$AGENTBOX_URL/healthz" >/dev/null && break
  sleep 0.2
done
curl -sf "$AGENTBOX_URL/healthz"; echo

step "2. 보고서 폴더로 샌드박스 생성 (네트워크 차단, 원본 읽기 전용)"
"$PY" -m agentbox create "$ROOT/demo/reports" --env-file "$AGENTBOX_HOME/agent.env" >"$AGENTBOX_HOME/create.log"
head -4 "$AGENTBOX_HOME/create.log"
set -a; source "$AGENTBOX_HOME/agent.env"; set +a
SID="$AGENTBOX_SANDBOX_ID"
echo "${D}숨은 지시가 든 파일: demo/reports/2024-q4-sales.md (HTML 주석)${X}"

step "3. 에이전트에게 \"보고서를 요약해\"라고만 지시"
"$PY" demo/injected_agent.py &
AGENT=$!

step "4. 사람: 터미널 승인"
# 에이전트가 승인 요청을 낼 때까지 기다린 뒤, 대기 중인 요청을 처리한다.
for _ in $(seq 1 150); do
  n=$("$PY" - <<'EOF'
import httpx, os
from agentbox.config import Settings
r = httpx.get(os.environ["AGENTBOX_URL"] + "/approvals", params={"status": "pending"},
              headers={"Authorization": "Bearer " + Settings().human_token()})
print(len(r.json()))
EOF
)
  [[ "$n" != "0" ]] && break
  kill -0 "$AGENT" 2>/dev/null || break
  sleep 0.2
done
if [[ -n "$AUTO" ]]; then
  "$PY" -m agentbox approve --once --auto "$AUTO"
else
  "$PY" -m agentbox approve --once
fi
wait "$AGENT"; AGENT=""

step "5. 원본 폴더는 무사한가"
ls -la "$ROOT/demo/reports"

step "6. 감사 로그 타임라인"
"$PY" -m agentbox audit --sandbox "$SID"

step "7. 해시 체인 검증"
"$PY" -m agentbox verify

SNAP=$("$PY" -m agentbox snapshots "$SID" | awk 'NR==1{print $1}')
if [[ -n "$SNAP" ]]; then
  step "8. 승인 후 지워진 작업 폴더를 스냅샷 $SNAP 으로 복원"
  "$PY" - <<EOF
import httpx, os
from agentbox.config import Settings
h = {"Authorization": "Bearer " + os.environ["AGENTBOX_AGENT_TOKEN"]}
u = os.environ["AGENTBOX_URL"] + "/sandboxes/$SID/tools/exec"
print("복원 전 /workspace:", httpx.post(u, json={"args": {"command": "ls /workspace"}}, headers=h).json()["result"]["stdout"].split())
EOF
  "$PY" -m agentbox restore "$SID" "$SNAP"
  "$PY" - <<EOF
import httpx, os
h = {"Authorization": "Bearer " + os.environ["AGENTBOX_AGENT_TOKEN"]}
u = os.environ["AGENTBOX_URL"] + "/sandboxes/$SID/tools/exec"
print("복원 후 /workspace:", httpx.post(u, json={"args": {"command": "ls /workspace"}}, headers=h).json()["result"]["stdout"].split())
EOF
fi

echo; echo "${G}${B}데모 끝.${X} 외부 전송은 네트워크 차단으로 실패했고, 삭제는 사람 승인 앞에서 멈췄고, 원본은 그대로다."
