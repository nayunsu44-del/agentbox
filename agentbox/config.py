"""설정. 모두 환경 변수로 바꿀 수 있다."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Template:
    """샌드박스 템플릿 (SB-1). 이미지와 시작 명령, 자원 상한을 묶는다."""
    name: str
    image: str
    command: list[str] | None      # None이면 sleep infinity
    mem_limit: str
    cpus: float
    pids_limit: int
    desktop: bool


@dataclass
class Settings:
    home: Path = field(default_factory=lambda: Path(_env("AGENTBOX_HOME", "./data")).resolve())
    image: str = field(default_factory=lambda: _env("AGENTBOX_IMAGE", "buildpack-deps:noble-curl"))
    runtime: str = field(default_factory=lambda: _env("AGENTBOX_RUNTIME", "auto"))
    policy_path: Path = field(
        default_factory=lambda: Path(
            _env("AGENTBOX_POLICY", str(Path(__file__).with_name("default_policy.yaml")))
        )
    )
    # SB-5 자원 상한
    mem_limit: str = field(default_factory=lambda: _env("AGENTBOX_MEM", "512m"))
    cpus: float = field(default_factory=lambda: float(_env("AGENTBOX_CPUS", "1.0")))
    pids_limit: int = field(default_factory=lambda: int(_env("AGENTBOX_PIDS", "256")))
    # 디스크 상한은 overlay가 xfs+pquota일 때만 동작한다. 비워 두면 적용하지 않는다.
    disk_limit: str = field(default_factory=lambda: _env("AGENTBOX_DISK", ""))
    exec_timeout: int = field(default_factory=lambda: int(_env("AGENTBOX_EXEC_TIMEOUT", "60")))
    # 샌드박스 하나의 스냅샷이 이만큼 쌓이면, 에이전트의 덮어쓰기·삭제는 허용 규칙이어도 승인을 거친다.
    # docker commit은 매번 쓰기 레이어 전체를 복사하므로 사람 없이 호스트 디스크를 채우지 못하게 한다. 0이면 끔.
    snapshot_quota: int = field(default_factory=lambda: int(_env("AGENTBOX_SNAPSHOT_QUOTA", "50")))
    # GUI 입력(click·type·key)은 무엇을 바꿀지 시스템이 모른다. 그래서 입력 하나하나가 아니라 구간 단위로
    # 스냅샷을 뜬다: 이만큼(초) 쉬었다가 다시 입력할 때, 또는 마지막 GUI 스냅샷이 interval(초)보다 오래됐을 때.
    # interval이 0이면 끔.
    gui_snapshot_idle: int = field(default_factory=lambda: int(_env("AGENTBOX_GUI_SNAPSHOT_IDLE", "60")))
    gui_snapshot_interval: int = field(default_factory=lambda: int(_env("AGENTBOX_GUI_SNAPSHOT_INTERVAL", "600")))
    # 샌드박스 하나가 동시에 돌릴 수 있는 도구 호출 수. 0이면 끔.
    tool_concurrency: int = field(default_factory=lambda: int(_env("AGENTBOX_TOOL_CONCURRENCY", "4")))
    # 데이터 폴더(DB)가 있는 디스크의 남은 공간이 이만큼(바이트)보다 적으면 에이전트의 도구 호출을 받지 않는다(507).
    # 감사 로그는 지울 수 없어서, 에이전트 하나가 호출을 쏟아 디스크를 채우면 모든 샌드박스의 호출과 사람의 삭제·승인까지
    # 기록 실패로 멈춘다. 남겨 둔 공간은 사람이 문제의 샌드박스를 지우고 결정하는 데 쓴다 (보안 검수 run-4 N2). 0이면 끔.
    min_free_bytes: int = field(default_factory=lambda: int(_env("AGENTBOX_MIN_FREE", str(256 * 1024 * 1024))))
    max_read_bytes: int = 256 * 1024
    max_write_bytes: int = 1024 * 1024
    # UX-3, UX-4 사람이 넣고 받는 파일 하나의 상한
    max_upload_bytes: int = field(default_factory=lambda: int(_env("AGENTBOX_MAX_UPLOAD", str(50 * 1024 * 1024))))
    # 요청 본문 상한. 인증보다 먼저 읽히는 본문이 컨트롤 플레인 메모리·임시 디스크를 채우지 못하게
    # 본문을 읽기 전에 413으로 끊는다 (보안 검수 run-4 F1). JSON은 write_file 1 MiB를 이스케이프해도 들어가게 잡았고,
    # 파일 넣기는 한 번에 여러 파일을 보내므로 요청 전체 상한을 따로 둔다.
    max_body_bytes: int = field(default_factory=lambda: int(_env("AGENTBOX_MAX_BODY", str(8 * 1024 * 1024))))
    max_upload_body_bytes: int = field(
        default_factory=lambda: int(_env("AGENTBOX_MAX_UPLOAD_BODY", str(256 * 1024 * 1024))))
    # 동시에 처리하는 연결·요청 수 (uvicorn limit_concurrency). 넘으면 503. 화면 웹소켓도 하나씩 센다.
    # 본문 해석은 요청마다 메모리를 쓰므로 동시 수를 묶어 둔다 (보안 검수 run-5 N1). 0이면 끈다.
    max_connections: int = field(default_factory=lambda: int(_env("AGENTBOX_MAX_CONNECTIONS", "256")))
    # AP-1 승인 대기 상한. 지나면 거부로 처리한다.
    approval_timeout: int = field(default_factory=lambda: int(_env("AGENTBOX_APPROVAL_TIMEOUT", "300")))
    # 데스크톱 템플릿 (UX-1, UX-2, TL-2)
    desktop_image: str = field(default_factory=lambda: _env("AGENTBOX_DESKTOP_IMAGE", "agentbox-desktop:0.1"))
    desktop_mem: str = field(default_factory=lambda: _env("AGENTBOX_DESKTOP_MEM", "1536m"))
    desktop_cpus: float = field(default_factory=lambda: float(_env("AGENTBOX_DESKTOP_CPUS", "2.0")))
    desktop_pids: int = field(default_factory=lambda: int(_env("AGENTBOX_DESKTOP_PIDS", "1024")))
    # 화면을 인수한 사람이 제어 연결 없이 이만큼 지나면 에이전트에게 자동으로 돌려준다.
    takeover_idle: int = field(default_factory=lambda: int(_env("AGENTBOX_TAKEOVER_IDLE", "600")))
    docker_cli: str = field(default_factory=lambda: _env("AGENTBOX_DOCKER_CLI", "docker"))
    # TLS 뒤에서 돌 때(직접 인증서 또는 TLS 프록시) 세션 쿠키에 Secure를 붙인다.
    secure_cookie: bool = field(default_factory=lambda: _env("AGENTBOX_SECURE_COOKIE", "") in ("1", "true", "yes"))

    def templates(self) -> dict[str, "Template"]:
        return {
            "cli": Template("cli", self.image, None, self.mem_limit, self.cpus, self.pids_limit, desktop=False),
            "desktop": Template("desktop", self.desktop_image, ["/usr/local/bin/agentbox-desktop-start"],
                                self.desktop_mem, self.desktop_cpus, self.desktop_pids, desktop=True),
        }

    def template(self, name: str) -> "Template":
        t = self.templates().get(name)
        if not t:
            raise ValueError(f"알 수 없는 템플릿: {name} (가능한 것: {', '.join(self.templates())})")
        return t

    @property
    def db_path(self) -> Path:
        return Path(_env("AGENTBOX_DB", str(self.home / "agentbox.db")))

    def human_token(self) -> str:
        """사람(관리자) 토큰. 환경 변수가 없으면 처음 실행 때 만들어 파일에 둔다."""
        env = os.environ.get("AGENTBOX_HUMAN_TOKEN")
        if env:
            return env
        self.home.mkdir(parents=True, exist_ok=True)
        path = self.home / "human_token"
        if path.exists():
            return path.read_text().strip()
        token = "hum_" + secrets.token_urlsafe(24)
        path.write_text(token + "\n")
        path.chmod(0o600)
        return token
