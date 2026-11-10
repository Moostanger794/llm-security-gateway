"""Fixed synthetic cases over real loopback HTTP: RULES / NO LIVE LLM."""

import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

import httpx

from ai_security_gateway.evaluation.injection_dataset import (
    InjectionRecord,
    load_injection_dataset,
)
from ai_security_gateway.models.security import SecurityResult

ROOT = Path(__file__).resolve().parents[1]
CASE_IDS = ("ii-dev-009", "ii-dev-005", "ii-dev-007", "ii-dev-008")

# Same stdin shutdown protocol as smoke_prompt.py. Binding in the child avoids
# the free-port probe/rebind race and never connects to a pre-existing server.
SERVER_CODE = """
import ipaddress, socket, sys, threading

def offline(event, args):
    if event in {"socket.connect", "socket.sendto"}:
        address = args[-1]
        if not isinstance(address, tuple):
            return
        host = address[0]
    elif event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}:
        host = args[0]
    else:
        return
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if not local:
        raise OSError("External network forbidden in offline demo")

sys.addaudithook(offline)
import uvicorn
from ai_security_gateway.main import app

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="warning"))
    threading.Thread(target=lambda: (sys.stdin.readline(),
        setattr(server, "should_exit", True)), daemon=True).start()
    print(listener.getsockname()[1], flush=True)
    server.run(sockets=[listener])
    if not server.started:
        raise SystemExit(1)
"""


def offline_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Isolate child configuration without touching the caller or a real .env."""
    child = {
        key: value
        for key, value in (os.environ if environ is None else environ).items()
        if not key.upper().startswith(("LLM_", "OPENAI_"))
    }
    child.update(
        ENABLE_LLM_ANALYSIS="false",
        ALLOW_EXTERNAL_LLM="false",
        LLM_API_KEY="",
        LLM_MODEL="",
        APP_NAME="AI Security Gateway",
        LOG_LEVEL="WARNING",
        PYTHONUTF8="1",
    )
    return child


def cases() -> tuple[InjectionRecord, ...]:
    dataset = load_injection_dataset(
        [
            ROOT / "datasets" / "indirect_injection" / f"{split}.jsonl"
            for split in ("dev", "holdout")
        ]
    )
    by_id = {row.id: row for row in dataset.records}
    selected = tuple(by_id[sample_id] for sample_id in CASE_IDS)
    if any(row.provenance.origin != "synthetic" for row in selected):
        raise ValueError("Demo requires the fixed synthetic cases")
    return selected


def stop_server(process: subprocess.Popen) -> None:
    """Reap only the process we started, including failed startup and timeout paths."""
    try:
        try:
            process.stdin.write("stop\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass  # Startup may have failed before the child read stdin.
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("Demo server required forced shutdown") from None
    finally:
        try:
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        process.stdout.close()


def wait_for_health(client: httpx.Client, process: subprocess.Popen, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while process.poll() is None:
        try:
            response = client.get("/health")
            response.raise_for_status()
            if response.json().get("status") != "ok":
                raise ValueError("Unexpected health response")
            return
        except httpx.TransportError:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
    raise RuntimeError("Demo server did not become ready")


@contextmanager
def local_server(startup_timeout: float = 10) -> Iterator[httpx.Client]:
    # An empty cwd prevents even main.py's module-level app from reading .env.
    with tempfile.TemporaryDirectory(prefix="kp2-demo-") as isolated_cwd:
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", SERVER_CODE],
            cwd=isolated_cwd,
            env=offline_environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        try:
            port_line: queue.Queue[str] = queue.Queue(maxsize=1)
            reader = threading.Thread(
                target=lambda: port_line.put(process.stdout.readline()), daemon=True
            )
            reader.start()
            port = int(port_line.get(timeout=startup_timeout))
            if not 1 <= port <= 65535:
                raise ValueError("Invalid local port")
            with httpx.Client(
                base_url=f"http://127.0.0.1:{port}",
                timeout=2,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                wait_for_health(client, process, startup_timeout)
                yield client
        finally:
            stop_server(process)
        if process.returncode != 0:
            raise RuntimeError("Demo server exited unsuccessfully")


def analyze_case(client: httpx.Client, case: InjectionRecord) -> SecurityResult:
    # Labels/expected decisions stay in this presenter; only source fields reach API.
    response = client.post(f"/analyze/{case.kind}", json=case.input.model_dump())
    response.raise_for_status()
    if (
        response.headers.get("X-Analysis-Mode") != "rules"
        or response.headers.get("X-Requested-Analysis-Mode") != "rules"
        or response.headers.get("X-LLM-Status") != "disabled"
        or response.headers.get("X-LLM-Requests") != "0"
    ):
        raise RuntimeError("Offline analysis contract failed")
    result = SecurityResult.model_validate(response.json())
    print(f"\n{case.id} | label={case.label} | expected_action={case.expected_action}")
    print(
        f"mode={response.headers['X-Analysis-Mode']} action={result.action} "
        f"risk={result.risk_score:.6f} level={result.risk_level} "
        f"llm_status={response.headers['X-LLM-Status']} "
        f"provider_attempts={response.headers['X-LLM-Requests']}"
    )
    print(f"explanation: {result.explanation}")
    if case.label == "attack" and result.action == "ALLOW":
        print("LIMITATION: missed attack; ALLOW is gateway passage, not proven agent compromise.")
    elif case.label == "safe" and not result.safe:
        print("LIMITATION: false alarm on a benign example.")
    elif result.action != case.expected_action:
        print("LIMITATION: actual action differs from the fixed annotation.")
    return result


def main() -> int:
    print("RULES / NO LIVE LLM", flush=True)
    print("Synthetic cases; real loopback HTTP. No downstream model, agent or mail delivery.")
    print("The caller must enforce action. Demo is not a full benchmark.")
    try:
        selected = cases()
        with local_server() as client:
            print("GET /health: 200 ok")
            for case in selected:
                analyze_case(client, case)
    except KeyboardInterrupt:
        print("Demo interrupted; owned server cleanup attempted.", file=sys.stderr)
        return 130
    except Exception:
        # Process/config/HTTP errors can carry sensitive values; never echo them.
        print("Demo failed; see docs/kp2/demo.md for offline troubleshooting.", file=sys.stderr)
        return 1
    print("\nOwned Uvicorn: graceful shutdown, exit 0. Provider attempts total: 0.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
