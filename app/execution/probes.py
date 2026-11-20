"""Bounded HTTP observations, restricted to the lab's loopback port."""
import time
import urllib.error
import urllib.request

from app.domain.reproduction import Probe


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """阻止重定向响应并拒绝未经检查的跳转。"""
        return None


def request(port: int, probe: Probe, timeout: int = 10) -> dict:
    """向目标主机发送单个 HTTP 探针并返回状态、正文和时序证据。"""
    url = f"http://127.0.0.1:{port}{probe.path}"
    started = time.monotonic()
    observation = {"probe_id": probe.id, "url": url, "method": probe.method}
    try:
        req = urllib.request.Request(url, data=probe.body.encode() if probe.body is not None else None,
                                     method=probe.method, headers=probe.headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            pieces, length = [], 0
            while length < 65537:
                if time.monotonic() - started > timeout:
                    raise TimeoutError("HTTP response exceeded the request time budget")
                # read1 returns available bytes rather than waiting for a complete
                # large body. This also detects a server dripping data forever.
                piece = response.read1(min(8192, 65537 - length))
                if not piece:
                    break
                pieces.append(piece)
                length += len(piece)
            raw = b"".join(pieces)
            observation.update(status=response.code, headers=dict(response.headers),
                               body=raw[:65536].decode("utf-8", errors="replace"),
                               truncated=len(raw) > 65536)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        observation.update(error=str(exc), category="connection_error")
    observation["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return observation


def verify(probes: list[Probe], observations: list[dict], logs: str | None) -> dict:
    """根据既有观测和日志内容验证各项 HTTP 与文件断言。"""
    checks = []
    if len(observations) != len(probes):
        return {"status": "inconclusive", "reason": "Missing observations", "checks": []}
    for probe, observation in zip(probes, observations):
        if observation.get("probe_id") != probe.id or observation.get("error"):
            return {"status": "inconclusive", "reason": "Probe execution failed or evidence mismatched", "checks": checks}
        checks.append({"probe": probe.id, "field": "status", "expected": probe.expected_status,
                       "observed": observation.get("status"), "matched": observation.get("status") == probe.expected_status})
        if probe.body_contains:
            matched = probe.body_contains in observation.get("body", "")
            if not matched and observation.get("truncated"):
                return {"status": "inconclusive", "reason": "Response truncated before evidence was found", "checks": checks}
            checks.append({"probe": probe.id, "field": "body_contains", "expected": probe.body_contains, "matched": matched})
        if probe.log_contains:
            if logs is None:
                return {"status": "inconclusive", "reason": "Logs unavailable", "checks": checks}
            checks.append({"probe": probe.id, "field": "log_contains", "expected": probe.log_contains,
                           "matched": probe.log_contains in logs})
    success = bool(checks) and all(check["matched"] for check in checks)
    return {"status": "success" if success else "not_reproduced", "checks": checks,
            "reason": "All trusted assertions matched" if success else "Trusted assertions did not match"}
