"""Small MessagePack RPC client for local/private Metasploit instances."""
from __future__ import annotations
from urllib.parse import urlparse


class MetasploitRPCError(RuntimeError):
    pass


class MetasploitRPCClient:
    """Minimal client: login, version, module search, info and options only."""
    def __init__(self, url: str, username: str, password: str, *, timeout: float = 15,
                 verify_tls: bool | str = True, session=None):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("RPC URL must be an absolute HTTP(S) URL")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Use HTTPS for non-local RPC endpoints")
        if not username or not password:
            raise ValueError("RPC username and password are required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.url, self.username, self.password = url, username, password
        self.timeout, self.verify_tls, self.session = timeout, verify_tls, session
        self.token = None

    def _post(self, payload):
        try:
            import msgpack
            import requests
        except ImportError as exc:
            raise RuntimeError("Install the metasploit optional dependencies: pip install -e '.[metasploit]'") from exc
        if self.session is None:
            self.session = requests.Session()
        try:
            response = self.session.post(self.url, data=msgpack.packb(payload, use_bin_type=True),
                headers={"Content-Type": "binary/message-pack"}, timeout=self.timeout, verify=self.verify_tls)
            response.raise_for_status()
            result = msgpack.unpackb(response.content, raw=False, strict_map_key=False)
        except Exception as exc:
            raise MetasploitRPCError(f"RPC request failed: {type(exc).__name__}") from exc
        if isinstance(result, dict) and (result.get("error") or result.get("error_class")):
            raise MetasploitRPCError(str(result.get("error_message") or result.get("error"))[:500])
        return result

    def login(self):
        result = self._post(["auth.login", self.username, self.password])
        if not isinstance(result, dict) or result.get("result") != "success" or not result.get("token"):
            raise MetasploitRPCError("Metasploit login failed")
        self.token = result["token"]
        return True

    def _call(self, method, *args):
        if not self.token:
            self.login()
        return self._post([method, self.token, *args])

    def version(self):
        return self._call("core.version")

    def search_modules(self, query: str):
        result = self._call("module.search", query)
        if isinstance(result, dict):
            result = result.get("modules", result.get("results", []))
        if not isinstance(result, list):
            raise MetasploitRPCError("Unexpected module.search response")
        return [row for row in result if isinstance(row, dict)]

    def module_info(self, module_type: str, module_name: str):
        self._validate_module(module_type, module_name)
        result = self._call("module.info", module_type, module_name)
        if not isinstance(result, dict):
            raise MetasploitRPCError("Unexpected module.info response")
        return result

    def module_options(self, module_type: str, module_name: str):
        self._validate_module(module_type, module_name)
        result = self._call("module.options", module_type, module_name)
        if not isinstance(result, dict):
            raise MetasploitRPCError("Unexpected module.options response")
        return result

    @staticmethod
    def _validate_module(module_type, module_name):
        import re
        if module_type not in {"exploit", "auxiliary", "post"}:
            raise ValueError("Unsupported module type")
        if not re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", module_name) or ".." in module_name.split("/"):
            raise ValueError("Invalid module name")

    def close(self):
        self.token = None
        if self.session is not None and hasattr(self.session, "close"):
            self.session.close()
