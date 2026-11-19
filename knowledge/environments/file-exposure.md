# File exposure demonstration

This is a deliberately configured local fixture, not a real CVE. A Python HTTP
server exposes a directory containing a synthetic canary. Reproduction requests
the canary without authentication; verification requires HTTP 200 and the exact
canary text. No real confidential data is used. Python's version is an environment
dependency, not a claimed vulnerable product version.

```yaml
services:
  web:
    image: python:3.11.11-alpine
    ports:
      - "127.0.0.1:18081:8000"
    command:
      - python
      - -u
      - -c
      - >-
        import pathlib, http.server;
        root = pathlib.Path('/tmp/lab-public');
        root.mkdir(exist_ok=True);
        (root / 'canary.txt').write_text('LOCAL_LAB_CANARY_7f42');
        handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(root), **k);
        http.server.HTTPServer(('0.0.0.0', 8000), handler).serve_forever()
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=2).read()"]
      interval: 2s
      timeout: 3s
      retries: 15
```

Expected evidence: `/canary.txt` returns `LOCAL_LAB_CANARY_7f42`. Removing the file
or restricting access makes the same verification fail. Container health alone
does not meet this assertion.
