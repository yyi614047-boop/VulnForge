# Target material

This directory contains upstream target repositories and environment fixtures. All upstream content is treated as untrusted input. It does not grant permission to build, deploy, execute scripts, or contact external hosts.

The initial adapter is `app/targets/vulhub/loader.py`; it emits `TargetSpec` candidates only. A separate reviewed `ExecutionPolicy` must bind an approved target fingerprint before execution.
