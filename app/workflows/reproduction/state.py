from typing import TypedDict

class PipelineState(TypedDict, total=False):
    identifier: str
    bundle: dict
    plan: dict
    target_spec: dict
    reproduction_spec: dict
    report: dict
    error: str
    status: str
    engine: dict
    poc_execution: dict
    deployment_ready: bool
