from typing import TypedDict

class PipelineState(TypedDict, total=False):
    identifier: str
    bundle: dict
    plan: dict
    report: dict
    error: str
    status: str
    engine: dict
