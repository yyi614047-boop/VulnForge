"""Enrich a documentary card with inert metadata from a Markdown HTTP example."""
import argparse
import json
import re
from pathlib import Path

import yaml

from app.lab.documented_card import DocumentedCard, RequestShape


def json_type(value):
    return {str: "string", int: "integer", float: "number", bool: "boolean",
            list: "array", dict: "object", type(None): "null"}[type(value)]


def read_example(markdown):
    examples = re.findall(
        r"^```[^\n]*\n([A-Z]+) [^\n]+ HTTP/[\d.]+\n(.*?)^```[ \t]*$",
        markdown, re.MULTILINE | re.DOTALL,
    )
    if len(examples) != 1:
        raise ValueError("Expected one fenced HTTP example")
    method, message = examples[0]
    headers, separator, body = message.partition("\n\n")
    fields = {}
    for line in headers.splitlines():
        name, _, value = line.partition(":")
        fields[name.lower()] = value.strip()
    media = fields.get("content-type", "").partition(";")[0].lower()
    if not separator or media != "application/json":
        raise ValueError("Expected a documented JSON body")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    cookies = [part.partition("=")[0].strip() for part in fields.get("cookie", "").split(";") if "=" in part]
    return method, RequestShape(media_type=media, required_cookie_names=cookies,
                                json_fields={key: json_type(value) for key, value in data.items()})


def compare_document(step, example=None):
    """Compare card claims with a document sample. Missing sample means unknown."""
    rules = []
    def compare(field, operator, expected, actual):
        status = "not_observed" if example is None else "match" if expected == actual else "mismatch"
        rules.append(dict(field=field, operator=operator, expected=expected, observed=actual, status=status))

    method, observed = example or (None, None)
    if step.method:
        compare("method", "equals", step.method, method)
    shape = step.request_shape
    if shape:
        compare("media_type", "equals", shape.media_type, observed.media_type if observed else None)
        for name in shape.required_cookie_names:
            compare("cookie." + name, "present", True, name in observed.required_cookie_names if observed else None)
        for key, kind in shape.json_fields.items():
            compare("json." + key, "type", kind, observed.json_fields.get(key) if observed else None)
    return rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("card", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--enrich", action="store_true", help="Write the extracted shape to the card")
    args = parser.parse_args()
    card = DocumentedCard.model_validate(yaml.safe_load(args.card.read_text(encoding="utf-8")))
    steps = [step for step in card.steps if step.type == "web"]
    if len(steps) != 1:
        parser.error("Expected one web step to associate with the documented example")
    source = (args.root / card.source).resolve()
    if not source.is_relative_to(args.root.resolve()):
        parser.error("Source is outside the document root")
    example = read_example(source.read_text(encoding="utf-8"))
    step = steps[0]
    if args.enrich:
        step.method, step.request_shape = example
        card.write(args.card)
    report = compare_document(step, example)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return int(any(item["status"] == "mismatch" for item in report))


if __name__ == "__main__":
    raise SystemExit(main())
