# Executable knowledge cards

Place reviewed executable YAML cards in this directory. Each file must conform to the `Card` schema in `app/lab/knowledge.py`.

Paths in `environment` and `sources` are resolved relative to this directory. Keep source Markdown, Compose files, scripts, and other declared assets inside the same knowledge root.

A target description is not an execution permission. Keep the approved target fingerprint and its `ExecutionPolicy` separate from target source material.

A card is trusted configuration. Review its allowed services, ports, HTTP probes, scripts, and independent verification criteria before using it.
