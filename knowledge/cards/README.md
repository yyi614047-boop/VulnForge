# Executable knowledge cards

Place reviewed executable YAML cards in this directory. Each file must conform to the `Card` schema in `app/lab/knowledge.py`.

Paths in `environment` and `sources` are resolved relative to this directory. Keep source Markdown, Compose files, scripts, and other declared assets inside the same knowledge root.

Do not copy files from `knowledge/evaluation-cards/` here: those are documentary evidence summaries and do not contain the execution permissions or independent assertions required by the Pipeline.

A card is trusted configuration. Review its allowed services, ports, HTTP probes, scripts, and independent verification criteria before using it.
