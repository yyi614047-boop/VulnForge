"""CVE search and basic module inspection."""
import re
from app.integrations.metasploit.models import ModuleMetadata, PoCCandidate

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class MetasploitDiscovery:
    def __init__(self, client):
        self.client = client

    def search_cve(self, cve_id: str, limit: int = 50) -> list[PoCCandidate]:
        cve_id = cve_id.strip().upper()
        if not _CVE.fullmatch(cve_id):
            raise ValueError("Invalid CVE identifier")
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        rows = self.client.search_modules(f"cve:{cve_id}")
        found, seen = [], set()
        for row in rows:
            kind = str(row.get("type", "")).lower()
            if kind not in {"exploit", "auxiliary", "post"}:
                continue
            fullname = str(row.get("fullname") or "")
            prefix = kind + "/"
            name = fullname[len(prefix):] if fullname.startswith(prefix) else str(row.get("name") or fullname)
            if not name or (kind, name) in seen:
                continue
            seen.add((kind, name))
            found.append(PoCCandidate(candidate_id=f"metasploit:{kind}:{name}", module_type=kind,
                module_name=name, fullname=fullname or f"{kind}/{name}", rank=row.get("rank"), cve_ids=[cve_id]))
            if len(found) >= limit:
                break
        return found

    def inspect(self, candidate: PoCCandidate) -> ModuleMetadata:
        info = self.client.module_info(candidate.module_type, candidate.module_name)
        options = self.client.module_options(candidate.module_type, candidate.module_name)
        refs = info.get("references", [])
        targets = info.get("targets", [])
        return ModuleMetadata(module_type=candidate.module_type, module_name=candidate.module_name,
            name=str(info.get("name") or candidate.fullname), description=str(info.get("description") or ""),
            rank=info.get("rank", candidate.rank),
            references=[x for x in refs if isinstance(x, dict)] if isinstance(refs, list) else [],
            targets=[str(x) for x in targets] if isinstance(targets, list) else [],
            options={str(k): v for k, v in options.items() if isinstance(v, dict)})
