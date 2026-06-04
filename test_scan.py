import sys, asyncio
sys.path.insert(0, 'C:/Users/Nakul/vibesec')
from pathlib import Path
from app.agents.repo_agent import _scan_secrets, _scan_ast_patterns, _scan_dependencies, _check_reachability

repo = Path('C:/Users/Nakul/vibesec/test_vuln_repo')

secrets  = _scan_secrets(repo)
ast_hits = _scan_ast_patterns(repo)
deps     = _scan_dependencies(repo)
enriched = _check_reachability(repo, ast_hits)

print("=== SECRETS ===")
for s in secrets:
    print(f"  [{s['severity'].upper():8}] {s['type']} @ {s['file']}:{s['line']}")

print(f"\n=== AST FINDINGS ({len(enriched)}) ===")
for a in enriched:
    reach = a.get('reachable')
    auth  = a.get('auth_protected')
    print(f"  [{a['severity'].upper():8}] {a['type']} @ {a['file']}:{a['line']}  | reachable={reach} auth={auth}")

print(f"\n=== DEPENDENCY CVEs ({len(deps)}) ===")
for d in deps:
    print(f"  [{d['severity'].upper():8}] {d['type']}")
    print(f"             {d['detail'][:100]}")

print(f"\nTotal findings: {len(secrets) + len(enriched) + len(deps)}")
