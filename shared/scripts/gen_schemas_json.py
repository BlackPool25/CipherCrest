from __future__ import annotations

import json
import pathlib
import sys


def main() -> None:
    # Ensure project root on sys.path so `import shared.schemas` works when
    # invoked as `python shared/scripts/gen_schemas_json.py`
    project_root = pathlib.Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    import shared.schemas
    out_path = pathlib.Path(__file__).resolve().parents[1] / "schemas.json"
    schema = shared.schemas.FlowVerdict.model_json_schema()
    # Ensure draft 2020-12 compatible structure (title + $defs)
    out_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out_path} title={schema.get('title')} $defs={list(schema.get('$defs', {}).keys())}")


if __name__ == "__main__":
    main()
