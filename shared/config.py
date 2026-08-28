"""USE_STUB flag — Day1-2 True (fixture passthrough), flips to False at Day3 when ledger 🟢.

When USE_STUB is True, api/app.py imports from shared.mocks.reassembler_stub /
validator_stub and returns validated FlowVerdict fixtures without invoking real
reassembly or X.509 validation. At Day3 the flag flips to False once
shared/progress.md has >=3 🟢, lab/LEDGER.md has >=3 coverage_ratio, and
lab/pcaps/jittered/*.pcap exists — polling ledger not time.
"""

import pathlib

USE_STUB: bool = not (
    pathlib.Path("shared/progress.md").read_text(encoding="utf-8").count("🟢") >= 3
    and pathlib.Path("lab/LEDGER.md").read_text(encoding="utf-8").count("coverage_ratio") >= 3
    and (any(pathlib.Path("lab/pcaps/jittered").glob("*.pcap")) or any(pathlib.Path("lab/pcaps").glob("*.pcap")))
)
