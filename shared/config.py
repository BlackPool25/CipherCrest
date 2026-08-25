"""USE_STUB flag — Day1-2 True (fixture passthrough), flips to False at Day3 when reassembled/*.bin green.

When USE_STUB is True, api/app.py imports from shared.mocks.reassembler_stub /
validator_stub and returns validated FlowVerdict fixtures without invoking real
reassembly or X.509 validation. At Day3 the flag flips to False once
lab/reassembler/reassemble.py produces reassembled/*.bin with coverage green,
at which point the real pipeline is wired and stubs become fallback only.
"""

USE_STUB: bool = True
