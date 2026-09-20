# scripts/

These moved into the package so an installed copy has them too. Use the CLI:

| was | now |
|---|---|
| `python scripts/generate_packets.py` | `threat-detector generate` |
| `python scripts/check_detection.py` | `threat-detector selfcheck` |
| `python scripts/inspect_model.py` | `threat-detector inspect` |
| `python run.py` | `threat-detector serve` |

`benchmark_models.py` and `capture_packets.py` stay here: they are development
and research tools, not part of what the application does.
