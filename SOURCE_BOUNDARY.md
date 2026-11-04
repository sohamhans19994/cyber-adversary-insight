# Clean-room source boundary

This repository has new history and contains no copied private research data or
generated experiment results.

The implementation may preserve behavior learned from these legacy files only:

- `parser/op_notes_time_parser.py`: timestamp recognition and nested CTD traversal
- `LLM_Semantic_Search/actions_split.py`: action prompts and timing normalization
- The ten tactic scripts under `LLM_Semantic_Search`: per-tactic prompts, query
  sequencing, output combination, and response validation
- `LLM_log_search/suricata.py`: alert parsing, chronological sorting, consecutive
  alert aggregation, phase prompts and processing, sequential MITRE prompt and
  processing, and category/technique response validation

The confirmed-synthetic prompt examples are intentionally preserved for behavioral
fidelity. The exact public MITRE ATT&CK reference JSON used by the original
retrieval steps is included with attribution because its raw text affects model
context. Credentials, API keys, machine-specific absolute paths, participant
identifiers, outputs, and real or derived research data are prohibited.
