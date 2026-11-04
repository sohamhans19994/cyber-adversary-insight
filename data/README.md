# Research inputs and reference context

`run_experiments.py` reads the conventional reproduction layout from this
directory.

- `opnotes/example.ctd` is an invented CherryTree-style OPNOTES document.
- `suricata/example.csv` is an invented combined Suricata alert stream.
- `mitre/opnotes/` preserves the ATT&CK JSON documents used by the original
  per-tactic OPNOTES analysis.
- `mitre/suricata/` preserves the ATT&CK JSON documents used by the original
  Suricata analysis.

The CTD and CSV are deliberately small, wholly invented examples. They preserve
the source shapes and exercise the research stages, but they cannot reproduce the
study results. An authorized reproduction can point `ExperimentSettings` at
private inputs stored outside this repository. Do not commit those inputs or any
generated outputs.

The MITRE directories are historical retrieval context, not experiment
observations or model results. See `mitre/README.md` and `mitre/MITRE_LICENSE.txt`.
