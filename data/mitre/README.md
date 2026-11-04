# Historical MITRE ATT&CK corpora

These directories preserve the raw JSON context supplied to the retrieval step in
the original experiments:

- `opnotes/` contains the ten tactic-specific JSON lists used by the OPNOTES
  scripts.
- `suricata/` contains the thirteen category documents indexed by the Suricata
  script.

The two corpora intentionally remain separate. Their schemas and raw text differ,
and replacing either with a newly downloaded ATT&CK release could change retrieval
and model output.

The original files did not record an ATT&CK release number or retrieval date.
They also contain historical formatting inconsistencies. In particular, field
capitalization varies, and the Suricata Exfiltration document labels its category
ID as `TA0003` even though Exfiltration is `TA0010`. The files are retained
unchanged for research fidelity.

These are MITRE ATT&CK reference descriptions, not GAMBIT experiment results.
MITRE's copyright designation and license are reproduced in
`MITRE_LICENSE.txt`.
