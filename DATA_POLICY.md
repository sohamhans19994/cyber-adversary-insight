# Data policy

## Purpose

This repository contains source code, two explicitly synthetic example inputs, and
attributed public MITRE ATT&CK reference snapshots. Real research input and model
output must remain outside both the publication working tree and repository
history.

## Prohibited material

Do not add:

- Participant, subject, customer, or employee identifiers
- Real CTD files, operator notes, key logs, packet captures, or network archives
- Suricata or other security logs from real environments
- Real internal IP addresses, credentials, tokens, secret-bearing environment
  files, or machine-specific absolute paths
- Raw or derived study results, evaluation tables, analyst comparisons, or caches
- Notebooks or notebook outputs
- PDFs, presentations, office documents, archives, or copied web pages
- A copied reference corpus or other material without documented redistribution
  rights and attribution
- Prompts or examples derived from private data

Generated actions, phases, findings, embeddings, summaries, manifests, and
aggregates are derived data and receive the same protection as their inputs.

## Allowed publication data

The only experiment inputs authorized for publication are:

- `data/opnotes/example.ctd`
- `data/suricata/example.csv`

Every identity, event, timestamp, filename, and network address in those examples
was invented for publication. Network examples use documentation address ranges.
Never sanitize a real record and call it synthetic; create publication examples
independently from the behavior the check needs to exercise.

`data/mitre/` is a separate category. It contains public reference descriptions,
not experiment observations. The two raw historical corpus layouts are retained
for retrieval fidelity under MITRE's reproduced license and copyright designation.

`docs/index.html` and `docs/assets/research-walkthrough.webp` are approved
presentation assets. They contain a pre-scripted scenario built from invented
events and are not experiment observations, model output, or study results.

## Authorized reproduction boundary

An authorized researcher may replace the example files locally, or keep private
input and output in directories outside the repository and provide those paths
through `ExperimentSettings` or the root experiment file's optional arguments. Do
not create symlinks to private material within the publication working tree. Run
private reproduction checks locally and publish only conclusions that have
separate authorization.

## Pre-publication checklist

- Install into a fresh virtual environment.
- Run all offline tests with network access and credentials absent.
- Run the default synthetic experiment file in offline mode.
- Run private acceptance tests with all input and output outside the repository.
- Run Ruff, the local smoke test, secret scanning, and
  `scripts/scan_repository.py`.
- Inspect `git ls-files` for identifiers, private paths, input, derived results,
  notebooks, and binary research artifacts.
- Inspect repository history from the first commit.
- Confirm that code-publication authorization is documented separately.
- Manually review the repository while it is private before changing visibility.
