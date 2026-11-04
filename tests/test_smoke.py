from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from gambit.errors import ResumeError
from gambit.llm import DeterministicFakeLLM, OpenAIClient, normalize_openai_api_base
from gambit.models import RunManifest
from gambit.pipeline import run_analysis

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("source", ["opnotes", "suricata"])
@pytest.mark.parametrize("api_base", [None, "http://localhost:8080/v1"])
def test_resume_rejects_changed_embedding_model(tmp_path, monkeypatch, source, api_base):
    monkeypatch.setenv("OPENAI_API_KEY", "unused-test-key")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("GAMBIT_EMBEDDING_API_KEY", raising=False)
    fake = DeterministicFakeLLM()

    def client(embedding_model):
        adapter = OpenAIClient(
            "gpt-4o", embedding_model=embedding_model, api_base=api_base
        )
        # Exercise real client identities without making model or embedding requests.
        monkeypatch.setattr(adapter, "complete", fake.complete)
        monkeypatch.setattr(adapter, "query", fake.query)
        monkeypatch.setattr(adapter, "chat", fake.chat)
        return adapter

    original = client("text-embedding-ada-002")
    input_name = "example.ctd" if source == "opnotes" else "example.csv"
    options = {
        "source": source,
        "input_path": ROOT / "data" / source / input_name,
        "mitre_corpus_path": ROOT / "data" / "mitre" / source,
        "output_dir": tmp_path,
    }
    run_analysis(**options, primary_llm=original, utility_llm=original)
    manifest_path = tmp_path / "run_manifest.json"
    manifest = RunManifest.model_validate_json(manifest_path.read_text())
    assert "text-embedding-ada-002" in manifest.primary_model
    assert "text-embedding-ada-002" in manifest.utility_model

    calls = fake.call_count
    unchanged = client("text-embedding-ada-002")
    run_analysis(**options, primary_llm=unchanged, utility_llm=unchanged)
    assert fake.call_count == calls
    saved_manifest = manifest_path.read_bytes()

    changed = client("text-embedding-3-small")
    with pytest.raises(ResumeError, match="primary_model, utility_model"):
        run_analysis(**options, primary_llm=changed, utility_llm=changed)
    assert fake.call_count == calls
    assert manifest_path.read_bytes() == saved_manifest


def test_generic_openai_endpoint_accepts_arbitrary_models_without_a_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GAMBIT_EMBEDDING_API_KEY", raising=False)

    assert normalize_openai_api_base("http://localhost:8080/") == (
        "http://localhost:8080/v1"
    )
    client = OpenAIClient(
        "local-generation-model",
        api_base="http://localhost:8080/",
        embedding_model="local-embedding-model",
        context_window=131_072,
    )

    assert client.model_name == "local-generation-model"
    assert client._llm.metadata.is_chat_model is True
    assert client._llm.metadata.context_window == 131_072
    assert client._embedding.model_name == "local-embedding-model"


def test_published_examples_run_end_to_end_without_credentials(tmp_path):
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "run_experiments.py"),
            "--offline",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": str(Path(sys.executable).parent)},
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "OPNOTES:" in completed.stdout
    assert "Suricata:" in completed.stdout

    for source in ("opnotes", "suricata"):
        output = tmp_path / source
        assert (output / "actions.json").is_file()
        assert (output / "phases.json").is_file()
        assert (output / "mitre_findings.json").is_file()
        manifest = RunManifest.model_validate_json(
            (output / "run_manifest.json").read_text(encoding="utf-8")
        )
        assert manifest.status == "completed"
