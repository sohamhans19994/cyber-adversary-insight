"""Injected LLM and retrieval clients.

No client is constructed and no environment variable is read at import time.
The online adapter intentionally uses the same LlamaIndex completion and vector
query paths as the research implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from gambit.errors import LLMConfigurationError

_FAKE_TIMESTAMP_PATTERN = (
    r"\b(?:"
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?"
    r"|"
    r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(?::\d{2})?"
    r")\b"
)
_DEFAULT_CONTEXT_WINDOW = 128_000
_UNAUTHENTICATED_ENDPOINT_KEY = "not-required"


def normalize_openai_api_base(value: str) -> str:
    """Validate an OpenAI-compatible server URL and ensure its `/v1` suffix."""

    candidate = value.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise LLMConfigurationError(
            "OpenAI-compatible API base must be an absolute http:// or https:// URL"
        )
    if parsed.username or parsed.password:
        raise LLMConfigurationError(
            "OpenAI-compatible API base must not contain credentials; "
            "use environment variables for API keys"
        )
    if parsed.query or parsed.fragment:
        raise LLMConfigurationError(
            "OpenAI-compatible API base must not contain a query or fragment"
        )
    path = parsed.path.rstrip("/")
    if not path.casefold().endswith("/v1"):
        path += "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _openai_compatible_llm(
    openai_class: type[Any],
    metadata_class: type[Any],
    *,
    model: str,
    api_base: str,
    api_key: str,
    context_window: int,
    max_output_tokens: int | None,
    temperature: float,
    timeout_seconds: float,
) -> Any:
    """Construct a LlamaIndex OpenAI client without its OpenAI model registry."""

    class GenericOpenAI(openai_class):
        context_window: int = _DEFAULT_CONTEXT_WINDOW

        @property
        def metadata(self) -> Any:
            return metadata_class(
                context_window=self.context_window,
                num_output=self.max_tokens or -1,
                is_chat_model=True,
                is_function_calling_model=False,
                model_name=self.model,
            )

    return GenericOpenAI(
        model=model,
        api_base=api_base,
        api_key=api_key,
        context_window=context_window,
        max_tokens=max_output_tokens,
        temperature=temperature,
        timeout=timeout_seconds,
    )


def _normalize_fake_timestamp(value: str) -> str:
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(value.replace("T", " "), pattern).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue
    return value.replace("T", " ")


@dataclass(frozen=True)
class QueryResult:
    text: str
    context: str = ""


@dataclass(frozen=True)
class QueryDocument:
    text: str
    file_path: str


class LLMClient(Protocol):
    model_name: str

    def complete(self, prompt: str) -> str:
        """Return an ordinary text completion."""

    def query(
        self, prompt: str, documents: Sequence[QueryDocument]
    ) -> QueryResult:
        """Query a vector index built from the supplied documents."""

    def chat(self, messages: Sequence[Mapping[str, str]]) -> str:
        """Return a chat response while preserving message roles."""


class OpenAIClient:
    """LlamaIndex adapter for OpenAI and OpenAI-compatible endpoints."""

    def __init__(
        self,
        model: str,
        *,
        timeout_seconds: float = 100,
        temperature: float = 0.1,
        embedding_model: str = "text-embedding-ada-002",
        api_base: str | None = None,
        embedding_api_base: str | None = None,
        context_window: int = _DEFAULT_CONTEXT_WINDOW,
        max_output_tokens: int | None = None,
    ) -> None:
        if context_window < 1:
            raise LLMConfigurationError("context window must be at least 1")
        if max_output_tokens is not None and max_output_tokens < 1:
            raise LLMConfigurationError("max output tokens must be at least 1")

        resolved_api_base = normalize_openai_api_base(api_base) if api_base else None
        resolved_embedding_base = (
            normalize_openai_api_base(embedding_api_base)
            if embedding_api_base
            else resolved_api_base
        )
        resolved_key = os.getenv("OPENAI_API_KEY")
        resolved_embedding_key = os.getenv("GAMBIT_EMBEDDING_API_KEY") or resolved_key
        if not resolved_key and resolved_api_base is None:
            raise LLMConfigurationError(
                "OPENAI_API_KEY is required for online analysis; "
                "a custom unauthenticated --api-base, installation, parsing, "
                "and offline mode do not need it"
            )
        request_key = resolved_key or _UNAUTHENTICATED_ENDPOINT_KEY
        embedding_request_key = (
            resolved_embedding_key or _UNAUTHENTICATED_ENDPOINT_KEY
        )
        try:
            from llama_index.core import Document, VectorStoreIndex
            from llama_index.core.llms import ChatMessage, LLMMetadata
            from llama_index.embeddings.openai import OpenAIEmbedding
            from llama_index.llms.openai import OpenAI
        except ImportError as exc:
            raise LLMConfigurationError(
                "online analysis requires the optional dependencies: "
                "install this repository with 'pip install \".[openai]\"'"
            ) from exc

        self.model_name = model
        if resolved_api_base is None:
            self._llm = OpenAI(
                model=model,
                timeout=timeout_seconds,
                temperature=temperature,
                api_key=request_key,
                max_tokens=max_output_tokens,
            )
        else:
            self._llm = _openai_compatible_llm(
                OpenAI,
                LLMMetadata,
                model=model,
                api_base=resolved_api_base,
                api_key=request_key,
                context_window=context_window,
                max_output_tokens=max_output_tokens,
                temperature=temperature,
                timeout_seconds=timeout_seconds,
            )

        embedding_options = {
            "api_key": embedding_request_key,
            "api_base": resolved_embedding_base,
            "timeout": timeout_seconds,
        }
        if resolved_embedding_base is None:
            self._embedding = OpenAIEmbedding(
                model=embedding_model,
                **embedding_options,
            )
        else:
            self._embedding = OpenAIEmbedding(
                model_name=embedding_model,
                **embedding_options,
            )

        self.manifest_identity = f"{model}; embedding={embedding_model}"
        if resolved_api_base is not None or resolved_embedding_base is not None:
            generation_endpoint = resolved_api_base or "OpenAI default"
            embedding_endpoint = resolved_embedding_base or "OpenAI default"
            self.manifest_identity = (
                f"{model} @ {generation_endpoint}; "
                f"embedding={embedding_model} @ {embedding_endpoint}; "
                f"context_window={context_window}"
            )
        self._Document = Document
        self._VectorStoreIndex = VectorStoreIndex
        self._ChatMessage = ChatMessage
        self._query_engines: dict[str, Any] = {}

    def complete(self, prompt: str) -> str:
        return self._llm.complete(prompt).text

    def query(
        self, prompt: str, documents: Sequence[QueryDocument]
    ) -> QueryResult:
        digest = hashlib.sha256()
        for document in documents:
            digest.update(document.file_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(document.text.encode("utf-8"))
            digest.update(b"\0")
        cache_key = digest.hexdigest()
        query_engine = self._query_engines.get(cache_key)
        if query_engine is None:
            nodes = [
                self._Document(
                    text=document.text,
                    metadata={"file_path": document.file_path},
                )
                for document in documents
            ]
            index = self._VectorStoreIndex.from_documents(
                nodes,
                embed_model=self._embedding,
            )
            query_engine = index.as_query_engine(llm=self._llm)
            self._query_engines[cache_key] = query_engine
        response = query_engine.query(prompt)
        context = "\n\n".join(
            node.node.get_content() for node in response.source_nodes[:5]
        )
        return QueryResult(text=response.response, context=context)

    def chat(self, messages: Sequence[Mapping[str, str]]) -> str:
        converted = [
            self._ChatMessage(role=message["role"], content=message["content"])
            for message in messages
        ]
        return self._llm.chat(converted).message.content or ""


class DeterministicFakeLLM:
    """Credential-free test double with optional scripted raw responses."""

    model_name = "deterministic-fake"

    def __init__(
        self,
        responses: Sequence[str | Mapping[str, Any] | Exception] | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self.call_count = 0
        self.prompts: list[str] = []

    def _next(self, prompt: str) -> str | None:
        self.call_count += 1
        self.prompts.append(prompt)
        if not self._responses:
            return None
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, str):
            return response
        return json.dumps(response)

    def complete(self, prompt: str) -> str:
        scripted = self._next(prompt)
        if scripted is not None:
            return scripted

        if "Split this into a  list of different actions" in prompt:
            timestamps = re.findall(
                _FAKE_TIMESTAMP_PATTERN,
                prompt.split("Split this into", 1)[0],
            )
            timestamp = timestamps[0] if timestamps else "1970-01-01 00:00:00"
            return (
                "1. **Recorded Activity**\n"
                f"   - **Timestamp:** {timestamp}\n"
                "   - Action: Recorded the supplied operator activity."
            )
        if "Convert the following structured text into a json list" in prompt:
            timestamps = re.findall(
                _FAKE_TIMESTAMP_PATTERN,
                prompt.split("Here is an example", 1)[0],
            )
            timestamp = timestamps[0] if timestamps else "1970-01-01 00:00:00"
            return json.dumps(
                [
                    {
                        "title": "Recorded Activity",
                        "timestamp": _normalize_fake_timestamp(timestamp),
                        "action": "Recorded the supplied operator activity.",
                        "end_timestamp": None,
                    }
                ]
            )
        if "determine if there is a day break" in prompt:
            return json.dumps(
                {
                    "day_break": False,
                    "day_break_reasoning": "Offline deterministic response.",
                    "first_day_end_timestamp": None,
                    "second_day_start_timestamp": None,
                }
            )
        if "marks the start of a new phase" in prompt:
            return json.dumps(
                {
                    "reasoning": "Offline deterministic response.",
                    "phase_start_prediction": False,
                    "summary": "The observed entries remain in the ongoing phase.",
                }
            )
        raise ValueError("fake has no default response for this prompt")

    def query(
        self, prompt: str, documents: Sequence[QueryDocument]
    ) -> QueryResult:
        scripted = self._next(prompt)
        if scripted is not None:
            return QueryResult(
                text=scripted,
                context="\n\n".join(document.text for document in documents[:5]),
            )
        if "MITRE_techniques_detected" in prompt:
            return QueryResult(
                text=json.dumps(
                    {
                        "analysis_in_context_of_previous_chunks": (
                            "Offline deterministic response."
                        ),
                        "MITRE_techniques_detected": [],
                        "updated_memory_summary": "No technique was detected.",
                    }
                ),
                context="\n\n".join(document.text for document in documents[:5]),
            )
        match = re.search(r"^(Is_[A-Za-z_]+|Initial_access):", prompt, re.MULTILINE)
        if match is None:
            raise ValueError("fake cannot identify the tactic response key")
        boolean_key = match.group(1)
        prefix = boolean_key.removeprefix("Is_")
        if boolean_key == "Initial_access":
            prefix = "Initial_access"
        return QueryResult(
            text=json.dumps(
                {
                    boolean_key: False,
                    f"{prefix}_technique_ID": None,
                    f"{prefix}_technique_name": None,
                    "Reasoning": "Offline deterministic response.",
                }
            ),
            context="\n\n".join(document.text for document in documents[:5]),
        )

    def chat(self, messages: Sequence[Mapping[str, str]]) -> str:
        prompt = "\n\n".join(message["content"] for message in messages)
        scripted = self._next(prompt)
        if scripted is not None:
            return scripted
        return json.dumps(
            {
                "analysis_in_context_of_previous_chunks": (
                    "Offline deterministic repair response."
                ),
                "MITRE_techniques_detected": [],
                "updated_memory_summary": "No technique was detected.",
            }
        )
