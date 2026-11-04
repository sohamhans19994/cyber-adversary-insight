"""Validated records passed between research stages."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gambit.time_utils import normalize_datetime


class ExperimentRecord(BaseModel):
    """Strict base record shared by serialized experiment stages."""

    model_config = ConfigDict(extra="forbid")


class OpNoteEntry(ExperimentRecord):
    timestamp: datetime
    text: str = Field(min_length=1)

    _normalize_timestamp = field_validator("timestamp", mode="before")(normalize_datetime)


class OpNoteDocument(ExperimentRecord):
    source_id: str = Field(min_length=1)
    entries: list[OpNoteEntry]
    source_text: str | None = Field(default=None, repr=False)


class SuricataEvent(ExperimentRecord):
    timestamp: datetime
    src_ip: str = Field(min_length=1)
    dest_ip: str = Field(min_length=1)
    alert: dict[str, Any]
    end_timestamp: datetime | None = None
    occurrence_count: int = Field(default=1, ge=1)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = None
    app_proto: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    network_fields: dict[str, Any] = Field(default_factory=dict)

    _normalize_timestamp = field_validator("timestamp", mode="before")(normalize_datetime)
    _normalize_end_timestamp = field_validator("end_timestamp", mode="before")(lambda value: (
        normalize_datetime(value) if value is not None else None
    ))

    @model_validator(mode="after")
    def validate_interval(self) -> SuricataEvent:
        if self.end_timestamp is not None and self.end_timestamp < self.timestamp:
            raise ValueError("end_timestamp cannot precede timestamp")
        return self


class Action(ExperimentRecord):
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    start_timestamp: datetime | None
    end_timestamp: datetime | None
    duration_seconds: float | None = Field(default=None, ge=0)
    original: dict[str, Any] = Field(default_factory=dict)

    _normalize_start = field_validator("start_timestamp", mode="before")(lambda value: (
        normalize_datetime(value) if value is not None else None
    ))
    _normalize_end = field_validator("end_timestamp", mode="before")(lambda value: (
        normalize_datetime(value) if value is not None else None
    ))

    @model_validator(mode="after")
    def validate_interval(self) -> Action:
        if self.start_timestamp is None or self.end_timestamp is None:
            if self.duration_seconds is not None:
                raise ValueError("duration_seconds requires valid start and end timestamps")
            return self
        if self.end_timestamp < self.start_timestamp:
            raise ValueError("end_timestamp cannot precede start_timestamp")
        expected = (self.end_timestamp - self.start_timestamp).total_seconds()
        if self.duration_seconds is None or abs(self.duration_seconds - expected) > 0.001:
            raise ValueError("duration_seconds must match the timestamp interval")
        return self


class AttackPhase(ExperimentRecord):
    summary: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    start_timestamp: datetime
    end_timestamp: datetime
    events: list[SuricataEvent] = Field(min_length=1)
    differences: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)
    new_phase_start_summary: str = ""

    _normalize_start = field_validator("start_timestamp", mode="before")(normalize_datetime)
    _normalize_end = field_validator("end_timestamp", mode="before")(normalize_datetime)

    @model_validator(mode="after")
    def validate_interval(self) -> AttackPhase:
        if self.end_timestamp < self.start_timestamp:
            raise ValueError("end_timestamp cannot precede start_timestamp")
        return self


class MitreFinding(ExperimentRecord):
    category: str = Field(min_length=1)
    technique_id: str = Field(pattern=r"^T\d{4}$")
    technique_name: str = Field(min_length=1)
    reasoning: str = Field(min_length=1)
    timestamps: list[datetime] = Field(default_factory=list)
    subtechnique_id: str | None = Field(
        default=None, pattern=r"^T\d{4}\.\d{3}$"
    )
    subtechnique_name: str | None = None
    action_title: str | None = None
    action_description: str | None = None
    start_timestamp: datetime | None = None
    end_timestamp: datetime | None = None
    time_spent: float | None = Field(default=None, ge=0)

    @field_validator("timestamps", mode="before")
    @classmethod
    def normalize_timestamps(cls, values: Any) -> list[datetime]:
        if not isinstance(values, list):
            raise ValueError("timestamps must be a list")
        return [normalize_datetime(value) for value in values]

    _normalize_start = field_validator("start_timestamp", mode="before")(lambda value: (
        normalize_datetime(value) if value is not None else None
    ))
    _normalize_end = field_validator("end_timestamp", mode="before")(lambda value: (
        normalize_datetime(value) if value is not None else None
    ))


class RunManifest(ExperimentRecord):
    source_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    corpus_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    prompt_version: str
    primary_model: str
    utility_model: str
    configuration: dict[str, Any]
    started_at: datetime
    completed_at: datetime | None = None
    stages_completed: list[str] = Field(default_factory=list)
    status: Literal["running", "completed", "interrupted", "failed"] = "running"

    _normalize_started = field_validator("started_at", mode="before")(normalize_datetime)
    _normalize_completed = field_validator("completed_at", mode="before")(lambda value: (
        normalize_datetime(value) if value is not None else None
    ))
