import json
from typing import Literal

from pydantic import BaseModel, Field, ValidationError


class SupportingEvidence(BaseModel):
    source_type: Literal["alert", "historical_alert", "demo_incident", "cisa_kev", "nvd", "virustotal"]
    source_id: str
    claim: str
    evidence: str


class AssessmentOutput(BaseModel):
    summary: str = Field(min_length=1)
    suggested_classification: Literal["likely_true_positive", "likely_false_positive", "needs_review"]
    observed_facts: list[str] = Field(default_factory=list, max_length=30)
    interpretation: str = ""
    supporting_evidence: list[SupportingEvidence] = Field(default_factory=list, max_length=30)
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    recommended_steps: list[str] = Field(default_factory=list, max_length=20)


class InvalidModelOutput(Exception):
    pass


def parse_assessment(content: str, valid_refs: set[tuple[str, str]]) -> AssessmentOutput:
    """Parse and validate model output.

    Valid JSON is not proof of correctness, but every cited source must exist in the
    evidence package that was sent. Raises InvalidModelOutput otherwise.
    """
    try:
        output = AssessmentOutput.model_validate(json.loads(content))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise InvalidModelOutput(f"Output did not match the assessment schema ({type(exc).__name__}).") from exc

    unknown = [e for e in output.supporting_evidence if (e.source_type, e.source_id) not in valid_refs]
    if unknown:
        raise InvalidModelOutput("Output cited evidence that was not in the supplied package.")
    return output
