"""Request/response models. Kept separate from `core.client_report`'s own
`ConsolidatedFinding`/`RunReportData` dataclasses deliberately — those are
internal pipeline shapes; these are the public HTTP contract, allowed to
evolve independently of the engine's internals.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CreateAccountResponse(BaseModel):
    account_id: str
    api_key: str = Field(
        description="Shown exactly once. Store it now — it cannot be retrieved again, only revoked/rotated."
    )
    key_id: str


class CreateApiKeyResponse(BaseModel):
    key_id: str
    api_key: str = Field(description="Shown exactly once, same as account creation.")


class RotateKeyResponse(BaseModel):
    old_key_id: str
    old_key_valid_until: str
    new_key_id: str
    new_api_key: str = Field(description="Shown exactly once.")


class CreateScanRequest(BaseModel):
    domain: str = Field(min_length=1, description="Target domain, e.g. example.com")


class CreateScanResponse(BaseModel):
    scan_id: str
    status: Literal["queued"]


class ScanStatusResponse(BaseModel):
    scan_id: str
    domain: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: str
    updated_at: str
    error_message: str | None = None


class ClientReportRequest(BaseModel):
    format: Literal["markdown", "docx"] = "markdown"
    language: Literal["en", "es"] = "es"
    white_label: bool = Field(
        default=False, description="Ultra-tier only — omits Hydra's own branding from the report."
    )


class ErrorResponse(BaseModel):
    error: str
    detail: str


class RegisterDomainRequest(BaseModel):
    domain: str = Field(min_length=1, description="Domain to verify, e.g. example.com")


class DnsInstructions(BaseModel):
    record_type: Literal["TXT"] = "TXT"
    name: str
    value: str


class FileInstructions(BaseModel):
    path: str
    content: str


class RegisterDomainResponse(BaseModel):
    domain: str
    token: str
    dns_instructions: DnsInstructions
    file_instructions: FileInstructions


class VerifyDomainRequest(BaseModel):
    method: Literal["dns_txt", "well_known_file"]


class VerifyDomainResponse(BaseModel):
    domain: str
    status: Literal["verified"]
    method: Literal["dns_txt", "well_known_file"]
    verified_at: str
    expires_at: str


# --- Part B/D: tiers, subscription management, Wompi (Round 3) --------


class SubscriptionResponse(BaseModel):
    tier: Literal["free", "medium", "pro", "ultra"]
    status: Literal["active", "past_due", "suspended"]
    scans_used_this_period: int
    scans_limit: int
    verified_domains_count: int
    verified_domains_limit: int | None = None
    grace_period_started_at: str | None = None
    retention_days: int


class CreateSubscriptionRequest(BaseModel):
    tier: Literal["free", "medium", "pro", "ultra"]
    billing_email: str | None = Field(
        default=None,
        description=(
            "Required for medium/pro/ultra — the email you will use when enrolling at the "
            "returned Wompi payment link, used to match the resulting webhook back to this "
            "account. Not needed for tier=free (no payment involved)."
        ),
    )


class CreateSubscriptionResponse(BaseModel):
    tier: Literal["free", "medium", "pro", "ultra"]
    status: Literal["active", "past_due", "suspended"]
    payment_url: str | None = Field(
        default=None, description="Set only when tier != free — the Wompi enrollment link."
    )
    previous_tier: str | None = None
    exceeds_domain_limit: bool = False
    exceeds_scan_limit: bool = False


class WompiReconcileRequest(BaseModel):
    unmatched_id: str
    account_id: str
    tier: Literal["medium", "pro", "ultra"]


class WompiReconcileResponse(BaseModel):
    unmatched_id: str
    account_id: str
    tier: str
    status: Literal["resolved"]


# --- Part E.1 extended to assess-reportability / suggest-hypotheses ----
#
# Part E.1's original sketch showed the estimate call as a bare `GET
# .../reportability-estimate?program_rules_id=...`, implying the rules
# text was already stored server-side under that id. No such storage
# mechanism exists (a client has no way to have uploaded it in advance),
# so this round's actual estimate endpoint is a `POST` carrying the
# rules text directly in the body — a large program-rules document does
# not fit in a query string. It keeps the same non-mutating, repeatable-
# without-spending-anything semantics the original sketch called for
# (the only side effect is a bookkeeping `cost_estimates` row, the same
# shape `POST /domains` already has in Round 2); only the HTTP verb
# differs from the original sketch, documented here and in
# docs/PAID_API_DESIGN.md's "Round 3 implemented" section.


class ReportabilityEstimateRequest(BaseModel):
    program_rules_text: str = Field(min_length=1)
    severity: str | None = Field(default=None, description="Comma-separated, e.g. 'high,critical'")
    host: str | None = None
    limit: int | None = None
    provider: Literal["anthropic", "openai"] | None = None
    adversarial_provider: Literal["anthropic", "openai"] | None = None


class ReportabilityEstimateResponse(BaseModel):
    estimate_id: str
    estimated_cost_usd: float
    expires_at: str
    findings_count: int
    provider: str
    adversarial_provider: str | None = None
    degraded_from_adversarial: bool = False


class ReportabilityAssessmentRequest(BaseModel):
    estimate_id: str
    confirm: bool = False


class ReportabilityAssessmentResponse(BaseModel):
    assessed_count: int
    eligible_count: int
    not_eligible_count: int
    uncertain_count: int
    cross_validated: bool
    degraded_from_adversarial: bool = False
    actual_cost_usd: float


class HypothesesEstimateRequest(BaseModel):
    limit: int | None = None
    provider: Literal["anthropic", "openai"] | None = None
    adversarial_provider: Literal["anthropic", "openai"] | None = None


class HypothesesEstimateResponse(BaseModel):
    estimate_id: str
    estimated_cost_usd: float
    expires_at: str
    relationships_count: int
    provider: str
    adversarial_provider: str | None = None
    degraded_from_adversarial: bool = False


class HypothesesAssessmentRequest(BaseModel):
    estimate_id: str
    confirm: bool = False


class HypothesesAssessmentResponse(BaseModel):
    hypotheses_count: int
    trustworthy_count: int
    degraded_from_adversarial: bool = False
    actual_cost_usd: float
