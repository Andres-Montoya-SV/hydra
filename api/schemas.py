"""Request/response models. Kept separate from `core.client_report`'s own
`ConsolidatedFinding`/`RunReportData` dataclasses deliberately — those are
internal pipeline shapes; these are the public HTTP contract, allowed to
evolve independently of the engine's internals.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# A minimal, pragmatic format check — not full RFC 5322 validation
# (pydantic's `EmailStr` would need the `email-validator` extra, a new
# dependency this fix doesn't need: the real proof of a working address
# is the verification email actually arriving and its token being used,
# not a stricter regex at the door).
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CreateAccountRequest(BaseModel):
    email: str = Field(
        description="Required — a verification link is sent here before the account can scan."
    )

    @field_validator("email")
    @classmethod
    def _looks_like_an_email(cls, value: str) -> str:
        if not _EMAIL_PATTERN.match(value.strip()):
            raise ValueError("must look like a real email address")
        return value.strip().lower()


class CreateAccountResponse(BaseModel):
    account_id: str
    api_key: str = Field(
        description="Shown exactly once. Store it now — it cannot be retrieved again, only revoked/rotated."
    )
    key_id: str
    email_verification_required: bool = Field(
        default=True,
        description="POST /scans is refused until POST /accounts/verify-email confirms this address.",
    )


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=1)


class VerifyEmailResponse(BaseModel):
    account_id: str
    status: Literal["verified"]


class ResendVerificationResponse(BaseModel):
    account_id: str
    status: Literal["verification_email_resent"]


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
    # 'standard' = the account's own configured enable_* flags, unchanged.
    # 'passive' = force off every active-collection plugin, reusing the
    # exact same narrowing api/monitoring.py's Speed 1 monitoring already
    # applies — never a second, differently-defined "passive" here.
    profile: Literal["standard", "passive"] = "standard"


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
    collection_profile: str = "standard"


class ClientReportRequest(BaseModel):
    format: Literal["markdown", "docx"] = "markdown"
    language: Literal["en", "es"] = "es"
    white_label: bool = Field(
        default=False,
        description=(
            "Ultra-tier only — shows the account's own configured branding "
            "(PUT /account/branding) on the report's cover/title instead of no "
            "branding at all. Requires branding to already be configured; 422 otherwise."
        ),
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


class SetMonitoringRequest(BaseModel):
    speed2: bool = Field(
        default=False,
        description="Opt into the weekly ACTIVE deep-scan (Speed 2, Pro/Ultra only). Speed 1 "
        "(daily passive re-scan) is implied by monitoring simply being enabled.",
    )


class MonitoringStatusResponse(BaseModel):
    domain: str
    status: Literal["active", "paused_verification_lapsed", "needs_review"]
    speed2_enabled: bool
    last_passive_run_at: str | None
    last_active_run_at: str | None
    next_passive_due_at: str
    next_active_due_at: str | None
    last_asset_count: int | None
    needs_review: bool


class RegisterWebhookRequest(BaseModel):
    url: str = Field(min_length=1, description="Must be https:// and not a private/loopback host.")
    event_types: list[str] = Field(
        min_length=1,
        description="Which events to receive — see api/webhooks.py::EVENT_TYPES for the full set.",
    )


class WebhookResponse(BaseModel):
    webhook_id: str
    url: str
    event_types: list[str]
    status: Literal["active", "disabled"]
    consecutive_failures: int
    last_delivery_at: str | None
    last_success_at: str | None
    last_error: str | None
    created_at: str


class WebhookCreatedResponse(WebhookResponse):
    secret: str = Field(
        description="Shown exactly once, at creation — save it now. Used to verify the "
        "X-Hydra-Signature header on every delivery."
    )


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


class SetBrandingRequest(BaseModel):
    company_name: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "The name shown on white-labeled client reports (PUT /scans/{id}/"
            "client-report with white_label=true). null clears any previously "
            "configured branding."
        ),
    )


class BrandingResponse(BaseModel):
    company_name: str | None = None


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


# --- EASM Exposure inventory (Fase 08 hardening) ----------------------


class ExposureResponse(BaseModel):
    exposure_id: str
    organization_id: str
    asset_id: str
    source: str
    template_id: str
    location: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    description: str
    confidence_score: int | None = None
    status: Literal["open", "reopened", "resolved"]
    first_seen_at: str
    last_seen_at: str
    first_seen_run_id: str
    last_seen_run_id: str
    resolved_at: str | None = None
    resolved_run_id: str | None = None
    resolution_reason: str | None = None


class ExposureFindingResponse(BaseModel):
    """The detector result behind one piece of exposure evidence — what
    was actually matched, where, and how confidently."""

    host: str
    url: str | None = None
    name: str | None = None
    severity: str | None = None
    description: str | None = None
    confidence_score: int | None = None
    discovered_at: str | None = None


class ExposureEvidenceResponse(BaseModel):
    exposure_evidence_id: str
    exposure_id: str
    run_id: str
    finding_id: int
    observed_at: str
    # `None` only when the underlying finding row can no longer be read
    # (e.g. the run's data is gone) — never fabricated.
    finding: ExposureFindingResponse | None = None


class ReasonedExposureRequest(BaseModel):
    """Shared by every audited exposure lifecycle transition, so the reason
    rules can't drift between them."""

    reason: str = Field(min_length=1, max_length=1000)

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, value: str) -> str:
        # min_length alone accepts "   ", which the router strips to "" and
        # the data layer then rejects with a ValueError -> a 500, not a 422.
        if not value.strip():
            raise ValueError("reason must not be blank")
        return value


class ReopenExposureRequest(ReasonedExposureRequest):
    pass


class ExposureHistoryResponse(BaseModel):
    event_id: str
    exposure_id: str
    event_type: Literal["observed", "reopened", "resolved"]
    happened_at: str
    run_id: str | None = None
    reason: str


class ResolveExposureRequest(ReasonedExposureRequest):
    pass


class ExposureReportHistoryEventResponse(BaseModel):
    event_type: Literal["observed", "reopened", "resolved"]
    happened_at: str
    run_id: str | None = None
    reason: str


class ExposureReportEntryResponse(BaseModel):
    """Fase 21: one exposure with its FULL cross-run history and risk
    classification — the report-facing shape, never just a current-run
    snapshot."""

    exposure_id: str
    asset_id: str
    title: str
    severity: str
    status: str
    first_seen_at: str
    last_seen_at: str
    history: list[ExposureReportHistoryEventResponse]
    risk_level: str
    risk_reasons: list[str]


class ExposureRiskResponse(BaseModel):
    """Fase 21: deterministic, explainable risk/criticality — `level` is
    never returned without `reasons`, the phase's own explicit
    requirement that a classification always cites what produced it."""

    exposure_id: str
    level: Literal["low", "medium", "high", "critical"]
    reasons: list[str]


# Fase 19 (EASM roadmap) — API surface for the domain model Fases 02-18
# built. Every response model here is a thin, explicit projection of an
# existing `api/control_db.py` dataclass, never a raw `.__dict__` dump of
# a table row a future column could silently leak through.


class OrganizationResponse(BaseModel):
    organization_id: str
    name: str
    role: str
    created_at: str
    updated_at: str


class CreateOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class OrganizationMemberResponse(BaseModel):
    account_id: str
    role: str
    created_at: str


class AddOrganizationMemberRequest(BaseModel):
    account_id: str = Field(min_length=1)
    role: Literal["owner", "viewer"]


class AssetResponse(BaseModel):
    asset_id: str
    organization_id: str
    asset_type: str
    identity_key: str
    first_seen_at: str
    last_seen_at: str
    last_seen_run_id: str | None = None


class CandidateAssetResponse(BaseModel):
    candidate_asset_id: str
    organization_id: str
    candidate_type: str
    normalized_value: str
    display_value: str
    first_seen_at: str
    last_seen_at: str
    scope_status: str
    collection_status: str
    authorization_status: str
    reason: str
    review_status: str
    discarded_signal_hash: str | None = None
    promoted_asset_id: str | None = None


class PromoteCandidateAssetRequest(BaseModel):
    justification: str = Field(min_length=1, max_length=1000)


class DiscardCandidateAssetRequest(BaseModel):
    justification: str = Field(min_length=1, max_length=1000)


class EvidenceResponse(BaseModel):
    evidence_id: str
    source: str
    detail: str
    confidence_score: int | None = None
    confidence_class: str
    first_seen_at: str
    last_seen_at: str


class ObservationResponse(BaseModel):
    observation_id: str
    run_id: str
    observation_type: str
    observed_at: str
    evidence: EvidenceResponse


class ChangeEventResponse(BaseModel):
    change_event_id: str
    asset_id: str
    run_id: str
    previous_state: str | None = None
    new_state: str
    reason: str
    detected_at: str


class CertificateEventResponse(BaseModel):
    certificate_event_id: str
    asset_id: str
    run_id: str
    event_type: str
    reason: str
    previous_fingerprint: str | None = None
    new_fingerprint: str
    detected_at: str


class TechnologyEventResponse(BaseModel):
    technology_event_id: str
    asset_id: str
    run_id: str
    event_type: str
    technology_name: str
    reason: str
    detected_at: str


class CurrentTechnologyResponse(BaseModel):
    technology_name: str
    version: str | None = None
    source: str
    last_seen_at: str


class CurrentCertificateResponse(BaseModel):
    fingerprint_sha256: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    sans: tuple[str, ...]
    observed_at: str


class AssetIdentifierResponse(BaseModel):
    identifier_type: str
    identifier_value: str
    first_seen_at: str
    last_seen_at: str


class RelationshipResponse(BaseModel):
    relationship_id: str
    source_entity: str
    relationship_type: str
    target_entity: str
    source_asset_id: str | None = None
    target_asset_id: str | None = None
    confidence: str
    strength: str
    # Parsed from the stored data_json (e.g. the shared certificate
    # fingerprint or IP a SHARED_CERTIFICATE/SHARED_IP relationship
    # cites) — never the raw JSON string; empty dict, never null, when
    # nothing was recorded.
    data: dict[str, object] = {}
    first_seen_at: str
    last_seen_at: str
    last_seen_run_id: str


class RelationshipEvidenceResponse(BaseModel):
    relationship_evidence_id: str
    run_id: str
    source: str
    collector: str
    reason: str
    metadata: dict[str, object] = {}
    observed_at: str


class CapabilityStatusResponse(BaseModel):
    provider: str
    display_name: str
    capability: str
    intensity: str
    active: bool
    status: Literal["disabled", "runnable", "not_runnable"]
