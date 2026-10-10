// SPDX-License-Identifier: AGPL-3.0-or-later
//! The policy as data (15 §5.2 `authz/matrix.yaml`, §5.8, §5.6, §4.7):
//! permission cells per role, the route registry (ADR-029), dual-control
//! rules, the break-glass rule and freshness limits. Parsed strictly from the
//! canonical JSON form (`deny_unknown_fields`, bounded sizes, every
//! identifier validated). The compiled-in baseline (`authz/matrix.json`) is
//! not overridable: a tenant bundle may only restrict it (lint).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{Audience, BreakGlassReason, DcId, Permission, Role};

/// Format tag of the policy document.
pub const FORMAT: &str = "candor/authz-policy/v1";
/// Maximum canonical policy size in bytes (hostile-input bound).
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
/// Maximum number of route declarations.
pub const MAX_ROUTES: usize = 512;
/// Maximum route path length.
pub const MAX_PATH_LEN: usize = 200;
/// Maximum route id length.
pub const MAX_ID_LEN: usize = 16;
/// Hard ceiling on step-up freshness (DA-06 `expires_in: 300`).
pub const MAX_STEP_UP_FRESHNESS_S: u64 = 300;
/// Accessibility accommodation ceiling (RVW-C-16).
pub const MAX_ACCOMMODATION_FRESHNESS_S: u64 = 180;
/// Break-glass maximum duration (15 §5.5/§5.6: 4 h).
pub const MAX_BREAK_GLASS_S: u64 = 4 * 3600;
/// Approval lifetime (15 §5.8: 24 h).
pub const APPROVAL_TTL_S: u64 = 24 * 3600;

/// Typed parse / validation errors (no input echoed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    TooLarge,
    Syntax,
    BadFormat,
    UnknownPermission,
    UnknownRole,
    BadCell,
    UnknownDc,
    BadRoute,
    TooManyRoutes,
    BadLimit,
    NotCanonical,
}

/// Grant kind of a matrix cell (15 §5.2 legend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantKind {
    /// `Y`: allowed by role alone.
    Role,
    /// `A`: allowed with a relation on the object.
    Relation,
}

/// One matrix cell: `Y`/`A`, optional `S` (step-up), optional `DC-xx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cell {
    pub grant: GrantKind,
    pub step_up: bool,
    pub dual: Option<DcId>,
}

impl Cell {
    /// Parse the compact form, e.g. `A`, `Y+S`, `A+S+DC-01`.
    pub fn parse(s: &str) -> Result<Cell, PolicyError> {
        let mut parts = s.split('+');
        let grant = match parts.next() {
            Some("Y") => GrantKind::Role,
            Some("A") => GrantKind::Relation,
            _ => return Err(PolicyError::BadCell),
        };
        let mut cell = Cell {
            grant,
            step_up: false,
            dual: None,
        };
        for p in parts {
            match p {
                "S" if !cell.step_up => cell.step_up = true,
                dc if dc.starts_with("DC-") && cell.dual.is_none() => {
                    cell.dual = Some(DcId::parse(dc).ok_or(PolicyError::UnknownDc)?);
                }
                _ => return Err(PolicyError::BadCell),
            }
        }
        Ok(cell)
    }

    /// Canonical compact form.
    #[must_use]
    pub fn to_compact(self) -> String {
        let mut s = String::from(match self.grant {
            GrantKind::Role => "Y",
            GrantKind::Relation => "A",
        });
        if self.step_up {
            s.push_str("+S");
        }
        if let Some(dc) = self.dual {
            s.push('+');
            s.push_str(dc.as_str());
        }
        s
    }
}

/// Resource derivation of a route (the PEP builds the matching
/// [`crate::model::Object`] variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Tenant,
    Channel,
    Envelope,
    Case,
    CaseChild,
    Admin,
}

impl ResourceKind {
    /// Deny on these answers with the uniform 404 (08 §3.3).
    #[must_use]
    pub const fn uniform_404(self) -> bool {
        matches!(
            self,
            ResourceKind::Channel | ResourceKind::Envelope | ResourceKind::Case | ResourceKind::CaseChild
        )
    }
}

/// The authorization declaration of a route (ADR-029).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RouteAuthz {
    /// Authentication-only routes (DA-01..DA-06, DA-11; AP-01): the
    /// credential itself is the authorization; no permission is consulted.
    TransportOnly,
    /// A permission from the matrix.
    Permission(String),
}

/// One declared route (08 §8–§9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDecl {
    pub id: String,
    pub method: String,
    pub path: String,
    pub audience: String,
    pub resource: ResourceKind,
    /// Missing in the data ⇒ the lint fails ("route lacks an authz
    /// declaration"); parsing still succeeds so the lint can name it.
    #[serde(default)]
    pub authz: Option<RouteAuthz>,
}

/// One dual-control rule (15 §5.8). `approvers` counts approvers in
/// addition to the proposer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DualControlRule {
    pub approvers: u8,
    pub roles: Vec<String>,
    pub independent_required: bool,
    pub coi_checked: bool,
    pub approver_step_up: bool,
}

/// Break-glass rule (15 §5.6). Expiry and reason code are mandatory by type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassRule {
    /// Maximum grant duration in seconds; must be `1..=14400`.
    pub max_duration_s: u64,
    /// Delay before execution for non-imminent reasons (24 h).
    pub delay_s: u64,
    pub requester_roles: Vec<String>,
    pub approver_roles: Vec<String>,
    pub reason_codes: Vec<String>,
    pub dc: String,
    /// Post-hoc review deadline in days (7).
    pub review_days: u32,
}

/// Step-up freshness (15 §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpRule {
    pub freshness_s: u64,
    pub accommodation_freshness_s: u64,
}

/// Temporary grant maxima in days (15 §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantLimits {
    pub reviewer_days: u32,
    pub consultant_days: u32,
    pub counsel_days: u32,
    pub custodian_days: u32,
    pub role_days: u32,
}

/// The raw document as serialized (canonical JSON, sorted maps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    pub format: String,
    /// permission → role → compact cell.
    pub permissions: BTreeMap<String, BTreeMap<String, String>>,
    pub routes: Vec<RouteDecl>,
    pub dual_control: BTreeMap<String, DualControlRule>,
    pub break_glass: BreakGlassRule,
    pub step_up: StepUpRule,
    pub grants: GrantLimits,
    /// DC rule applied to membership changes on `SEALED_MATTER` cases.
    pub sealed_matter_membership_dc: String,
    /// Tenant downgrade of the AAL3 content requirement (DANGEROUS).
    pub content_aal2_allowed: bool,
    pub min_recipients: u32,
}

/// Validated, typed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub(crate) cells: BTreeMap<(Permission, Role), Cell>,
    pub(crate) routes: Vec<RouteDecl>,
    pub(crate) dual_control: BTreeMap<DcId, DualRule>,
    pub(crate) break_glass: BreakGlass,
    pub(crate) step_up: StepUpRule,
    pub(crate) grants: GrantLimits,
    pub(crate) sealed_matter_dc: DcId,
    pub(crate) content_aal2_allowed: bool,
    pub(crate) min_recipients: u32,
    doc: PolicyDoc,
}

/// Typed dual-control rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualRule {
    pub approvers: u8,
    pub roles: Vec<Role>,
    pub independent_required: bool,
    pub coi_checked: bool,
    pub approver_step_up: bool,
}

/// Typed break-glass rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlass {
    pub max_duration_s: u64,
    pub delay_s: u64,
    pub requester_roles: Vec<Role>,
    pub approver_roles: Vec<Role>,
    pub reason_codes: Vec<BreakGlassReason>,
    pub dc: DcId,
    pub review_days: u32,
}

fn roles(v: &[String]) -> Result<Vec<Role>, PolicyError> {
    v.iter()
        .map(|s| Role::parse(s).ok_or(PolicyError::UnknownRole))
        .collect()
}

impl Policy {
    /// Parse and validate canonical JSON bytes. The bytes must re-serialize
    /// to exactly themselves (canonical form), so there is one encoding per
    /// policy and signatures are over that encoding.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Policy, PolicyError> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::TooLarge);
        }
        let doc: PolicyDoc = serde_json::from_slice(bytes).map_err(|_| PolicyError::Syntax)?;
        let re = serde_json::to_vec(&doc).map_err(|_| PolicyError::Syntax)?;
        if re != bytes {
            return Err(PolicyError::NotCanonical);
        }
        Policy::from_doc(doc)
    }

    /// Validate a document (non-canonical input allowed; used by tooling and
    /// tests). Use [`Policy::from_canonical_json`] for bundles.
    pub fn from_doc(doc: PolicyDoc) -> Result<Policy, PolicyError> {
        if doc.format != FORMAT {
            return Err(PolicyError::BadFormat);
        }
        let mut cells = BTreeMap::new();
        for (p, row) in &doc.permissions {
            let perm = Permission::parse(p).ok_or(PolicyError::UnknownPermission)?;
            for (r, c) in row {
                let role = Role::parse(r).ok_or(PolicyError::UnknownRole)?;
                let cell = Cell::parse(c)?;
                if cell.to_compact() != *c {
                    return Err(PolicyError::BadCell);
                }
                cells.insert((perm, role), cell);
            }
        }
        if doc.routes.len() > MAX_ROUTES {
            return Err(PolicyError::TooManyRoutes);
        }
        for r in &doc.routes {
            validate_route(r)?;
        }
        let mut dual_control = BTreeMap::new();
        for (id, rule) in &doc.dual_control {
            let dc = DcId::parse(id).ok_or(PolicyError::UnknownDc)?;
            dual_control.insert(
                dc,
                DualRule {
                    approvers: rule.approvers,
                    roles: roles(&rule.roles)?,
                    independent_required: rule.independent_required,
                    coi_checked: rule.coi_checked,
                    approver_step_up: rule.approver_step_up,
                },
            );
        }
        let bg = &doc.break_glass;
        let break_glass = BreakGlass {
            max_duration_s: bg.max_duration_s,
            delay_s: bg.delay_s,
            requester_roles: roles(&bg.requester_roles)?,
            approver_roles: roles(&bg.approver_roles)?,
            reason_codes: bg
                .reason_codes
                .iter()
                .map(|s| BreakGlassReason::parse(s).ok_or(PolicyError::BadLimit))
                .collect::<Result<_, _>>()?,
            dc: DcId::parse(&bg.dc).ok_or(PolicyError::UnknownDc)?,
            review_days: bg.review_days,
        };
        if break_glass.max_duration_s == 0
            || break_glass.max_duration_s > MAX_BREAK_GLASS_S
            || break_glass.reason_codes.is_empty()
            || break_glass.review_days == 0
        {
            return Err(PolicyError::BadLimit);
        }
        if doc.step_up.freshness_s == 0
            || doc.step_up.freshness_s > MAX_STEP_UP_FRESHNESS_S
            || doc.step_up.accommodation_freshness_s == 0
            || doc.step_up.accommodation_freshness_s > MAX_ACCOMMODATION_FRESHNESS_S
        {
            return Err(PolicyError::BadLimit);
        }
        let g = doc.grants;
        if g.reviewer_days == 0
            || g.reviewer_days > 7
            || g.consultant_days == 0
            || g.consultant_days > 90
            || g.counsel_days == 0
            || g.counsel_days > 180
            || g.custodian_days == 0
            || g.custodian_days > 30
            || g.role_days == 0
            || g.role_days > 365
        {
            return Err(PolicyError::BadLimit);
        }
        if doc.min_recipients < 2 {
            // ADR-044(2): `min_recipients` = 1 is DANGEROUS and never a
            // policy-bundle decision.
            return Err(PolicyError::BadLimit);
        }
        let sealed_matter_dc =
            DcId::parse(&doc.sealed_matter_membership_dc).ok_or(PolicyError::UnknownDc)?;
        Ok(Policy {
            cells,
            routes: doc.routes.clone(),
            dual_control,
            break_glass,
            step_up: doc.step_up,
            grants: g,
            sealed_matter_dc,
            content_aal2_allowed: doc.content_aal2_allowed,
            min_recipients: doc.min_recipients,
            doc,
        })
    }

    /// The canonical JSON encoding of this policy.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, PolicyError> {
        serde_json::to_vec(&self.doc).map_err(|_| PolicyError::Syntax)
    }

    #[must_use]
    pub fn cell(&self, perm: Permission, role: Role) -> Option<Cell> {
        self.cells.get(&(perm, role)).copied()
    }

    #[must_use]
    pub fn cells(&self) -> &BTreeMap<(Permission, Role), Cell> {
        &self.cells
    }

    #[must_use]
    pub fn routes(&self) -> &[RouteDecl] {
        &self.routes
    }

    #[must_use]
    pub fn dual_rule(&self, dc: DcId) -> Option<&DualRule> {
        self.dual_control.get(&dc)
    }

    #[must_use]
    pub fn break_glass(&self) -> &BreakGlass {
        &self.break_glass
    }

    #[must_use]
    pub fn step_up(&self) -> StepUpRule {
        self.step_up
    }

    #[must_use]
    pub fn grants(&self) -> GrantLimits {
        self.grants
    }

    #[must_use]
    pub fn min_recipients(&self) -> u32 {
        self.min_recipients
    }

    #[must_use]
    pub fn doc(&self) -> &PolicyDoc {
        &self.doc
    }

    /// The compiled-in baseline (`authz/matrix.json`).
    pub fn baseline() -> Result<&'static Policy, PolicyError> {
        static BASELINE: std::sync::OnceLock<Result<Policy, PolicyError>> =
            std::sync::OnceLock::new();
        BASELINE
            .get_or_init(|| Policy::from_canonical_json(BASELINE_JSON))
            .as_ref()
            .map_err(|e| *e)
    }
}

/// The baseline matrix, byte-exact canonical JSON.
pub const BASELINE_JSON: &[u8] = include_bytes!("../authz/matrix.json");

fn validate_route(r: &RouteDecl) -> Result<(), PolicyError> {
    let id_ok = !r.id.is_empty()
        && r.id.len() <= MAX_ID_LEN
        && r.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let method_ok = matches!(r.method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE");
    let audience = Audience::parse(&r.audience).ok_or(PolicyError::BadRoute)?;
    let prefix = match audience {
        Audience::DeskApi => "/desk/v1/",
        Audience::AdminApi => "/admin/v1/",
    };
    let path_ok = r.path.len() <= MAX_PATH_LEN
        && r.path.starts_with(prefix)
        && r.path.is_ascii()
        && !r.path.contains("//")
        && !r.path.contains("..")
        && !r.path.contains('?');
    if !(id_ok && method_ok && path_ok) {
        return Err(PolicyError::BadRoute);
    }
    if let Some(RouteAuthz::Permission(p)) = &r.authz {
        let perm = Permission::parse(p).ok_or(PolicyError::UnknownPermission)?;
        let admin = perm.is_admin_api();
        if admin != (audience == Audience::AdminApi) {
            return Err(PolicyError::BadRoute);
        }
    }
    Ok(())
}
