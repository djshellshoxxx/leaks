// SPDX-License-Identifier: AGPL-3.0-or-later
//! Service configuration, validated at start (fail closed: an invalid value
//! refuses start, never a silent default), and the two integration seams the
//! web uses besides the sealer socket: [`StoreReads`] (the store reads the
//! web tier is allowed to make) and [`DayClock`] (the independent day clock).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use candor_intake_store::{AccountId, IntakeStore, LookupTag, StoredReply};
use candor_source_ui::{
    Banners, ChannelOption, ChoiceOption, DeploymentInfo, LandingData, StatusData,
};

use crate::limits::{
    LOGIN_FLOOR_DEFAULT, LOGIN_FLOOR_MAX, LOGIN_FLOOR_MIN, MAX_FILE_BYTES_CEILING,
    MAX_FILES_CEILING,
};
use crate::ratelimit::GlobalLimits;

/// The independent day clock (16 §14.3: Tor consensus plus Roughtime; 07 §12).
/// `None` when the clock is not sane: the web then refuses new submissions
/// with the busy page (IMPL-RM2-020).
pub trait DayClock: Send + Sync {
    /// Today as days since 1970-01-01 (UTC), or `None`.
    fn today(&self) -> Option<u32>;
}

/// One account as the web sees it at login: only verifier-side values.
pub struct AccountView {
    /// Intake-local account id (never shown, never logged).
    pub account_id: AccountId,
    /// Ed25519 auth public key.
    pub auth_pk: [u8; 32],
    /// `prefs_ct` (ciphertext for the sealer's `LOAD_PREFS`).
    pub prefs_ct: Vec<u8>,
}

impl core::fmt::Debug for AccountView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountView(<redacted>)")
    }
}

/// Store failure (content-free). `RestorePending` and every backend error
/// give the busy page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreUnavailable;

/// The reads the web tier makes on the Intake Store (07 §5.3 IPC to web:
/// `ACCOUNT_AUTH_*` and `MAILBOX_LIST`; 08 SW-10/SW-11), and nothing else.
/// Envelopes and accounts are written by the sealer (ADR-052(2)); deletions
/// need the store-held K31 and are not available to the web (SPEC-NOTES,
/// open item). Implemented for every [`IntakeStore`].
pub trait StoreReads: Send + Sync {
    /// `false` while a restore awaits its deletion list (07 BE-074).
    fn serving_allowed(&self) -> impl Future<Output = Result<bool, StoreUnavailable>> + Send;
    /// Account by `lookup_tag` (no write, ADR-010).
    fn account(
        &self,
        tag: [u8; 32],
    ) -> impl Future<Output = Result<Option<AccountView>, StoreUnavailable>> + Send;
    /// The account's fixed mailbox (≤ 32 replies).
    fn mailbox(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<StoredReply>, StoreUnavailable>> + Send;
}

impl<S: IntakeStore> StoreReads for S {
    async fn serving_allowed(&self) -> Result<bool, StoreUnavailable> {
        IntakeStore::serving_allowed(self)
            .await
            .map_err(|_| StoreUnavailable)
    }

    async fn account(&self, tag: [u8; 32]) -> Result<Option<AccountView>, StoreUnavailable> {
        let a = self
            .lookup_account(&LookupTag(tag))
            .await
            .map_err(|_| StoreUnavailable)?;
        Ok(a.map(|a| AccountView {
            account_id: a.account_id,
            auth_pk: a.auth_pk,
            prefs_ct: a.prefs_ct,
        }))
    }

    async fn mailbox(&self, account: AccountId) -> Result<Vec<StoredReply>, StoreUnavailable> {
        self.mailbox_list(account)
            .await
            .map_err(|_| StoreUnavailable)
    }
}

/// A report channel as offered on S04 (rendered from the verified Key
/// Directory snapshot by the integrator; the web never trusts it for
/// sealing: the sealer decides recipients itself).
#[derive(Clone)]
pub struct ChannelConfig {
    /// Channel id.
    pub id: [u8; 16],
    /// S04 option. Its `id` must be the lowercase hex of [`ChannelConfig::id`].
    pub option: ChannelOption,
    /// Role labels for the S04b checklist: `(role-label id, label)`; the
    /// form value is the index, the sealer receives the id.
    pub roles: Vec<(u16, String)>,
    /// Report categories offered at S05 step 3: `(category id, option)`.
    pub categories: Vec<(u16, ChoiceOption)>,
}

impl core::fmt::Debug for ChannelConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChannelConfig")
    }
}

/// Deployment content shown on the pages.
#[derive(Clone, Default)]
pub struct SiteContent {
    /// Organisation label.
    pub org: String,
    /// Deployment statements.
    pub deployment: DeploymentInfo,
    /// Warning banners.
    pub banners: Banners,
    /// S01.
    pub landing: LandingData,
    /// S03.
    pub status: StatusData,
    /// Channels (S04).
    pub channels: Vec<ChannelConfig>,
}

impl core::fmt::Debug for SiteContent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SiteContent")
    }
}

/// The service configuration.
#[derive(Clone)]
pub struct WebConfig {
    /// The onion host (`<56 base32>.onion`): the only accepted `Host`.
    pub onion_host: String,
    /// `http` (default) or `https` (onion TLS mode, NET-042): the scheme of
    /// the only accepted non-null `Origin`.
    pub onion_tls: bool,
    /// Tenant id (bound into the source-auth signature, 04 §11.5).
    pub tenant_id: [u8; 16],
    /// `T_LOGIN_FLOOR` (SAFE range 2–6 s).
    pub login_floor: Duration,
    /// `intake.max_file_bytes` (≤ 4 GiB).
    pub max_file_bytes: u64,
    /// Files per envelope (≤ 32).
    pub max_files: u32,
    /// Global limits.
    pub global: GlobalLimits,
    /// Page content.
    pub site: SiteContent,
    /// The signed running manifest served at `/.well-known/candor/manifest`
    /// (SW-23), byte-exact; `None` → 404.
    pub manifest: Option<Arc<[u8]>>,
}

impl core::fmt::Debug for WebConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WebConfig")
    }
}

impl WebConfig {
    /// A configuration with defaults for everything but the identity values.
    #[must_use]
    pub fn new(onion_host: String, tenant_id: [u8; 16], site: SiteContent) -> Self {
        Self {
            onion_host,
            onion_tls: false,
            tenant_id,
            login_floor: LOGIN_FLOOR_DEFAULT,
            max_file_bytes: 512 << 20,
            max_files: 20,
            global: GlobalLimits::default(),
            site,
            manifest: None,
        }
    }

    /// `http://<onion>` (or `https://`).
    #[must_use]
    pub fn origin(&self) -> String {
        let scheme = if self.onion_tls { "https" } else { "http" };
        format!("{scheme}://{}", self.onion_host)
    }
}

/// Invalid configuration (start refused). Carries the setting name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

fn onion_ok(h: &str) -> bool {
    h.strip_suffix(".onion").is_some_and(|b| {
        b.len() == 56
            && b.bytes()
                .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
    })
}

/// Validate a configuration.
pub fn validate(cfg: &WebConfig) -> Result<(), ConfigError> {
    if !onion_ok(&cfg.onion_host) {
        return Err(ConfigError("onion_host"));
    }
    if !(LOGIN_FLOOR_MIN..=LOGIN_FLOOR_MAX).contains(&cfg.login_floor) {
        return Err(ConfigError("login_floor"));
    }
    if cfg.max_file_bytes == 0 || cfg.max_file_bytes > MAX_FILE_BYTES_CEILING {
        return Err(ConfigError("max_file_bytes"));
    }
    if cfg.max_files == 0 || cfg.max_files > MAX_FILES_CEILING {
        return Err(ConfigError("max_files"));
    }
    if cfg.global.requests_per_sec == 0 || cfg.global.sessions_per_hour == 0 {
        return Err(ConfigError("global"));
    }
    let words = candor_core::passphrase::Wordlist::eff_large()
        .map_err(|_| ConfigError("wordlist"))?
        .word_count();
    if usize::try_from(cfg.site.deployment.passphrase_words).ok() != Some(words) {
        return Err(ConfigError("deployment.passphrase_words"));
    }
    let mut seen: Vec<[u8; 16]> = Vec::new();
    for c in &cfg.site.channels {
        if *crate::token::hex(&c.id) != c.option.id || seen.contains(&c.id) {
            return Err(ConfigError("channels.id"));
        }
        if c.roles.len() > usize::from(u16::MAX) || c.categories.len() > 64 {
            return Err(ConfigError("channels.roles"));
        }
        seen.push(c.id);
    }
    Ok(())
}
