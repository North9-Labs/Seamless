/// ACME (Let's Encrypt) automatic TLS certificate provisioning.
///
/// Supports two challenge types:
///   1. DNS-01 via Cloudflare API (when `cloudflare_api_token` is set)
///   2. HTTP-01 via a tiny HTTP server on port 80 (fallback)
///
/// Uses the `instant-acme` crate for the ACME protocol itself; this module
/// handles certificate storage, renewal scheduling, and DNS record management.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::audit::AuditLog;

// ── Config ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// Email address for Let's Encrypt account registration.
    pub email: String,
    /// Domains to request a certificate for.
    pub domains: Vec<String>,
    /// Cloudflare API token for DNS-01 challenge. When `None`, HTTP-01 is used.
    pub cloudflare_api_token: Option<String>,
    /// Directory where account keys and certificates are stored.
    pub acme_dir: PathBuf,
    /// Use the production Let's Encrypt CA. When `false`, staging is used.
    pub production: bool,
}

// ── HTTP-01 challenge token store (shared with the ACME HTTP server) ───────────

/// Shared map of `token → key_authorization` for HTTP-01 challenges.
pub type ChallengeTokenStore = Arc<RwLock<HashMap<String, String>>>;

// ── ACME client ────────────────────────────────────────────────────────────────

pub struct AcmeClient {
    pub config: AcmeConfig,
    /// HTTP client for Cloudflare API calls.
    http: reqwest::Client,
    /// Token store for HTTP-01 challenges.
    pub challenge_tokens: ChallengeTokenStore,
    pub audit_log: AuditLog,
}

impl AcmeClient {
    pub fn new(config: AcmeConfig, audit_log: AuditLog) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            challenge_tokens: Arc::new(RwLock::new(HashMap::new())),
            audit_log,
        }
    }

    /// Obtain or renew a certificate.  Stores cert + key under `acme_dir`.
    /// Returns `(cert_pem, key_pem)`.
    pub async fn obtain_certificate(&self) -> Result<(String, String)> {
        // Ensure the storage directory exists.
        tokio::fs::create_dir_all(&self.config.acme_dir)
            .await
            .context("creating ACME directory")?;

        // Load or create the ACME account.
        let account = self.load_or_create_account().await?;

        // Place an order for the configured domains.
        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .context("creating ACME order")?;

        // Process authorizations (challenges).
        let authorizations = order
            .authorizations()
            .await
            .context("fetching authorizations")?;
        let mut dns_records_to_clean: Vec<(String, String, String)> = Vec::new(); // (zone_id, record_id, domain)

        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Valid => {
                    // Already validated — nothing to do.
                    continue;
                }
                AuthorizationStatus::Pending => {}
                _ => bail!("unexpected authorization status: {:?}", authz.status),
            }

            let challenge_type = if self.config.cloudflare_api_token.is_some() {
                ChallengeType::Dns01
            } else {
                ChallengeType::Http01
            };

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == challenge_type)
                .ok_or_else(|| anyhow!("no {:?} challenge found", challenge_type))?;

            let domain = match &authz.identifier {
                Identifier::Dns(d) => d,
            };

            if let Some(ref cf_token) = self.config.cloudflare_api_token {
                // DNS-01: create `_acme-challenge.<domain>` TXT record.
                let key_auth = order.key_authorization(challenge);
                let digest = key_auth.dns_value();

                info!(
                    event = "acme.dns01.create",
                    domain = %domain,
                    "creating DNS-01 TXT record for {domain}"
                );

                let (zone_id, record_id) = self
                    .cf_create_txt_record(cf_token, domain, &digest)
                    .await
                    .with_context(|| format!("creating CF DNS TXT for {domain}"))?;
                dns_records_to_clean.push((zone_id, record_id, domain.clone()));

                // Wait for DNS propagation.
                tokio::time::sleep(Duration::from_secs(10)).await;
            } else {
                // HTTP-01: store token in shared map; challenge server will serve it.
                let key_auth = order.key_authorization(challenge);
                self.challenge_tokens
                    .write()
                    .await
                    .insert(challenge.token.clone(), key_auth.as_str().to_string());
                info!(
                    event = "acme.http01.token",
                    domain = %domain,
                    token = %challenge.token,
                    "HTTP-01 challenge token ready for {domain}"
                );
            }

            // Notify ACME server that we're ready.
            order
                .set_challenge_ready(&challenge.url)
                .await
                .context("setting challenge ready")?;
        }

        // Poll order until ready or invalid.
        let delay = Duration::from_secs(5);
        let max_attempts = 24; // 2 minutes
        for attempt in 0..max_attempts {
            tokio::time::sleep(delay).await;
            let state = order.refresh().await.context("refreshing order")?;
            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    bail!("ACME order became invalid after {} attempts", attempt + 1);
                }
                _ => {
                    if attempt + 1 == max_attempts {
                        bail!("ACME order did not complete within timeout");
                    }
                }
            }
        }

        // Generate CSR key pair and serialize CSR.
        let key_pair = KeyPair::generate().context("generating key pair")?;
        let mut params =
            CertificateParams::new(self.config.domains.clone()).context("creating cert params")?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params
            .serialize_request(&key_pair)
            .context("serializing CSR")?;
        let csr_der: &[u8] = csr.der();

        // Finalize the order (submit CSR).
        order
            .finalize(csr_der)
            .await
            .context("finalizing ACME order")?;

        // Poll for the certificate to become available.
        let cert_chain_pem = loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            match order
                .certificate()
                .await
                .context("downloading certificate")?
            {
                Some(pem) => break pem,
                None => continue,
            }
        };

        let key_pem = key_pair.serialize_pem();

        // Clean up DNS records.
        if let Some(ref cf_token) = self.config.cloudflare_api_token {
            for (zone_id, record_id, domain) in &dns_records_to_clean {
                if let Err(e) = self
                    .cf_delete_txt_record(cf_token, zone_id, record_id)
                    .await
                {
                    warn!(
                        event = "acme.dns01.cleanup_failed",
                        domain = %domain,
                        "failed to clean up DNS-01 TXT record for {domain}: {e:#}"
                    );
                } else {
                    info!(
                        event = "acme.dns01.cleanup",
                        domain = %domain,
                        "cleaned up DNS-01 TXT record for {domain}"
                    );
                }
            }
        }

        // Clean up HTTP-01 tokens.
        self.challenge_tokens.write().await.clear();

        // Store certificate and key on disk.
        let primary_domain = self.config.domains.first().context("no domains")?;
        let cert_path = self.config.acme_dir.join(format!("{primary_domain}.crt"));
        let key_path = self.config.acme_dir.join(format!("{primary_domain}.key"));

        tokio::fs::write(&cert_path, &cert_chain_pem)
            .await
            .context("writing certificate")?;
        tokio::fs::write(&key_path, &key_pem)
            .await
            .context("writing private key")?;

        info!(
            event = "acme.cert_obtained",
            domain = %primary_domain,
            cert_path = %cert_path.display(),
            "ACME certificate obtained and stored"
        );
        crate::audit_event!(self.audit_log, "acme.cert_obtained",
            "domain" => primary_domain.as_str(),
            "cert_path" => cert_path.display().to_string().as_str()
        );

        Ok((cert_chain_pem, key_pem))
    }

    /// Check whether the stored certificate for the primary domain expires in < 30 days.
    /// Returns `true` if renewal is needed.
    pub async fn needs_renewal(&self) -> bool {
        let Some(primary_domain) = self.config.domains.first() else {
            return false;
        };
        let cert_path = self.config.acme_dir.join(format!("{primary_domain}.crt"));
        if !cert_path.exists() {
            return true; // No certificate yet — obtain one.
        }
        match tokio::fs::read_to_string(&cert_path).await {
            Ok(pem) => days_until_expiry(&pem).map(|d| d < 30).unwrap_or(true),
            Err(_) => true,
        }
    }

    /// Returns paths to the stored cert and key for the primary domain.
    pub fn cert_paths(&self) -> Option<(PathBuf, PathBuf)> {
        let primary_domain = self.config.domains.first()?;
        let cert = self.config.acme_dir.join(format!("{primary_domain}.crt"));
        let key = self.config.acme_dir.join(format!("{primary_domain}.key"));
        Some((cert, key))
    }

    // ── Account management ────────────────────────────────────────────────────

    async fn load_or_create_account(&self) -> Result<Account> {
        let creds_path = self.config.acme_dir.join("account.json");
        let server = if self.config.production {
            LetsEncrypt::Production.url()
        } else {
            LetsEncrypt::Staging.url()
        };

        if creds_path.exists() {
            let json = tokio::fs::read_to_string(&creds_path)
                .await
                .context("reading account credentials")?;
            let creds: AccountCredentials =
                serde_json::from_str(&json).context("parsing account credentials")?;
            let account = Account::from_credentials(creds)
                .await
                .context("loading ACME account from credentials")?;
            info!(
                event = "acme.account_loaded",
                "loaded existing ACME account"
            );
            return Ok(account);
        }

        // Register a new account.
        let (account, creds) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.config.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            server,
            None,
        )
        .await
        .context("registering ACME account")?;

        let json = serde_json::to_string_pretty(&creds).context("serializing account creds")?;
        tokio::fs::write(&creds_path, &json)
            .await
            .context("saving account credentials")?;
        info!(event = "acme.account_created", email = %self.config.email, "registered new ACME account");
        Ok(account)
    }

    // ── Cloudflare DNS-01 helpers ─────────────────────────────────────────────

    async fn cf_get_zone_id(&self, token: &str, domain: &str) -> Result<String> {
        // Strip to the registrable domain (last two labels).
        let parts: Vec<&str> = domain.split('.').collect();
        let zone_name = if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            domain.to_string()
        };
        let url = format!("https://api.cloudflare.com/client/v4/zones?name={zone_name}");
        let resp: serde_json::Value = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("CF zones GET")?
            .json()
            .await
            .context("CF zones parse")?;
        let zone_id = resp["result"][0]["id"]
            .as_str()
            .ok_or_else(|| anyhow!("zone not found for domain {domain} (zone: {zone_name})"))?
            .to_string();
        Ok(zone_id)
    }

    async fn cf_create_txt_record(
        &self,
        token: &str,
        domain: &str,
        value: &str,
    ) -> Result<(String, String)> {
        let zone_id = self.cf_get_zone_id(token, domain).await?;
        let record_name = format!("_acme-challenge.{domain}");
        let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 60
        });
        let resp: serde_json::Value = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .context("CF create DNS TXT")?
            .json()
            .await
            .context("CF create DNS parse")?;
        if !resp["success"].as_bool().unwrap_or(false) {
            bail!(
                "CF API error creating TXT: {}",
                resp["errors"][0]["message"].as_str().unwrap_or("unknown")
            );
        }
        let record_id = resp["result"]["id"]
            .as_str()
            .ok_or_else(|| anyhow!("no record ID in CF response"))?
            .to_string();
        Ok((zone_id, record_id))
    }

    async fn cf_delete_txt_record(
        &self,
        token: &str,
        zone_id: &str,
        record_id: &str,
    ) -> Result<()> {
        let url =
            format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("CF delete DNS TXT")?;
        if !resp.status().is_success() {
            bail!("CF delete DNS record failed: HTTP {}", resp.status());
        }
        Ok(())
    }
}

// ── Certificate expiry check ──────────────────────────────────────────────────

fn days_until_expiry(pem: &str) -> Option<i64> {
    // Find the base64 body of the first CERTIFICATE block.
    let b64: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();

    if b64.is_empty() {
        return None;
    }

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;

    // Search for UTCTime (0x17) or GeneralizedTime (0x18) — find the second one (notAfter).
    let mut found_times: Vec<&[u8]> = Vec::new();
    let mut i = 0;
    while i + 2 < der.len() && found_times.len() < 2 {
        let tag = der[i];
        if tag == 0x17 || tag == 0x18 {
            let len = der[i + 1] as usize;
            if i + 2 + len <= der.len() {
                found_times.push(&der[i + 2..i + 2 + len]);
            }
            i += 2 + len;
        } else {
            i += 1;
        }
    }

    let not_after_bytes = found_times.get(1)?;
    let s = std::str::from_utf8(not_after_bytes).ok()?;

    // Parse YYMMDDHHMMSSZ (UTCTime) or YYYYMMDDHHMMSSZ (GeneralizedTime).
    let (year, rest) = if s.len() >= 15 {
        (s[..4].parse::<i64>().ok()?, &s[4..])
    } else {
        let yy = s[..2].parse::<i64>().ok()?;
        let full_year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        (full_year, &s[2..])
    };
    let month = rest[..2].parse::<i64>().ok()?;
    let day = rest[2..4].parse::<i64>().ok()?;

    let exp_days = days_since_epoch(year, month, day)?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let now_days = now_secs / 86_400;

    Some(exp_days - now_days)
}

fn days_since_epoch(year: i64, month: i64, day: i64) -> Option<i64> {
    // Julian Day Number formula (Gregorian calendar).
    let a = (14 - month) / 12;
    let y = year + 4800 - a;
    let m = month + 12 * a - 3;
    let jdn = day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;
    // JDN of 1970-01-01 is 2440588.
    Some(jdn - 2_440_588)
}

// ── Renewal background task ───────────────────────────────────────────────────

/// Spawn a background task that checks every 12 hours whether renewal is needed.
/// When a renewal completes, sends `(cert_pem, key_pem)` via `cert_tx`.
pub fn spawn_renewal_task(
    client: Arc<AcmeClient>,
    cert_tx: tokio::sync::mpsc::Sender<(String, String)>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await; // discard immediate tick
        loop {
            interval.tick().await;
            if client.needs_renewal().await {
                info!(
                    event = "acme.renewal_check",
                    "certificate renewal needed — starting ACME"
                );
                match client.obtain_certificate().await {
                    Ok((cert, key)) => {
                        info!(
                            event = "acme.cert_renewed",
                            "certificate renewed successfully"
                        );
                        crate::audit_event!(client.audit_log, "acme.cert_renewed", "domain" => "");
                        let _ = cert_tx.send((cert, key)).await;
                    }
                    Err(e) => {
                        warn!(
                            event = "acme.renewal_failed",
                            "certificate renewal failed: {e:#}"
                        );
                    }
                }
            } else {
                info!(
                    event = "acme.renewal_check",
                    "certificate valid — no renewal needed"
                );
            }
        }
    });
}

// ── HTTP-01 challenge server ───────────────────────────────────────────────────

/// Bind a minimal HTTP server that responds to ACME HTTP-01 challenges.
/// Only serves `/.well-known/acme-challenge/<token>` paths.
pub async fn run_acme_http_server(
    addr: std::net::SocketAddr,
    tokens: ChallengeTokenStore,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr)
        .await
        .context("binding ACME HTTP-01 server")?;
    info!(
        event = "acme.http01.listening",
        addr = %addr,
        "ACME HTTP-01 challenge server listening on {addr}"
    );

    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("ACME HTTP accept: {e}");
                continue;
            }
        };
        let tokens = tokens.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = match std::str::from_utf8(&buf[..n]) {
                Ok(s) => s,
                Err(_) => return,
            };
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");

            const PREFIX: &str = "/.well-known/acme-challenge/";
            let response = if let Some(token) = path.strip_prefix(PREFIX) {
                let token = token.trim_end_matches('/').to_string();
                let guard = tokens.read().await;
                if let Some(key_auth) = guard.get(&token) {
                    let body = key_auth.clone();
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                }
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_since_epoch_known_date() {
        assert_eq!(days_since_epoch(1970, 1, 1), Some(0));
        assert_eq!(days_since_epoch(1970, 1, 2), Some(1));
        assert_eq!(days_since_epoch(2000, 1, 1), Some(10957));
    }

    #[test]
    fn days_until_expiry_empty_pem() {
        assert_eq!(days_until_expiry("not a cert"), None);
    }
}
