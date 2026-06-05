use anyhow::{bail, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Build a `TlsAcceptor` from PEM-encoded certificate and private key files.
pub fn acceptor_from_files(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading TLS cert {cert_path}"))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading TLS key {key_path}"))?;
    acceptor_from_pem(&cert_pem, &key_pem)
}

/// Build a `TlsAcceptor` for a freshly-generated self-signed certificate.
/// The cert covers `domains` (use the relay's public hostname(s)).
pub fn self_signed_acceptor(domains: &[&str]) -> Result<TlsAcceptor> {
    let mut params = CertificateParams::new(domains.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .context("building self-signed cert params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Seamless Relay (self-signed)");
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate().context("generating TLS key pair")?;
    let cert = params.self_signed(&key_pair).context("signing self-signed cert")?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    acceptor_from_pem(&cert_pem, &key_pem)
}

fn acceptor_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    let certs: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()
        .context("parsing TLS certificate PEM")?;
    if certs.is_empty() {
        bail!("no certificates found in cert PEM");
    }

    let key = private_key(&mut BufReader::new(key_pem))
        .context("parsing TLS private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in key PEM"))?;


    // Enforce TLS 1.3 only — CNSA 2.0 / NIST SP 800-52 Rev 2 requirement.
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS 1.3-only server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// ── Admin mTLS ────────────────────────────────────────────────────────────────

/// Build a `TlsAcceptor` for the admin port with optional mutual TLS.
///
/// - `cert_path` / `key_path` — the server's certificate and private key (PEM).
/// - `client_ca_path` — when `Some`, enable mTLS: only clients presenting a
///   certificate signed by this CA are allowed. This is the recommended
///   configuration for government / classified network deployments.
pub fn admin_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<TlsAcceptor> {
    use rustls::server::WebPkiClientVerifier;
    use rustls::RootCertStore;
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading admin TLS cert {cert_path}"))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading admin TLS key {key_path}"))?;

    let server_certs: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(cert_pem.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .context("parsing admin TLS certificate PEM")?;
    if server_certs.is_empty() {
        bail!("no certificates found in admin TLS cert PEM");
    }

    let key = private_key(&mut BufReader::new(key_pem.as_slice()))
        .context("parsing admin TLS private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in admin TLS key PEM"))?;

    let config = if let Some(ca_path) = client_ca_path {
        // Mutual TLS: require client certificates signed by the given CA.
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("reading admin client CA {ca_path}"))?;
        let ca_certs: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(ca_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .context("parsing admin client CA PEM")?;
        if ca_certs.is_empty() {
            bail!("no certificates found in admin client CA PEM");
        }

        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).context("adding client CA certificate to root store")?;
        }
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("building mTLS client verifier")?;

        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, key)
            .context("building admin mTLS server config")?
    } else {
        // TLS without client verification (still TLS 1.3 only).
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .context("building admin TLS server config")?
    };

    Ok(TlsAcceptor::from(Arc::new(config)))
}
