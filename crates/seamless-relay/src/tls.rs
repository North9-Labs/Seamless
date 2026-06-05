use anyhow::{bail, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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

    let key = PrivateKeyDer::try_from(key).map_err(|e| anyhow::anyhow!("invalid key: {e}"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
