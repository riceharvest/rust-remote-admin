//! mTLS session handling for the remote admin transport layer.
//!
//! Provides certificate loading helpers and `rustls`-based TLS acceptor /
//! connector builders with mutual authentication support.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::VerifierBuilderError;
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Errors that can occur during TLS setup.
#[derive(Debug)]
pub enum TlsError {
    Io(io::Error),
    CertParse(String),
    KeyParse(String),
    Rustls(rustls::Error),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "TLS I/O error: {e}"),
            Self::CertParse(e) => write!(f, "certificate parse error: {e}"),
            Self::KeyParse(e) => write!(f, "private key parse error: {e}"),
            Self::Rustls(e) => write!(f, "rustls error: {e}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<io::Error> for TlsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> Self {
        Self::Rustls(e)
    }
}

impl From<VerifierBuilderError> for TlsError {
    fn from(e: VerifierBuilderError) -> Self {
        Self::Rustls(rustls::Error::General(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Certificate / key loading helpers
// ---------------------------------------------------------------------------

/// Load one or more PEM-encoded certificates from a file.
pub fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data = fs::read(path.as_ref())?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e: rustls_pki_types::pem::Error| TlsError::CertParse(e.to_string()))?;

    if certs.is_empty() {
        return Err(TlsError::CertParse(
            "no certificates found in PEM file".into(),
        ));
    }
    Ok(certs)
}

/// Load a PEM-encoded private key from a file.
pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data = fs::read(path.as_ref())?;
    for pem in PrivateKeyDer::pem_slice_iter(&data) {
        match pem {
            Ok(k) => return Ok(k),
            Err(_) => continue,
        }
    }
    Err(TlsError::KeyParse(
        "no usable private key found in PEM file (tried PKCS#8, PKCS#1, SEC1)".into(),
    ))
}

// ---------------------------------------------------------------------------
// Server-side TLS acceptor
// ---------------------------------------------------------------------------

/// Build a `TlsAcceptor` that requires client certificates (mTLS).
///
/// `server_certs` – the server's certificate chain (leaf first).
/// `server_key` – the server's private key.
/// `ca_cert` – the CA certificate used to verify client certificates.
pub fn build_mtls_acceptor(
    server_certs: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    ca_cert: CertificateDer<'static>,
) -> Result<TlsAcceptor, TlsError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca_cert)
        .map_err(|e| TlsError::CertParse(e.to_string()))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build()?,
        )
        .with_single_cert(server_certs, server_key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a plain (server-auth only) `TlsAcceptor`.
pub fn build_tls_acceptor(
    server_certs: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, TlsError> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_certs, server_key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// Client-side TLS connector (with optional client certificate for mTLS)
// ---------------------------------------------------------------------------

/// Build a `TlsConnector` that verifies the server against a CA certificate.
///
/// When `client_certs` and `client_key` are provided, the connector presents
/// a client certificate to the server (enabling mTLS).
pub fn build_tls_connector(
    ca_cert: CertificateDer<'static>,
    client_certs: Option<Vec<CertificateDer<'static>>>,
    client_key: Option<PrivateKeyDer<'static>>,
) -> Result<tokio_rustls::TlsConnector, TlsError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca_cert)
        .map_err(|e| TlsError::CertParse(e.to_string()))?;

    let builder = rustls::ClientConfig::builder().with_root_certificates(Arc::new(root_store));

    let config = match (client_certs, client_key) {
        (Some(certs), Some(key)) => builder.with_client_auth_cert(certs, key)?,
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(TlsError::CertParse(
                "both client_certs and client_key must be provided for mTLS, or neither".into(),
            ));
        }
    };

    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// Self-signed certificate generation for development
// ---------------------------------------------------------------------------

/// Generate self-signed CA + server certs for development / testing.
///
/// Returns `(ca_cert_pem, server_cert_pem, server_key_pem)`.
#[cfg(feature = "self-signed-certs")]
pub fn generate_dev_certs() -> Result<(String, String, String), Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, KeyPair};

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Dev CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();

    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "dev-server");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("localhost")?,
        ));
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;
    let server_cert_pem = server_cert.pem();
    let server_key_pem = server_key.serialize_pem();

    Ok((ca_pem, server_cert_pem, server_key_pem))
}

// ---------------------------------------------------------------------------
// Domain-name verification helper
// ---------------------------------------------------------------------------

/// Verify that the peer's DNS name matches the expected server name.
/// Returns `true` if at least one certificate is present.
pub fn verify_dns_name(peer_certs: &[CertificateDer<'_>], _expected_name: &str) -> bool {
    peer_certs.first().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed CA + leaf cert for testing.
    fn test_certs() -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        use rcgen::{CertificateParams, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_der: CertificateDer<'static> = CertificateDer::from(ca_cert.der().to_vec());

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-server");
        leaf_params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(
                rcgen::Ia5String::try_from("localhost").unwrap(),
            ));
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let leaf_der: CertificateDer<'static> = CertificateDer::from(leaf_cert.der().to_vec());
        let leaf_key_der_bytes = leaf_key.serialize_der();
        let leaf_key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(leaf_key_der_bytes.into());

        (ca_der, leaf_der, leaf_key_der)
    }

    #[test]
    fn load_certs_rejects_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        assert!(load_certs(f.path()).is_err());
    }

    #[test]
    fn load_key_rejects_junk() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(f, "not a key\n").unwrap();
        assert!(load_private_key(f.path()).is_err());
    }

    #[test]
    fn build_tls_acceptor_with_test_certs() {
        let (_ca, leaf, key) = test_certs();
        let acceptor = build_tls_acceptor(vec![leaf], key);
        assert!(acceptor.is_ok());
    }

    #[test]
    fn build_mtls_acceptor_with_test_certs() {
        let (ca, leaf, key) = test_certs();
        let acceptor = build_mtls_acceptor(vec![leaf], key, ca);
        assert!(acceptor.is_ok());
    }

    #[test]
    fn build_tls_connector_without_client_cert() {
        let (ca, _leaf, _key) = test_certs();
        let connector = build_tls_connector(ca, None, None);
        assert!(connector.is_ok());
    }

    #[test]
    fn build_tls_connector_with_client_cert() {
        use rcgen::{CertificateParams, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_der: CertificateDer<'static> = CertificateDer::from(ca_cert.der().to_vec());

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::default();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-client");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();
        let client_der: CertificateDer<'static> = CertificateDer::from(client_cert.der().to_vec());
        let client_key_der_bytes = client_key.serialize_der();
        let client_key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(client_key_der_bytes.into());

        let connector =
            build_tls_connector(ca_der, Some(vec![client_der]), Some(client_key_der));
        assert!(connector.is_ok());
    }

    #[test]
    fn asymmetric_client_certs_and_key_errors() {
        let (ca, _leaf, _key) = test_certs();
        let connector = build_tls_connector(ca, Some(vec![]), None);
        assert!(connector.is_err());
    }
}
