//! Validate dedicated operator-supplied broker certificates with rustls.
use super::*;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::sync::Arc;

pub(crate) fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs =
        CertificateDer::pem_reader_iter(fs::File::open(path)?).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("broker certificate file is empty".into());
    }
    Ok(certs)
}

pub(crate) fn same_public_key(first: &[u8], second: &[u8]) -> bool {
    match (
        x509_parser::parse_x509_certificate(first),
        x509_parser::parse_x509_certificate(second),
    ) {
        (Ok((_, first)), Ok((_, second))) => first.public_key().raw == second.public_key().raw,
        _ => false,
    }
}

pub(crate) fn roots(path: &Path) -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certificates(path)? {
        roots.add(cert)?;
    }
    Ok(roots)
}

pub(crate) fn trust_hash(path: &Path) -> Result<String, Error> {
    let mut certs: Vec<_> = certificates(path)?
        .into_iter()
        .map(|cert| cert.to_vec())
        .collect();
    certs.sort();
    certs.dedup();
    Ok(hash(&serde_json::to_vec(&certs)?))
}

pub(crate) fn client_config(ca: &Path) -> Result<rustls::ClientConfig, Error> {
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots(ca)?)
    .with_no_client_auth())
}

pub(crate) fn validate(
    cert: &Path,
    key: &Path,
    ca: &Path,
    names: &[String],
) -> Result<Value, Error> {
    if names.is_empty() {
        return Err("broker TLS needs at least one endpoint name".into());
    }
    let chain = certificates(cert)?;
    let key = PrivateKeyDer::from_pem_file(key)?;
    let provider = rustls::crypto::ring::default_provider();
    rustls::sign::CertifiedKey::from_der(chain.clone(), key, &provider)?.keys_match()?;
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots(ca)?),
        Arc::new(provider),
    )
    .build()?;
    for name in names {
        verifier.verify_server_cert(
            &chain[0],
            &chain[1..],
            &ServerName::try_from(name.clone())?,
            &[],
            UnixTime::now(),
        )?;
    }
    let (_, leaf) = x509_parser::parse_x509_certificate(&chain[0])
        .map_err(|_| "invalid broker leaf certificate")?;
    Ok(
        json!({"verified":true,"endpoint_names":names,"certificate_sha256":hash(&chain[0]),
        "trust_sha256":trust_hash(ca)?,"not_before":leaf.validity().not_before.to_string(),"not_after":leaf.validity().not_after.to_string()}),
    )
}
