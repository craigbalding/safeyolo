//! Existing CA import and leaf issuance. HTTPS interception wiring is separate.
//!
//! Import never rewrites or rotates an operator's trust root. Legacy RSA
//! PKCS#1 material is wrapped in PKCS#8 only in memory for the ring signer.

use std::{io::Cursor, path::Path, sync::Arc};

use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo, der::Encode};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pemfile::Item;
use time::{Duration, OffsetDateTime};

use crate::Error;

/// Holds CA signing material without exposing it through Debug or serialization.
pub struct CertificateAuthority {
    certificate: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl CertificateAuthority {
    /// Read the existing combined `mitmproxy-ca.pem` file. Missing or invalid
    /// material is an error; creating a different trust root is never a fallback.
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::from_pem(&std::fs::read(path)?)
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        let mut certificates = Vec::new();
        let mut private_key = None;
        for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
            let key = match item? {
                Item::X509Certificate(cert) => {
                    certificates.push(cert);
                    continue;
                }
                Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
                Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
                Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
                _ => continue,
            };
            if private_key.replace(key).is_some() {
                return Err("CA file contains more than one private key".into());
            }
        }
        let key = private_key.ok_or("CA file has no private key")?;
        let certificate = certificates
            .into_iter()
            .next()
            .ok_or("CA file has no certificate")?;
        let (rest, parsed) = x509_parser::parse_x509_certificate(&certificate)
            .map_err(|_| "invalid CA certificate")?;
        if !rest.is_empty()
            || !parsed
                .basic_constraints()?
                .is_some_and(|extension| extension.value.ca)
        {
            return Err("configured signing certificate is not a CA".into());
        }
        if parsed
            .key_usage()?
            .is_some_and(|extension| !extension.value.key_cert_sign())
        {
            return Err("configured CA cannot sign certificates".into());
        }
        let not_before = parsed.validity().not_before.to_datetime();
        let not_after = parsed.validity().not_after.to_datetime();
        let provider = rustls::crypto::ring::default_provider();
        let certified_key =
            CertifiedKey::from_der(vec![certificate.clone()], key.clone_key(), &provider)?;
        certified_key.keys_match()?;

        let signing_key = match key {
            PrivateKeyDer::Pkcs1(key) => {
                // RFC 5208 wraps the unchanged PKCS#1 payload with rsaEncryption.
                // The operator's on-disk PEM and certificate remain byte-identical.
                let algorithm = AlgorithmIdentifierRef {
                    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                    parameters: Some(pkcs8::der::asn1::AnyRef::NULL),
                };
                let wrapped = PrivateKeyInfo::new(algorithm, key.secret_pkcs1_der()).to_der()?;
                KeyPair::try_from(&PrivatePkcs8KeyDer::from(wrapped))?
            }
            key => KeyPair::try_from(&key)?,
        };
        let issuer = Issuer::from_ca_cert_der(&certificate, signing_key)?;
        Ok(Self {
            certificate,
            issuer,
            not_before,
            not_after,
        })
    }

    /// The original public trust root, suitable for fingerprint/restart checks.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    pub fn server_config(
        &self,
        host: &str,
        now: OffsetDateTime,
    ) -> Result<Arc<rustls::ServerConfig>, Error> {
        let resolver = PinnedCertificate {
            host: host.to_owned(),
            key: self.issue(host, now)?,
        };
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// Issue a leaf for the admitted destination only. Caller-supplied SNI or an
    /// inner HTTP authority must not expand this name after CONNECT admission.
    pub fn issue(&self, host: &str, now: OffsetDateTime) -> Result<Arc<CertifiedKey>, Error> {
        ServerName::try_from(host)?;
        if now < self.not_before || now >= self.not_after {
            return Err("configured CA is not currently valid".into());
        }
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        // Preserve the current mitmproxy leaf validity window: two days of
        // clock-skew allowance and 199 days total, bounded by the existing CA.
        params.not_before = now - Duration::days(2);
        params.not_after = (now + Duration::days(197)).min(self.not_after);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate()?;
        let certificate = params.signed_by(&key, &self.issuer)?;
        Ok(Arc::new(CertifiedKey::from_der(
            vec![certificate.der().clone(), self.certificate.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            &rustls::crypto::ring::default_provider(),
        )?))
    }
}

#[derive(Debug)]
struct PinnedCertificate {
    host: String,
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for PinnedCertificate {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello.server_name().is_some_and(|name| {
            !name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(self.host.trim_end_matches('.'))
        }) {
            return None;
        }
        Some(self.key.clone())
    }
}
