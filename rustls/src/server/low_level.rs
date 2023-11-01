//! FIXME: docs

use core::ops::{Deref, DerefMut};

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::conn::ConnectionRandoms;
use crate::dns_name::DnsName;
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::low_level::{GeneratedMessage, SendState, WriteState};
use crate::msgs::enums::ECPointFormat;
use crate::msgs::handshake::{
    HandshakeMessagePayload, Random, ServerExtension, ServerHelloPayload, SessionId,
};
use crate::server::common::ActiveCertifiedKey;
use crate::server::{hs, ClientHello};
use crate::sign::CertifiedKey;
use crate::{
    low_level::{CommonState, ExpectState, LlConnectionCommon, WriteAlert},
    msgs::{
        enums::Compression,
        handshake::{ConvertServerNameList, HandshakePayload},
        message::{Message, MessagePayload},
    },
    AlertDescription, Error, HandshakeType, PeerIncompatible, PeerMisbehaved, ProtocolVersion,
    ServerConfig,
};
use crate::{suites, SupportedCipherSuite, Tls12CipherSuite};

/// FIXME: docs
pub struct LlServerConnection {
    conn: LlConnectionCommon<Arc<ServerConfig>>,
}

impl Deref for LlServerConnection {
    type Target = LlConnectionCommon<Arc<ServerConfig>>;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl DerefMut for LlServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl LlServerConnection {
    /// FIXME: docs
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            conn: LlConnectionCommon::new(
                config,
                CommonState::Expect(Box::new(ExpectClientHello::new())),
            )?,
        })
    }
}

struct ExpectClientHello {
    sni: Option<DnsName>,
}

impl ExpectClientHello {
    fn new() -> Self {
        Self { sni: None }
    }
}

impl ExpectState for ExpectClientHello {
    type Data = Arc<ServerConfig>;

    fn process_message(
        self: Box<Self>,
        common: &mut LlConnectionCommon<Self::Data>,
        msg: Message,
    ) -> Result<CommonState<Self::Data>, Error> {
        let client_hello = require_handshake_msg!(
            msg,
            HandshakeType::ClientHello,
            HandshakePayload::ClientHello
        )?;

        if !client_hello
            .compression_methods
            .contains(&Compression::Null)
        {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::IllegalParameter,
                PeerIncompatible::NullCompressionRequired,
            ))));
        }

        if client_hello.has_duplicate_extension() {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::DecodeError,
                PeerMisbehaved::DuplicateClientHelloExtensions,
            ))));
        }

        let sni: Option<DnsName> = match client_hello.get_sni_extension() {
            Some(sni) => {
                if sni.has_duplicate_names_for_type() {
                    return Ok(CommonState::Write(Box::new(WriteAlert::new(
                        AlertDescription::DecodeError,
                        PeerMisbehaved::DuplicateServerNameTypes,
                    ))));
                }

                if let Some(hostname) = sni.get_single_hostname() {
                    Some(hostname.to_lowercase_owned())
                } else {
                    return Ok(CommonState::Write(Box::new(WriteAlert::new(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::ServerNameMustContainOneHostName,
                    ))));
                }
            }
            None => None,
        };

        let Some(sig_schemes) = client_hello.get_sigalgs_extension() else {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::SignatureAlgorithmsExtensionRequired,
            ))));
        };

        let mut sig_schemes = sig_schemes.to_owned();

        let tls12_enabled = common
            .config
            .supports_version(ProtocolVersion::TLSv1_2);

        let maybe_versions_ext = client_hello.get_versions_extension();
        let version = if let Some(versions) = maybe_versions_ext {
            if !versions.contains(&ProtocolVersion::TLSv1_2) || !tls12_enabled {
                return Ok(CommonState::Write(Box::new(WriteAlert::new(
                    AlertDescription::ProtocolVersion,
                    PeerIncompatible::Tls12NotOfferedOrEnabled,
                ))));
            } else {
                ProtocolVersion::TLSv1_2
            }
        } else if client_hello.client_version.get_u16() < ProtocolVersion::TLSv1_2.get_u16() {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::ProtocolVersion,
                PeerIncompatible::Tls12NotOffered,
            ))));
        } else {
            ProtocolVersion::TLSv1_2
        };

        let client_suites = common
            .config
            .cipher_suites
            .iter()
            .copied()
            .filter(|scs| {
                client_hello
                    .cipher_suites
                    .contains(&scs.suite())
            })
            .collect::<Vec<_>>();

        sig_schemes
            .retain(|scheme| suites::compatible_sigscheme_for_suites(*scheme, &client_suites));

        // Choose a certificate.
        let certkey = {
            let client_hello = ClientHello::new(
                &self.sni,
                &sig_schemes,
                client_hello.get_alpn_extension(),
                &client_hello.cipher_suites,
            );

            let Some(certkey) = common
                .config
                .cert_resolver
                .resolve(client_hello)
            else {
                return Ok(CommonState::Write(Box::new(WriteAlert::new(
                    AlertDescription::AccessDenied,
                    Error::General("no server certificate chain resolved".to_owned()),
                ))));
            };

            certkey
        };

        let active_certkey = ActiveCertifiedKey::from_certified_key(&certkey);

        // Reduce our supported ciphersuites by the certificate.
        // (no-op for TLS1.3)
        let suitable_suites = suites::reduce_given_sigalg(
            &common.config.cipher_suites,
            active_certkey.get_key().algorithm(),
        );

        // And version
        let suitable_suites = suites::reduce_given_version(&suitable_suites, version);

        let suite = if common.config.ignore_client_order {
            suites::choose_ciphersuite_preferring_server(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        } else {
            suites::choose_ciphersuite_preferring_client(
                &client_hello.cipher_suites,
                &suitable_suites,
            )
        };

        let Some(suite) = suite else {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoCipherSuitesInCommon,
            ))));
        };

        // Start handshake hash.
        let starting_hash = suite.hash_provider();

        let SupportedCipherSuite::Tls12(suite) = suite else {
            unreachable!()
        };

        let mut transcript = HandshakeHashBuffer::new().start_hash(starting_hash);

        // Save their Random.
        let randoms =
            ConnectionRandoms::new(client_hello.random, Random::new(common.config.provider)?);

        // -- TLS1.2 only from hereon in --
        transcript.add_message(&msg);

        let using_ems = client_hello.ems_support_offered();

        let Some(groups_ext) = client_hello.get_namedgroups_extension() else {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NamedGroupsExtensionRequired,
            ))));
        };

        let Some(ecpoints_ext) = client_hello.get_ecpoints_extension() else {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::EcPointsExtensionRequired,
            ))));
        };

        if !ecpoints_ext.contains(&ECPointFormat::Uncompressed) {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::IllegalParameter,
                PeerIncompatible::UncompressedEcPointsRequired,
            ))));
        }

        // Now we have chosen a ciphersuite, we can make kx decisions.
        let sigschemes = suite.resolve_sig_schemes(&sig_schemes);

        if sigschemes.is_empty() {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoSignatureSchemesInCommon,
            ))));
        }

        let Some(ecpoint) = ECPointFormat::SUPPORTED
            .iter()
            .find(|format| ecpoints_ext.contains(format))
            .cloned()
        else {
            return Ok(CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoEcPointFormatsInCommon,
            ))));
        };

        debug_assert_eq!(ecpoint, ECPointFormat::Uncompressed);

        // If we're not offered a ticket or a potential session ID, allocate a session ID.
        let session_id = if !common
            .config
            .session_storage
            .can_cache()
        {
            SessionId::empty()
        } else {
            SessionId::random(common.config.provider)?
        };

        let mut ocsp_response = active_certkey.get_ocsp();

        let mut ep = hs::ExtensionProcessing::new();
        let mut alpn_protocol = None;
        if let Err((opt_desc, err)) = ep.process_common_aux(
            &common.config,
            &mut alpn_protocol,
            #[cfg(feature = "quic")]
            false,
            #[cfg(feature = "quic")]
            &mut crate::quic::Quic::default(),
            false,
            &mut ocsp_response,
            client_hello,
            None,
            vec![],
        ) {
            return match opt_desc {
                Some(desc) => Ok(CommonState::Write(Box::new(WriteAlert::new(desc, err)))),
                None => Err(err),
            };
        }
        ep.process_tls12(&common.config, client_hello, using_ems);

        Ok(CommonState::Write(Box::new(WriteServerHello {
            session_id,
            transcript,
            randoms,
            suite,
            extensions: ep.exts,
            certkey,
        })))
    }
}

struct WriteServerHello {
    session_id: SessionId,
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    extensions: Vec<ServerExtension>,
    certkey: Arc<CertifiedKey>,
}

impl WriteState for WriteServerHello {
    type Data = Arc<ServerConfig>;

    fn generate_message(
        mut self: Box<Self>,
        _conn: &mut LlConnectionCommon<Self::Data>,
    ) -> GeneratedMessage<Self::Data> {
        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHello,
                payload: HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from(self.randoms.server),
                    session_id: self.session_id,
                    cipher_suite: self.suite.common.suite,
                    compression_method: Compression::Null,
                    extensions: self.extensions,
                }),
            }),
        };

        self.transcript.add_message(&sh);

        GeneratedMessage::new(
            sh,
            CommonState::Send(Box::new(SendServerHello {
                transcript: self.transcript,
                certkey: self.certkey,
            })),
        )
    }
}

struct SendServerHello {
    transcript: HandshakeHash,
    certkey: Arc<CertifiedKey>,
}

impl SendState for SendServerHello {
    type Data = Arc<ServerConfig>;

    fn tls_data_done(self: Box<Self>) -> CommonState<Self::Data> {
        CommonState::Write(Box::new(WriteCertificate {
            transcript: self.transcript,
            certkey: self.certkey,
        }))
    }
}

struct WriteCertificate {
    transcript: HandshakeHash,
    certkey: Arc<CertifiedKey>,
}

impl WriteState for WriteCertificate {
    type Data = Arc<ServerConfig>;

    fn generate_message(
        mut self: Box<Self>,
        conn: &mut LlConnectionCommon<Self::Data>,
    ) -> GeneratedMessage<Self::Data> {
        let c = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::Certificate,
                payload: HandshakePayload::Certificate(
                    ActiveCertifiedKey::from_certified_key(self.certkey.as_ref())
                        .get_cert()
                        .to_owned(),
                ),
            }),
        };

        self.transcript.add_message(&c);

        GeneratedMessage::new(
            c,
            CommonState::Send(Box::new(SendCertificate {
                transcript: self.transcript,
            })),
        )
    }
}

struct SendCertificate {
    transcript: HandshakeHash,
}

impl SendState for SendCertificate {
    type Data = Arc<ServerConfig>;

    fn tls_data_done(self: Box<Self>) -> CommonState<Self::Data> {
        CommonState::Write(Box::new(WriteServerKeyExchange {
            transcript: self.transcript,
        }))
    }
}

struct WriteServerKeyExchange {
    transcript: HandshakeHash,
}

impl WriteState for WriteServerKeyExchange {
    type Data = Arc<ServerConfig>;

    fn generate_message(
        self: Box<Self>,
        conn: &mut LlConnectionCommon<Self::Data>,
    ) -> GeneratedMessage<Self::Data> {
        todo!()
    }
}
