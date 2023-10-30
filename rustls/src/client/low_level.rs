//! FIXME: docs

use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::conn::ConnectionRandoms;
use crate::hash_hs::HandshakeHashBuffer;
use crate::low_level::{
    log_msg, CommonState, ExpectState, GeneratedMessage, LlConnectionCommon, SendState, WriteState,
};
use crate::msgs::enums::{Compression, ECPointFormat};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, Random, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::{
    AlertDescription, ClientConfig, Error, HandshakeType, PeerMisbehaved, ProtocolVersion,
    ServerName, SupportedCipherSuite,
};

/// FIXME: docs
pub struct LlClientConnection {
    conn: LlConnectionCommon,
}

impl Deref for LlClientConnection {
    type Target = LlConnectionCommon;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl DerefMut for LlClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl LlClientConnection {
    /// FIXME: docs
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Result<Self, Error> {
        Ok(Self {
            conn: LlConnectionCommon::new(config, name)?,
        })
    }
}

pub(crate) struct WriteClientHello {
    random: Random,
}

impl WriteClientHello {
    pub(crate) fn new(config: &ClientConfig) -> Result<Self, Error> {
        Ok(Self {
            random: Random::new(config.provider)?,
        })
    }

    pub(crate) fn generate_message(self, common: &mut LlConnectionCommon) -> GeneratedMessage {
        let support_tls12 = common
            .config
            .supports_version(ProtocolVersion::TLSv1_2);

        let mut supported_versions = Vec::new();
        if support_tls12 {
            supported_versions.push(ProtocolVersion::TLSv1_2);
        }

        let payload = HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                client_version: ProtocolVersion::TLSv1_2,
                random: self.random,
                session_id: SessionId::empty(),
                cipher_suites: common
                    .config
                    .cipher_suites
                    .iter()
                    .map(|cs| cs.suite())
                    .collect(),
                compression_methods: vec![Compression::Null],
                extensions: vec![
                    ClientExtension::SupportedVersions(supported_versions),
                    ClientExtension::EcPointFormats(ECPointFormat::SUPPORTED.to_vec()),
                    ClientExtension::NamedGroups(
                        common
                            .config
                            .kx_groups
                            .iter()
                            .map(|skxg| skxg.name())
                            .collect(),
                    ),
                    ClientExtension::SignatureAlgorithms(
                        common
                            .config
                            .verifier
                            .supported_verify_schemes(),
                    ),
                    ClientExtension::ExtendedMasterSecretRequest,
                    ClientExtension::CertificateStatusRequest(
                        CertificateStatusRequest::build_ocsp(),
                    ),
                ],
            }),
        };

        let msg = Message {
            version: ProtocolVersion::TLSv1_0,
            payload: MessagePayload::handshake(payload),
        };
        log_msg(&msg, false);

        let mut transcript_buffer = HandshakeHashBuffer::new();
        transcript_buffer.add_message(&msg);
        let next_state = CommonState::Send(SendState::ClientHello(SendClientHello {
            transcript_buffer,
            random: self.random,
        }));

        GeneratedMessage::new(msg, next_state)
    }
}

pub(crate) struct SendClientHello {
    transcript_buffer: HandshakeHashBuffer,
    random: Random,
}

impl SendClientHello {
    pub(crate) fn tls_data_done(self) -> CommonState {
        CommonState::Expect(ExpectState::ServerHello(ExpectServerHello {
            transcript_buffer: self.transcript_buffer,
            random: self.random,
        }))
    }
}

pub(crate) struct ExpectServerHello {
    transcript_buffer: HandshakeHashBuffer,
    random: Random,
}

impl ExpectServerHello {
    pub(crate) fn process_message(
        self,
        common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let payload = require_handshake_msg!(
            msg,
            HandshakeType::ServerHello,
            HandshakePayload::ServerHello
        )?;
        if let Some(suite) = common
            .config
            .find_cipher_suite(payload.cipher_suite)
        {
            let mut transcript = self
                .transcript_buffer
                .start_hash(suite.hash_provider());

            transcript.add_message(&msg);

            let suite = match suite {
                SupportedCipherSuite::Tls12(suite) => suite,
                SupportedCipherSuite::Tls13(_) => todo!(),
            };

            Ok(CommonState::Expect(ExpectState::Certificate {
                suite,
                randoms: ConnectionRandoms::new(self.random, payload.random),
                transcript,
            }))
        } else {
            Ok(CommonState::Write(WriteState::Alert {
                description: AlertDescription::HandshakeFailure,
                error: PeerMisbehaved::SelectedUnofferedCipherSuite.into(),
            }))
        }
    }
}
