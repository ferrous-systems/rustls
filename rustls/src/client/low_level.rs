//! FIXME: docs

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use pki_types::UnixTime;
use std::sync::Arc;

use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::conn::ConnectionRandoms;
use crate::crypto::ActiveKeyExchange;
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::low_level::{
    log_msg, CommonState, ExpectState, GeneratedMessage, LlConnectionCommon, SendState, WriteAlert,
    WriteState,
};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{Compression, ECPointFormat};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, Random, ServerEcdhParams, ServerKeyExchangePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::tls12::ConnectionSecrets;
use crate::{
    AlertDescription, ClientConfig, ContentType, Error, HandshakeType, InvalidMessage,
    PeerMisbehaved, ProtocolVersion, ServerName, Side, SupportedCipherSuite, Tls12CipherSuite,
};

use super::tls12::ServerKxDetails;

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
        let next_state = CommonState::Send(Box::new(SendClientHello {
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

impl SendState for SendClientHello {
    fn tls_data_done(self: Box<Self>) -> CommonState {
        CommonState::Expect(Box::new(ExpectServerHello {
            transcript_buffer: self.transcript_buffer,
            random: self.random,
        }))
    }
}

pub(crate) struct ExpectServerHello {
    transcript_buffer: HandshakeHashBuffer,
    random: Random,
}

impl ExpectState for ExpectServerHello {
    fn process_message(
        self: Box<Self>,
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

            Ok(CommonState::Expect(Box::new(ExpectCertificate {
                suite,
                randoms: ConnectionRandoms::new(self.random, payload.random),
                transcript,
            })))
        } else {
            Ok(CommonState::Write(WriteState::Alert(WriteAlert::new(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::SelectedUnofferedCipherSuite,
            ))))
        }
    }
}

pub(crate) struct ExpectCertificate {
    suite: &'static Tls12CipherSuite,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}

impl ExpectState for ExpectCertificate {
    fn process_message(
        self: Box<Self>,
        common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let payload = require_handshake_msg_move!(
            msg,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if let Err(error) = common
            .config
            .verifier
            .verify_server_cert(&payload[0], &[], &common.name, &[], UnixTime::now())
        {
            Ok(CommonState::Write(WriteState::Alert(WriteAlert::new(
                match &error {
                    Error::InvalidCertificate(e) => e.clone().into(),
                    Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
                    _ => AlertDescription::HandshakeFailure,
                },
                error,
            ))))
        } else {
            Ok(CommonState::Expect(Box::new(ExpectServerKeyExchange {
                suite: self.suite,
                randoms: self.randoms,
                transcript: self.transcript,
            })))
        }
    }

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

pub(crate) struct ExpectServerKeyExchange {
    suite: &'static Tls12CipherSuite,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}
impl ExpectState for ExpectServerKeyExchange {
    fn process_message(
        self: Box<Self>,
        _common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let opaque_kx = require_handshake_msg_move!(
            msg,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;

        Ok(CommonState::Expect(Box::new(ExpectServerHelloDone {
            suite: self.suite,
            randoms: self.randoms,
            opaque_kx,
            transcript: self.transcript,
        })))
    }

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

pub(crate) struct ExpectServerHelloDone {
    suite: &'static Tls12CipherSuite,
    opaque_kx: ServerKeyExchangePayload,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}

impl ExpectState for ExpectServerHelloDone {
    fn process_message(
        self: Box<Self>,
        common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        match msg.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::CertificateRequest,
                        payload: HandshakePayload::CertificateRequest(_),
                    },
                ..
            } => Ok(CommonState::Expect(self)),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::ServerHelloDone,
                        payload: HandshakePayload::ServerHelloDone,
                    },
                ..
            } => match self
                .opaque_kx
                .unwrap_given_kxa(self.suite.kx)
            {
                Some(ecdhe) => {
                    let mut kx_params = Vec::new();
                    ecdhe.params.encode(&mut kx_params);
                    let server_kx = ServerKxDetails::new(kx_params, ecdhe.dss);

                    let mut rd = Reader::init(&server_kx.kx_params);
                    let ecdh_params = ServerEcdhParams::read(&mut rd)?;

                    if rd.any_left() {
                        Ok(CommonState::Write(WriteState::Alert(WriteAlert::new(
                            AlertDescription::DecodeError,
                            InvalidMessage::InvalidDhParams,
                        ))))
                    } else if let Some(skxg) = common
                        .config
                        .find_kx_group(ecdh_params.curve_params.named_group)
                    {
                        let kx = skxg
                            .start()
                            .map_err(|_| Error::FailedToGetRandomBytes)?;

                        Ok(CommonState::Write(WriteState::ClientKeyExchange(
                            WriteClientKeyExchange {
                                suite: self.suite,
                                kx,
                                ecdh_params,
                                randoms: self.randoms,
                                transcript: self.transcript,
                            },
                        )))
                    } else {
                        Ok(CommonState::Write(WriteState::Alert(WriteAlert::new(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup,
                        ))))
                    }
                }
                None => Ok(CommonState::Write(WriteState::Alert(WriteAlert::new(
                    AlertDescription::DecodeError,
                    InvalidMessage::MissingKeyExchange,
                )))),
            },
            payload => {
                return Err(inappropriate_handshake_message(
                    &payload,
                    &[ContentType::Handshake],
                    &[
                        HandshakeType::ServerHelloDone,
                        HandshakeType::CertificateRequest,
                    ],
                ));
            }
        }
    }

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}

pub(crate) struct WriteClientKeyExchange {
    suite: &'static Tls12CipherSuite,
    kx: Box<dyn ActiveKeyExchange>,
    ecdh_params: ServerEcdhParams,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
}
impl WriteClientKeyExchange {
    pub(crate) fn generate_message(mut self, _common: &mut LlConnectionCommon) -> GeneratedMessage {
        let mut buf = Vec::new();
        let ecpoint = PayloadU8::new(Vec::from(self.kx.pub_key()));
        ecpoint.encode(&mut buf);
        let pubkey = Payload::new(buf);

        let msg = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientKeyExchange,
                payload: HandshakePayload::ClientKeyExchange(pubkey),
            }),
        };
        log_msg(&msg, false);

        self.transcript.add_message(&msg);

        let next_state = CommonState::SetupClientEncryption(SetupClientEncryption {
            kx: self.kx,
            peer_pub_key: self.ecdh_params.public.0,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
        });

        GeneratedMessage::new(msg, next_state)
    }
}

pub(crate) struct SetupClientEncryption {
    kx: Box<dyn ActiveKeyExchange>,
    peer_pub_key: Vec<u8>,
    randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    transcript: HandshakeHash,
}

impl SetupClientEncryption {
    pub(crate) fn setup_encryption(
        self,
        common: &mut LlConnectionCommon,
    ) -> Result<CommonState, Error> {
        {
            let secrets = ConnectionSecrets::from_key_exchange(
                self.kx,
                &self.peer_pub_key,
                Some(self.transcript.get_current_hash()),
                self.randoms,
                self.suite,
            )?;

            let (dec, enc) = secrets.make_cipher_pair(Side::Client);

            common
                .record_layer
                .prepare_message_encrypter(enc);
            common
                .record_layer
                .prepare_message_decrypter(dec);
            common.record_layer.start_encrypting();

            Ok(CommonState::Send(Box::new(SendClientKeyExchange {
                secrets,
                transcript: self.transcript,
            })))
        }
    }
}

pub(crate) struct SendClientKeyExchange {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
}

impl SendState for SendClientKeyExchange {
    fn tls_data_done(self: Box<Self>) -> CommonState {
        CommonState::Write(WriteState::ChangeCipherSpec(WriteChangeCipherSpec {
            secrets: self.secrets,
            transcript: self.transcript,
        }))
    }
}

pub(crate) struct WriteChangeCipherSpec {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
}
impl WriteChangeCipherSpec {
    pub(crate) fn generate_message(self, _common: &mut LlConnectionCommon) -> GeneratedMessage {
        let msg = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };
        log_msg(&msg, false);

        let next_state = CommonState::Send(Box::new(SendChangeCipherSpec {
            secrets: self.secrets,
            transcript: self.transcript,
        }));

        GeneratedMessage::new(msg, next_state)
    }
}

pub(crate) struct SendChangeCipherSpec {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
}

impl SendState for SendChangeCipherSpec {
    fn tls_data_done(self: Box<Self>) -> CommonState {
        CommonState::Write(WriteState::Finished(WriteFinished {
            secrets: self.secrets,
            transcript: self.transcript,
        }))
    }
}

pub(crate) struct WriteFinished {
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
}
impl WriteFinished {
    pub(crate) fn generate_message(mut self, _common: &mut LlConnectionCommon) -> GeneratedMessage {
        let vh = self.transcript.get_current_hash();
        let verify_data = self.secrets.client_verify_data(&vh);
        let verify_data_payload = Payload::new(verify_data);

        let msg = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };
        log_msg(&msg, false);

        self.transcript.add_message(&msg);

        GeneratedMessage::new(
            msg,
            CommonState::Send(Box::new(SendFinished {
                transcript: self.transcript,
            })),
        )
        .require_encryption(true)
    }
}

pub(crate) struct SendFinished {
    transcript: HandshakeHash,
}

impl SendState for SendFinished {
    fn tls_data_done(self: Box<Self>) -> CommonState {
        CommonState::Expect(Box::new(ExpectChangeCipherSpec {
            transcript: self.transcript,
        }))
    }
}

pub(crate) struct ExpectChangeCipherSpec {
    transcript: HandshakeHash,
}

impl ExpectState for ExpectChangeCipherSpec {
    fn process_message(
        self: Box<Self>,
        common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        match msg.payload {
            MessagePayload::ChangeCipherSpec(_) => {
                common.record_layer.start_decrypting();
                Ok(CommonState::Expect(Box::new(ExpectFinished {
                    transcript: self.transcript,
                })))
            }
            payload => Err(inappropriate_message(
                &payload,
                &[ContentType::ChangeCipherSpec],
            )),
        }
    }
}

pub(crate) struct ExpectFinished {
    transcript: HandshakeHash,
}

impl ExpectState for ExpectFinished {
    fn process_message(
        self: Box<Self>,
        _common: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let _ = require_handshake_msg!(msg, HandshakeType::Finished, HandshakePayload::Finished)?;

        Ok(CommonState::HandshakeDone)
    }

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        Some(&mut self.transcript)
    }
}
