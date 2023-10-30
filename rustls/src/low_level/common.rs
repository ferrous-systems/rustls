//! FIXME: docs

use core::num::NonZeroUsize;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use pki_types::UnixTime;
use std::sync::Arc;

use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::client::tls12::ServerKxDetails;
use crate::conn::ConnectionRandoms;
use crate::crypto::cipher::{OpaqueMessage, PlainMessage};
use crate::crypto::ActiveKeyExchange;
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::internal::record_layer::RecordLayer;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertLevel, ECPointFormat};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ServerEcdhParams, ServerKeyExchangePayload,
};
use crate::msgs::message::MessageError;
use crate::tls12::ConnectionSecrets;
use crate::{
    msgs::{
        enums::Compression,
        fragmenter::MessageFragmenter,
        handshake::{
            ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionId,
        },
        message::{Message, MessagePayload},
    },
    ClientConfig, Error, HandshakeType, ProtocolVersion,
};
use crate::{
    AlertDescription, ContentType, InvalidMessage, PeerMisbehaved, ServerName, Side,
    SupportedCipherSuite, Tls12CipherSuite,
};

fn log_msg(msg: &Message, read: bool) {
    let verb = if read { "Read" } else { "Write" };
    match &msg.payload {
        MessagePayload::Handshake {
            parsed: HandshakeMessagePayload { typ, .. },
            ..
        } => std::println!("{} {:?}", verb, typ),
        payload => std::println!("{} {:?}", verb, payload.content_type()),
    };
}

enum ExpectState {
    ServerHello {
        transcript_buffer: HandshakeHashBuffer,
        random: Random,
    },
    Certificate {
        suite: &'static Tls12CipherSuite,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    ServerKeyExchange {
        suite: &'static Tls12CipherSuite,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    ServerHelloDone {
        suite: &'static Tls12CipherSuite,
        opaque_kx: ServerKeyExchangePayload,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    ChangeCipherSpec,
    Finished,
}

enum WriteState {
    ClientHello {
        random: Random,
    },
    ClientKeyExchange {
        suite: &'static Tls12CipherSuite,
        kx: Box<dyn ActiveKeyExchange>,
        ecdh_params: ServerEcdhParams,
        randoms: ConnectionRandoms,
        transcript: HandshakeHash,
    },
    ChangeCipherSpec {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    Finished {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    Alert {
        description: AlertDescription,
        error: Error,
    },
    Retry {
        plain_msg: PlainMessage,
        index: usize,
        needs_encryption: bool,
        next_state: Box<CommonState>,
    },
}

enum SendState {
    ClientHello {
        transcript_buffer: HandshakeHashBuffer,
        random: Random,
    },
    ClientKeyExchange {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    ChangeCipherSpec {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    Finished,
    Alert(Error),
}

enum CommonState {
    Unreachable,
    Process {
        message: Message,
        expect_state: ExpectState,
    },
    Expect(ExpectState),
    Write(WriteState),
    Send(SendState),
    SetupEncryption {
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: Vec<u8>,
        randoms: ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        transcript: HandshakeHash,
    },
    HandshakeDone,
    Poisoned(Error),
}

impl CommonState {
    fn take(&mut self) -> Self {
        core::mem::replace(self, Self::Unreachable)
    }
}

/// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon {
    config: Arc<ClientConfig>,
    name: ServerName,
    state: CommonState,
    record_layer: RecordLayer,
    offset: usize,
}

impl LlConnectionCommon {
    /// FIXME: docs
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Result<Self, Error> {
        Ok(Self {
            state: CommonState::Write(WriteState::ClientHello {
                random: Random::new(config.provider)?,
            }),
            config,
            name,
            record_layer: RecordLayer::new(),
            offset: 0,
        })
    }

    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i>, Error> {
        loop {
            match self.state.take() {
                CommonState::Unreachable => unreachable!(),
                CommonState::Poisoned(err) => {
                    return Err(err);
                }
                state @ CommonState::Write(_) => {
                    self.state = state;
                    return Ok(Status {
                        discard: core::mem::take(&mut self.offset),
                        state: State::MustEncryptTlsData(MustEncryptTlsData { conn: self }),
                    });
                }
                CommonState::Send(curr_state) => {
                    return Ok(Status {
                        discard: core::mem::take(&mut self.offset),
                        state: State::MustTransmitTlsData(MustTransmitTlsData {
                            conn: self,
                            curr_state,
                        }),
                    });
                }
                state @ CommonState::Expect(_) if incoming_tls.is_empty() => {
                    self.state = state;
                    return Ok(Status {
                        discard: core::mem::take(&mut self.offset),
                        state: State::NeedsMoreTlsData { num_bytes: None },
                    });
                }
                CommonState::Expect(mut expect_state) => {
                    let transcript = match &mut expect_state {
                        ExpectState::ServerHello { .. }
                        | ExpectState::ChangeCipherSpec
                        | ExpectState::Finished => None,
                        ExpectState::Certificate { transcript, .. }
                        | ExpectState::ServerKeyExchange { transcript, .. }
                        | ExpectState::ServerHelloDone { transcript, .. } => Some(transcript),
                    };

                    let message = match self.read_message(incoming_tls, transcript) {
                        Ok(message) => message,
                        Err(Error::InvalidMessage(InvalidMessage::MessageTooShort)) => {
                            self.state = CommonState::Expect(expect_state);

                            return Ok(Status {
                                discard: core::mem::take(&mut self.offset),
                                state: State::NeedsMoreTlsData { num_bytes: None },
                            });
                        }
                        Err(err) => return Err(err),
                    };

                    self.state = if let MessagePayload::Alert(alert) = message.payload {
                        if let AlertLevel::Unknown(_) = alert.level {
                            CommonState::Write(WriteState::Alert {
                                description: AlertDescription::IllegalParameter,
                                error: Error::AlertReceived(alert.description),
                            })
                        } else if alert.description == AlertDescription::CloseNotify {
                            CommonState::Expect(expect_state)
                        } else if alert.level == AlertLevel::Warning {
                            std::println!("TLS alert warning received: {:#?}", alert);
                            CommonState::Expect(expect_state)
                        } else {
                            return Err(Error::AlertReceived(alert.description));
                        }
                    } else {
                        CommonState::Process {
                            message,
                            expect_state,
                        }
                    };
                }
                CommonState::Process {
                    message,
                    expect_state,
                } => {
                    self.state = self.process_message(expect_state, message)?;
                }
                CommonState::SetupEncryption {
                    kx,
                    peer_pub_key,
                    randoms,
                    suite,
                    transcript,
                } => {
                    let secrets = ConnectionSecrets::from_key_exchange(
                        kx,
                        &peer_pub_key,
                        Some(transcript.get_current_hash()),
                        randoms,
                        suite,
                    )?;

                    let (dec, enc) = secrets.make_cipher_pair(Side::Client);

                    self.record_layer
                        .prepare_message_encrypter(enc);
                    self.record_layer
                        .prepare_message_decrypter(dec);
                    self.record_layer.start_encrypting();

                    self.state = CommonState::Send(SendState::ClientKeyExchange {
                        secrets,
                        transcript,
                    });
                }
                state @ CommonState::HandshakeDone => {
                    self.state = state;

                    let mut reader = Reader::init(&incoming_tls[self.offset..]);
                    match OpaqueMessage::read(&mut reader) {
                        Ok(msg) => match msg.typ {
                            ContentType::ApplicationData => {
                                return Ok(Status {
                                    discard: core::mem::take(&mut self.offset),
                                    state: State::AppDataAvailable(AppDataAvailable {
                                        incoming_tls: Some(incoming_tls),
                                        conn: self,
                                    }),
                                });
                            }
                            content_type => {
                                panic!("{:?}", content_type);
                            }
                        },
                        Err(_) => {
                            return Ok(Status {
                                discard: core::mem::take(&mut self.offset),
                                state: State::TrafficTransit(TrafficTransit { conn: self }),
                            });
                        }
                    }
                }
            }
        }
    }

    fn generate_message(
        &mut self,
        write_state: WriteState,
    ) -> (PlainMessage, bool, usize, CommonState) {
        let mut needs_encryption = false;
        let mut skip_index = 0;

        let (msg, next_state) = match write_state {
            WriteState::ClientHello { random } => {
                let support_tls12 = self
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
                        random,
                        session_id: SessionId::empty(),
                        cipher_suites: self
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
                                self.config
                                    .kx_groups
                                    .iter()
                                    .map(|skxg| skxg.name())
                                    .collect(),
                            ),
                            ClientExtension::SignatureAlgorithms(
                                self.config
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
                let next_state = CommonState::Send(SendState::ClientHello {
                    transcript_buffer,
                    random,
                });

                (msg.into(), next_state)
            }
            WriteState::ClientKeyExchange {
                suite,
                kx,
                ecdh_params,
                randoms,
                mut transcript,
            } => {
                let mut buf = Vec::new();
                let ecpoint = PayloadU8::new(Vec::from(kx.pub_key()));
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

                transcript.add_message(&msg);

                let next_state = CommonState::SetupEncryption {
                    kx,
                    peer_pub_key: ecdh_params.public.0,
                    randoms,
                    suite,
                    transcript,
                };

                (msg.into(), next_state)
            }
            WriteState::ChangeCipherSpec {
                secrets,
                mut transcript,
            } => {
                let msg = Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
                };
                log_msg(&msg, false);

                transcript.add_message(&msg);
                let next_state = CommonState::Send(SendState::ChangeCipherSpec {
                    secrets,
                    transcript,
                });

                (msg.into(), next_state)
            }
            WriteState::Finished {
                mut transcript,
                secrets,
            } => {
                let vh = transcript.get_current_hash();
                let verify_data = secrets.client_verify_data(&vh);
                let verify_data_payload = Payload::new(verify_data);

                let msg = Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::handshake(HandshakeMessagePayload {
                        typ: HandshakeType::Finished,
                        payload: HandshakePayload::Finished(verify_data_payload),
                    }),
                };
                log_msg(&msg, false);

                transcript.add_message(&msg);
                needs_encryption = true;

                (msg.into(), CommonState::Send(SendState::Finished))
            }
            WriteState::Alert { description, error } => (
                Message::build_alert(AlertLevel::Fatal, description).into(),
                CommonState::Send(SendState::Alert(error)),
            ),
            WriteState::Retry {
                plain_msg,
                index,
                needs_encryption: needs_encryption_aux,
                next_state,
            } => {
                skip_index = index;
                needs_encryption = needs_encryption_aux;

                (plain_msg, *next_state)
            }
        };

        (msg, needs_encryption, skip_index, next_state)
    }

    fn encrypt_tls_data(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        let message_fragmenter = MessageFragmenter::default();
        let (plain_msg, needs_encryption, skip_index, next_state) = match self.state.take() {
            CommonState::Write(write_state) => self.generate_message(write_state),
            _ => unreachable!(),
        };

        let mut written_bytes = 0;

        let mut iter = message_fragmenter
            .fragment_message(&plain_msg)
            .enumerate()
            .skip(skip_index);

        while let Some((index, m)) = iter.next() {
            let opaque_msg = if needs_encryption {
                self.record_layer.encrypt_outgoing(m)
            } else {
                m.to_unencrypted_opaque()
            };

            let bytes = opaque_msg.encode();

            if bytes.len() > outgoing_tls.len() {
                let required_size = bytes.len();

                drop(iter);

                self.state = CommonState::Write(WriteState::Retry {
                    plain_msg,
                    index,
                    needs_encryption,
                    next_state: Box::new(next_state),
                });

                return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                    required_size,
                }));
            }

            outgoing_tls[written_bytes..written_bytes + bytes.len()].copy_from_slice(&bytes);
            written_bytes += bytes.len();
        }

        self.state = next_state;

        Ok(written_bytes)
    }

    fn tls_data_done(&mut self, curr_state: SendState) {
        self.state = match curr_state {
            SendState::ClientHello {
                transcript_buffer,
                random,
            } => CommonState::Expect(ExpectState::ServerHello {
                transcript_buffer,
                random,
            }),
            SendState::ClientKeyExchange {
                secrets,
                transcript,
            } => CommonState::Write(WriteState::ChangeCipherSpec {
                secrets,
                transcript,
            }),
            SendState::ChangeCipherSpec {
                secrets,
                transcript,
            } => CommonState::Write(WriteState::Finished {
                secrets,
                transcript,
            }),
            SendState::Finished => CommonState::Expect(ExpectState::ChangeCipherSpec),
            SendState::Alert(error) => CommonState::Poisoned(error),
        };
    }

    fn encrypt_traffic_transit(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        let msg: PlainMessage = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ApplicationData(Payload(application_data.to_vec())),
        }
        .into();

        let opaque_msg = self
            .record_layer
            .encrypt_outgoing(msg.borrow());

        let bytes = opaque_msg.encode();
        outgoing_tls[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    fn read_message(
        &mut self,
        incoming_tls: &[u8],
        transcript_opt: Option<&mut HandshakeHash>,
    ) -> Result<Message, Error> {
        let mut reader = Reader::init(&incoming_tls[self.offset..]);
        let m = OpaqueMessage::read(&mut reader).map_err(|err| match err {
            MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                InvalidMessage::MessageTooShort
            }
            MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
            MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
            MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
            MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
        })?;
        self.offset += reader.used();

        let decrypted = self
            .record_layer
            .decrypt_incoming(m)?
            .expect("we don't support early data yet");

        let msg = decrypted.plaintext.try_into()?;
        if let Some(transcript) = transcript_opt {
            transcript.add_message(&msg);
        }

        log_msg(&msg, true);

        Ok(msg)
    }

    fn process_message(
        &mut self,
        expect_state: ExpectState,
        msg: Message,
    ) -> Result<CommonState, Error> {
        let state = match expect_state {
            ExpectState::ServerHello {
                transcript_buffer,
                random,
            } => {
                let payload = require_handshake_msg!(
                    msg,
                    HandshakeType::ServerHello,
                    HandshakePayload::ServerHello
                )?;
                if let Some(suite) = self
                    .config
                    .find_cipher_suite(payload.cipher_suite)
                {
                    let mut transcript = transcript_buffer.start_hash(suite.hash_provider());

                    transcript.add_message(&msg);

                    let suite = match suite {
                        SupportedCipherSuite::Tls12(suite) => suite,
                        SupportedCipherSuite::Tls13(_) => todo!(),
                    };

                    CommonState::Expect(ExpectState::Certificate {
                        suite,
                        randoms: ConnectionRandoms::new(random, payload.random),
                        transcript,
                    })
                } else {
                    CommonState::Write(WriteState::Alert {
                        description: AlertDescription::HandshakeFailure,
                        error: PeerMisbehaved::SelectedUnofferedCipherSuite.into(),
                    })
                }
            }
            ExpectState::Certificate {
                suite,
                randoms,
                transcript,
            } => {
                let payload = require_handshake_msg_move!(
                    msg,
                    HandshakeType::Certificate,
                    HandshakePayload::Certificate
                )?;

                if let Err(error) = self.config.verifier.verify_server_cert(
                    &payload[0],
                    &[],
                    &self.name,
                    &[],
                    UnixTime::now(),
                ) {
                    CommonState::Write(WriteState::Alert {
                        description: match &error {
                            Error::InvalidCertificate(e) => e.clone().into(),
                            Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
                            _ => AlertDescription::HandshakeFailure,
                        },
                        error,
                    })
                } else {
                    CommonState::Expect(ExpectState::ServerKeyExchange {
                        suite,
                        randoms,
                        transcript,
                    })
                }
            }
            ExpectState::ServerKeyExchange {
                suite,
                randoms,
                transcript,
            } => {
                let opaque_kx = require_handshake_msg_move!(
                    msg,
                    HandshakeType::ServerKeyExchange,
                    HandshakePayload::ServerKeyExchange
                )?;

                CommonState::Expect(ExpectState::ServerHelloDone {
                    suite,
                    randoms,
                    opaque_kx,
                    transcript,
                })
            }
            ExpectState::ServerHelloDone {
                suite,
                randoms,
                opaque_kx,
                transcript,
            } => {
                match msg.payload {
                    MessagePayload::Handshake {
                        parsed:
                            HandshakeMessagePayload {
                                typ: HandshakeType::CertificateRequest,
                                payload: HandshakePayload::CertificateRequest(_),
                            },
                        ..
                    } => CommonState::Expect(ExpectState::ServerHelloDone {
                        suite,
                        randoms,
                        opaque_kx,
                        transcript,
                    }),
                    MessagePayload::Handshake {
                        parsed:
                            HandshakeMessagePayload {
                                typ: HandshakeType::ServerHelloDone,
                                payload: HandshakePayload::ServerHelloDone,
                            },
                        ..
                    } => match opaque_kx.unwrap_given_kxa(suite.kx) {
                        Some(ecdhe) => {
                            let mut kx_params = Vec::new();
                            ecdhe.params.encode(&mut kx_params);
                            let server_kx = ServerKxDetails::new(kx_params, ecdhe.dss);

                            let mut rd = Reader::init(&server_kx.kx_params);
                            let ecdh_params = ServerEcdhParams::read(&mut rd)?;

                            if rd.any_left() {
                                CommonState::Write(WriteState::Alert {
                                    description: AlertDescription::DecodeError,
                                    error: InvalidMessage::InvalidDhParams.into(),
                                })
                            } else if let Some(skxg) = self
                                .config
                                .find_kx_group(ecdh_params.curve_params.named_group)
                            {
                                let kx = skxg
                                    .start()
                                    .map_err(|_| Error::FailedToGetRandomBytes)?;

                                CommonState::Write(WriteState::ClientKeyExchange {
                                    suite,
                                    kx,
                                    ecdh_params,
                                    randoms,
                                    transcript,
                                })
                            } else {
                                CommonState::Write(WriteState::Alert {
                                    description: AlertDescription::IllegalParameter,
                                    error: PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup.into(),
                                })
                            }
                        }
                        None => CommonState::Write(WriteState::Alert {
                            description: AlertDescription::DecodeError,
                            error: InvalidMessage::MissingKeyExchange.into(),
                        }),
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
            ExpectState::ChangeCipherSpec => match msg.payload {
                MessagePayload::ChangeCipherSpec(_) => {
                    self.record_layer.start_decrypting();
                    CommonState::Expect(ExpectState::Finished)
                }
                payload => {
                    return Err(inappropriate_message(
                        &payload,
                        &[ContentType::ChangeCipherSpec],
                    ));
                }
            },
            ExpectState::Finished => {
                let _ = require_handshake_msg!(
                    msg,
                    HandshakeType::Finished,
                    HandshakePayload::Finished
                )?;

                CommonState::HandshakeDone
            }
        };

        Ok(state)
    }
}

/// FIXME: docs
#[must_use]
pub struct Status<'c, 'i> {
    /// number of bytes that must be discarded from the *front* of `incoming_tls` *after* handling
    /// `state` and *before* the next `process_tls_records` call
    pub discard: usize,

    /// the current state of the handshake process
    pub state: State<'c, 'i>,
}

/// FIXME: docs
pub enum State<'c, 'i> {
    /// One, or more, application data record is available
    AppDataAvailable(AppDataAvailable<'c, 'i>),

    /// A Handshake record must be encrypted into the `outgoing_tls` buffer
    MustEncryptTlsData(MustEncryptTlsData<'c>),

    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData(MustTransmitTlsData<'c>),

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData {
        /// number of bytes required to complete a TLS record. `None` indicates that
        /// no information is available
        num_bytes: Option<NonZeroUsize>,
    },

    /// Handshake is complete.
    TrafficTransit(TrafficTransit<'c>),
    // .. other variants are omitted for now ..
}

/// A decrypted application data record
#[derive(Debug)]
pub struct AppDataRecord<'i> {
    /// number of the bytes associated to this record that must discarded from the front of
    /// the `incoming_tls` buffer before the next `process_tls_record` call
    pub discard: NonZeroUsize,

    /// FIXME: docs
    pub payload: &'i [u8],
}

/// FIXME: docs
pub struct AppDataAvailable<'c, 'i> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
    /// FIXME: docs
    incoming_tls: Option<&'i mut [u8]>,
}

impl<'c, 'i> AppDataAvailable<'c, 'i> {
    /// FIXME: docs
    pub fn next_record<'a>(&'a mut self) -> Option<Result<AppDataRecord<'a>, Error>> {
        let offset = self.conn.offset;
        let incoming_tls = self.incoming_tls.as_deref_mut()?;

        match self
            .conn
            .read_message(incoming_tls, None)
        {
            Ok(msg) => match msg.payload {
                MessagePayload::ApplicationData(Payload(payload)) => {
                    let slice = &mut incoming_tls[offset..offset + payload.len()];
                    slice.copy_from_slice(&payload);

                    Some(Ok(AppDataRecord {
                        discard: self.conn.offset.try_into().unwrap(),
                        payload: slice,
                    }))
                }
                _ => {
                    self.conn.offset = offset;
                    None
                }
            },
            Err(err) => Some(Err(err)),
        }
    }
}

impl<'c, 'i> AppDataAvailable<'c, 'i> {
    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        let mut reader = Reader::init(&self.incoming_tls.as_deref()?[self.conn.offset..]);

        match OpaqueMessage::read(&mut reader) {
            Ok(OpaqueMessage {
                typ: ContentType::ApplicationData,
                ..
            }) => Some(reader.used().try_into().unwrap()),
            _ => None,
        }
    }
}

/// Provided buffer was too small
#[derive(Debug)]
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}

/// FIXME: docs
pub struct MustEncryptTlsData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

/// An error occurred while encrypting a handshake record
#[derive(Debug)]
pub enum EncryptError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// The handshake record has already been encrypted; do not call `encrypt` again
    AlreadyEncrypted,
}

impl core::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncryptError::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encrypt due to insufficient size, {} bytes are required",
                required_size
            ),
            EncryptError::AlreadyEncrypted => {
                "cannot encrypt, data has already been encrypted".fmt(f)
            }
        }
    }
}

impl std::error::Error for EncryptError {}

impl<'c> MustEncryptTlsData<'c> {
    /// Encrypts a handshake record into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        self.conn.encrypt_tls_data(outgoing_tls)
    }
}

/// FIXME: docs
pub struct MustTransmitTlsData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
    /// FIXME: docs
    curr_state: SendState,
}

impl<'c> MustTransmitTlsData<'c> {
    /// FIXME: docs
    pub fn done(self) {
        self.conn.tls_data_done(self.curr_state)
    }
}

/// FIXME: docs
pub struct TrafficTransit<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

impl<'c> TrafficTransit<'c> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.conn
            .encrypt_traffic_transit(application_data, outgoing_tls)
    }
}
