//! FIXME: docs

use core::num::NonZeroUsize;

use alloc::boxed::Box;

use alloc::vec::Vec;
use std::sync::Arc;

use crate::check::inappropriate_message;
use crate::client::low_level::{
    ExpectCertificate, ExpectServerHello, ExpectServerHelloDone, ExpectServerKeyExchange,
    SendClientHello, WriteClientHello, WriteClientKeyExchange,
};
use crate::conn::ConnectionRandoms;
use crate::crypto::cipher::{OpaqueMessage, PlainMessage};
use crate::crypto::ActiveKeyExchange;
use crate::hash_hs::HandshakeHash;
use crate::internal::record_layer::RecordLayer;
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Reader;
use crate::msgs::enums::AlertLevel;
use crate::msgs::message::MessageError;
use crate::tls12::ConnectionSecrets;
use crate::{
    msgs::{
        fragmenter::MessageFragmenter,
        handshake::{HandshakeMessagePayload, HandshakePayload},
        message::{Message, MessagePayload},
    },
    ClientConfig, Error, HandshakeType, ProtocolVersion,
};
use crate::{AlertDescription, ContentType, InvalidMessage, ServerName, Side, Tls12CipherSuite};

pub(crate) fn log_msg(msg: &Message, read: bool) {
    let verb = if read { "Read" } else { "Write" };
    match &msg.payload {
        MessagePayload::Handshake {
            parsed: HandshakeMessagePayload { typ, .. },
            ..
        } => std::println!("{} Handshake::{:?}", verb, typ),
        payload => std::println!("{} {:?}", verb, payload.content_type()),
    };
}

pub(crate) struct GeneratedMessage {
    plain_msg: PlainMessage,
    needs_encryption: bool,
    skip_index: usize,
    next_state: CommonState,
}

impl GeneratedMessage {
    pub(crate) fn new(plain_msg: impl Into<PlainMessage>, next_state: CommonState) -> Self {
        Self {
            plain_msg: plain_msg.into(),
            needs_encryption: false,
            skip_index: 0,
            next_state,
        }
    }

    pub(crate) fn require_encryption(mut self, needs_encryption: bool) -> Self {
        self.needs_encryption = needs_encryption;
        self
    }

    pub(crate) fn skip(mut self, index: usize) -> Self {
        self.skip_index = index;
        self
    }
}

pub(crate) enum ExpectState {
    ServerHello(ExpectServerHello),
    Certificate(ExpectCertificate),
    ServerKeyExchange(ExpectServerKeyExchange),
    ServerHelloDone(ExpectServerHelloDone),
    ChangeCipherSpec { transcript: HandshakeHash },
    Finished { transcript: HandshakeHash },
}

pub(crate) enum WriteState {
    ClientHello(WriteClientHello),
    ClientKeyExchange(WriteClientKeyExchange),
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

pub(crate) enum SendState {
    ClientHello(SendClientHello),
    ClientKeyExchange {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    ChangeCipherSpec {
        secrets: ConnectionSecrets,
        transcript: HandshakeHash,
    },
    Finished {
        transcript: HandshakeHash,
    },
    Alert(Error),
}

pub(crate) enum CommonState {
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
    ConnectionClosed,
}

impl CommonState {
    fn take(&mut self) -> Self {
        core::mem::replace(self, Self::Unreachable)
    }
}

/// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) name: ServerName,
    pub(crate) state: CommonState,
    pub(crate) record_layer: RecordLayer,
    pub(crate) offset: usize,
}

impl LlConnectionCommon {
    /// FIXME: docs
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Result<Self, Error> {
        Ok(Self {
            state: CommonState::Write(WriteState::ClientHello(WriteClientHello::new(
                config.as_ref(),
            )?)),
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
                CommonState::ConnectionClosed => {
                    return Ok(Status {
                        discard: core::mem::take(&mut self.offset),
                        state: State::ConnectionClosed,
                    });
                }
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
                        ExpectState::ChangeCipherSpec { .. } => None,
                        ExpectState::Finished { transcript } => Some(transcript),
                        ExpectState::ServerHello(state) => state.get_transcript_mut(),
                        ExpectState::Certificate(state) => state.get_transcript_mut(),

                        ExpectState::ServerKeyExchange(state) => state.get_transcript_mut(),
                        ExpectState::ServerHelloDone(state) => state.get_transcript_mut(),
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

                    if let MessagePayload::Alert(alert) = message.payload {
                        self.handle_alert(alert, CommonState::Expect(expect_state))?;
                    } else {
                        self.state = CommonState::Process {
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
                    let mut reader = Reader::init(&incoming_tls[self.offset..]);
                    match OpaqueMessage::read(&mut reader) {
                        Ok(msg) => match msg.typ {
                            ContentType::ApplicationData => {
                                self.state = state;

                                return Ok(Status {
                                    discard: core::mem::take(&mut self.offset),
                                    state: State::AppDataAvailable(AppDataAvailable {
                                        incoming_tls: Some(incoming_tls),
                                        conn: self,
                                    }),
                                });
                            }
                            ContentType::Alert => {
                                let Message {
                                    payload: MessagePayload::Alert(alert),
                                    ..
                                } = self.read_message(incoming_tls, None)?
                                else {
                                    unreachable!()
                                };

                                self.handle_alert(alert, CommonState::HandshakeDone)?;
                            }

                            content_type => {
                                panic!("{:?}", content_type);
                            }
                        },
                        Err(_) => {
                            self.state = state;

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

    fn generate_message(&mut self, write_state: WriteState) -> GeneratedMessage {
        match write_state {
            WriteState::ClientHello(state) => state.generate_message(self),
            WriteState::ClientKeyExchange(state) => state.generate_message(self),
            WriteState::ChangeCipherSpec {
                secrets,
                transcript,
            } => {
                let msg = Message {
                    version: ProtocolVersion::TLSv1_2,
                    payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
                };
                log_msg(&msg, false);

                let next_state = CommonState::Send(SendState::ChangeCipherSpec {
                    secrets,
                    transcript,
                });

                GeneratedMessage::new(msg, next_state)
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

                GeneratedMessage::new(msg, CommonState::Send(SendState::Finished { transcript }))
                    .require_encryption(true)
            }
            WriteState::Alert { description, error } => GeneratedMessage::new(
                Message::build_alert(AlertLevel::Fatal, description),
                CommonState::Send(SendState::Alert(error)),
            ),
            WriteState::Retry {
                plain_msg,
                index,
                needs_encryption,
                next_state,
            } => GeneratedMessage::new(plain_msg, *next_state)
                .skip(index)
                .require_encryption(needs_encryption),
        }
    }

    fn encrypt_tls_data(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        let message_fragmenter = MessageFragmenter::default();
        let GeneratedMessage {
            plain_msg,
            needs_encryption,
            skip_index,
            next_state,
        } = match self.state.take() {
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
            SendState::ClientHello(state) => state.tls_data_done(),
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
            SendState::Finished { transcript } => {
                CommonState::Expect(ExpectState::ChangeCipherSpec { transcript })
            }
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
            ExpectState::ServerHello(state) => state.process_message(self, msg)?,

            ExpectState::Certificate(state) => state.process_message(self, msg)?,
            ExpectState::ServerKeyExchange(state) => state.process_message(self, msg)?,
            ExpectState::ServerHelloDone(state) => state.process_message(self, msg)?,
            ExpectState::ChangeCipherSpec { transcript } => match msg.payload {
                MessagePayload::ChangeCipherSpec(_) => {
                    self.record_layer.start_decrypting();
                    CommonState::Expect(ExpectState::Finished { transcript })
                }
                payload => {
                    return Err(inappropriate_message(
                        &payload,
                        &[ContentType::ChangeCipherSpec],
                    ));
                }
            },
            ExpectState::Finished { .. } => {
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

    fn handle_alert(
        &mut self,
        alert: crate::msgs::alert::AlertMessagePayload,
        curr_state: CommonState,
    ) -> Result<(), Error> {
        self.state = if let AlertLevel::Unknown(_) = alert.level {
            CommonState::Write(WriteState::Alert {
                description: AlertDescription::IllegalParameter,
                error: Error::AlertReceived(alert.description),
            })
        } else if alert.description == AlertDescription::CloseNotify {
            CommonState::ConnectionClosed
        } else if alert.level == AlertLevel::Warning {
            std::println!("TLS alert warning received: {:#?}", alert);
            curr_state
        } else {
            return Err(Error::AlertReceived(alert.description));
        };

        Ok(())
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

    /// Connection is being closed.
    ConnectionClosed,
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

        let msg = Ok(()).and_then(|()| {
            let mut reader = Reader::init(&incoming_tls[self.conn.offset..]);
            let m = OpaqueMessage::read(&mut reader).map_err(|err| match err {
                MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                    InvalidMessage::MessageTooShort
                }
                MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
            })?;
            if let ContentType::ApplicationData = m.typ {
                self.conn.offset += reader.used();

                let decrypted = self
                    .conn
                    .record_layer
                    .decrypt_incoming(m)?
                    .expect("we don't support early data yet");

                let msg = decrypted.plaintext.try_into()?;
                log_msg(&msg, true);

                let Message {
                    payload: MessagePayload::ApplicationData(Payload(payload)),
                    ..
                } = msg
                else {
                    unreachable!()
                };

                let slice = &mut incoming_tls[offset..offset + payload.len()];
                slice.copy_from_slice(&payload);

                Ok(Some(AppDataRecord {
                    discard: self.conn.offset.try_into().unwrap(),
                    payload: slice,
                }))
            } else {
                Ok(None)
            }
        });

        msg.transpose()
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
