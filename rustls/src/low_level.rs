//! FIXME: docs

use core::marker::PhantomData;
use core::num::NonZeroUsize;

use alloc::boxed::Box;

use crate::crypto::cipher::{OpaqueMessage, PlainMessage};
use crate::hash_hs::HandshakeHash;
use crate::internal::record_layer::RecordLayer;
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader;
use crate::msgs::enums::AlertLevel;
use crate::msgs::message::MessageError;
use crate::{
    msgs::{
        fragmenter::MessageFragmenter,
        handshake::HandshakeMessagePayload,
        message::{Message, MessagePayload},
    },
    Error, ProtocolVersion,
};
use crate::{AlertDescription, ContentType, InvalidMessage};

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

pub(crate) struct GeneratedMessage<Data> {
    plain_msg: PlainMessage,
    needs_encryption: bool,
    skip_index: usize,
    next_state: CommonState<Data>,
}

impl<Data> GeneratedMessage<Data> {
    pub(crate) fn new(plain_msg: impl Into<PlainMessage>, next_state: CommonState<Data>) -> Self {
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

pub(crate) trait ExpectState: Send + 'static {
    type Data;

    fn process_message(
        self: Box<Self>,
        common: &mut LlConnectionCommon<Self::Data>,
        msg: Message,
    ) -> Result<CommonState<Self::Data>, Error>;

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        None
    }
}

pub(crate) trait WriteState: Send + 'static {
    type Data;

    fn generate_message(
        self: Box<Self>,
        conn: &mut LlConnectionCommon<Self::Data>,
    ) -> GeneratedMessage<Self::Data>;
}

pub(crate) struct WriteAlert<Data> {
    description: AlertDescription,
    error: Error,
    _marker: PhantomData<Data>,
}

impl<Data> WriteAlert<Data> {
    pub(crate) fn new(description: AlertDescription, error: impl Into<Error>) -> Self {
        Self {
            description,
            error: error.into(),
            _marker: PhantomData,
        }
    }
}

impl<Data: 'static + Send> WriteState for WriteAlert<Data> {
    type Data = Data;

    fn generate_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon<Self::Data>,
    ) -> GeneratedMessage<Self::Data> {
        GeneratedMessage::new(
            Message::build_alert(AlertLevel::Fatal, self.description),
            CommonState::Send(Box::new(SendAlert {
                error: self.error,
                _marker: PhantomData,
            })),
        )
    }
}

pub(crate) struct RetryWrite<Data> {
    plain_msg: PlainMessage,
    index: usize,
    needs_encryption: bool,
    next_state: Box<CommonState<Data>>,
}

impl<Data: 'static + Send> WriteState for RetryWrite<Data> {
    type Data = Data;

    fn generate_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon<Self::Data>,
    ) -> GeneratedMessage<Self::Data> {
        GeneratedMessage::new(self.plain_msg, *self.next_state)
            .skip(self.index)
            .require_encryption(self.needs_encryption)
    }
}

pub(crate) trait SendState: Send + 'static {
    type Data;

    fn tls_data_done(self: Box<Self>) -> CommonState<Self::Data>;
}

pub(crate) struct SendAlert<Data> {
    error: Error,
    _marker: PhantomData<Data>,
}

impl<Data: Send + 'static> SendState for SendAlert<Data> {
    type Data = Data;

    fn tls_data_done(self: Box<Self>) -> CommonState<Self::Data> {
        CommonState::Poisoned(self.error)
    }
}

pub(crate) trait SetupEncryptionState: 'static + Send {
    type Data;

    fn setup_encryption(
        self: Box<Self>,
        common: &mut LlConnectionCommon<Self::Data>,
    ) -> Result<CommonState<Self::Data>, Error>;
}

pub(crate) enum CommonState<Data> {
    Unreachable,
    Process {
        message: Message,
        curr_state: Box<dyn ExpectState<Data = Data>>,
    },
    Expect(Box<dyn ExpectState<Data = Data>>),
    Write(Box<dyn WriteState<Data = Data>>),
    Send(Box<dyn SendState<Data = Data>>),
    SetupEncryption(Box<dyn SetupEncryptionState<Data = Data>>),
    HandshakeDone,
    Poisoned(Error),
    ConnectionClosed,
}

impl<Data> CommonState<Data> {
    fn take(&mut self) -> Self {
        core::mem::replace(self, Self::Unreachable)
    }
}

/// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon<Data> {
    pub(crate) config: Data,
    pub(crate) state: CommonState<Data>,
    pub(crate) record_layer: RecordLayer,
    pub(crate) offset: usize,
}

impl<Data: 'static + Send> LlConnectionCommon<Data> {
    /// FIXME: docs
    pub(crate) fn new(config: Data, state: CommonState<Data>) -> Result<Self, Error> {
        Ok(Self {
            state,
            config,
            record_layer: RecordLayer::new(),
            offset: 0,
        })
    }

    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i, Data>, Error> {
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
                CommonState::Expect(mut curr_state) => {
                    let transcript = curr_state.get_transcript_mut();
                    let message = match self.read_message(incoming_tls, transcript) {
                        Ok(message) => message,
                        Err(Error::InvalidMessage(InvalidMessage::MessageTooShort)) => {
                            self.state = CommonState::Expect(curr_state);

                            return Ok(Status {
                                discard: core::mem::take(&mut self.offset),
                                state: State::NeedsMoreTlsData { num_bytes: None },
                            });
                        }
                        Err(err) => return Err(err),
                    };

                    if let MessagePayload::Alert(alert) = message.payload {
                        self.handle_alert(alert, CommonState::Expect(curr_state))?;
                    } else {
                        self.state = CommonState::Process {
                            message,
                            curr_state,
                        }
                    };
                }
                CommonState::Process {
                    message,
                    curr_state,
                } => {
                    self.state = curr_state.process_message(self, message)?;
                }
                CommonState::SetupEncryption(state) => {
                    self.state = state.setup_encryption(self)?;
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

    fn encrypt_tls_data(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        let message_fragmenter = MessageFragmenter::default();
        let GeneratedMessage {
            plain_msg,
            needs_encryption,
            skip_index,
            next_state,
        } = match self.state.take() {
            CommonState::Write(state) => state.generate_message(self),
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

                self.state = CommonState::Write(Box::new(RetryWrite {
                    plain_msg,
                    index,
                    needs_encryption,
                    next_state: Box::new(next_state),
                }));

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

    fn handle_alert(
        &mut self,
        alert: crate::msgs::alert::AlertMessagePayload,
        curr_state: CommonState<Data>,
    ) -> Result<(), Error> {
        self.state = if let AlertLevel::Unknown(_) = alert.level {
            CommonState::Write(Box::new(WriteAlert::new(
                AlertDescription::IllegalParameter,
                Error::AlertReceived(alert.description),
            )))
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
pub struct Status<'c, 'i, Data> {
    /// number of bytes that must be discarded from the *front* of `incoming_tls` *after* handling
    /// `state` and *before* the next `process_tls_records` call
    pub discard: usize,

    /// the current state of the handshake process
    pub state: State<'c, 'i, Data>,
}

/// FIXME: docs
pub enum State<'c, 'i, Data> {
    /// One, or more, application data record is available
    AppDataAvailable(AppDataAvailable<'c, 'i, Data>),

    /// A Handshake record must be encrypted into the `outgoing_tls` buffer
    MustEncryptTlsData(MustEncryptTlsData<'c, Data>),

    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData(MustTransmitTlsData<'c, Data>),

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData {
        /// number of bytes required to complete a TLS record. `None` indicates that
        /// no information is available
        num_bytes: Option<NonZeroUsize>,
    },

    /// Handshake is complete.
    TrafficTransit(TrafficTransit<'c, Data>),

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
pub struct AppDataAvailable<'c, 'i, Data> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon<Data>,
    /// FIXME: docs
    incoming_tls: Option<&'i mut [u8]>,
}

impl<'c, 'i, Data> AppDataAvailable<'c, 'i, Data> {
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

impl<'c, 'i, Data> AppDataAvailable<'c, 'i, Data> {
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
pub struct MustEncryptTlsData<'c, Data> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon<Data>,
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

impl<'c, Data: 'static + Send> MustEncryptTlsData<'c, Data> {
    /// Encrypts a handshake record into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        self.conn.encrypt_tls_data(outgoing_tls)
    }
}

/// FIXME: docs
pub struct MustTransmitTlsData<'c, Data> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon<Data>,
    /// FIXME: docs
    curr_state: Box<dyn SendState<Data = Data>>,
}

impl<'c, Data: 'static + Send> MustTransmitTlsData<'c, Data> {
    /// FIXME: docs
    pub fn done(self) {
        self.conn.state = self.curr_state.tls_data_done();
    }
}

/// FIXME: docs
pub struct TrafficTransit<'c, Data> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon<Data>,
}

impl<'c, Data: 'static + Send> TrafficTransit<'c, Data> {
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
