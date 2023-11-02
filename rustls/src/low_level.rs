//! FIXME: docs

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
    let verb = if read { "Read" } else { "Emit" };
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
    pub(crate) fn new(msg: Message, next_state: CommonState) -> Self {
        log_msg(&msg, false);

        Self {
            plain_msg: msg.into(),
            needs_encryption: false,
            skip_index: 0,
            next_state,
        }
    }

    pub(crate) fn require_encryption(mut self, needs_encryption: bool) -> Self {
        self.needs_encryption = needs_encryption;
        self
    }
}

pub(crate) trait ExpectState: Send + 'static {
    fn process_message(self: Box<Self>, msg: Message) -> Result<CommonState, Error>;

    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        None
    }
}

pub(crate) trait EmitState: Send + 'static {
    fn generate_message(self: Box<Self>) -> GeneratedMessage;
}

pub(crate) struct EmitAlert {
    description: AlertDescription,
    error: Error,
}

impl EmitAlert {
    pub(crate) fn new(description: AlertDescription, error: impl Into<Error>) -> Self {
        Self {
            description,
            error: error.into(),
        }
    }
}

impl EmitState for EmitAlert {
    fn generate_message(self: Box<Self>) -> GeneratedMessage {
        GeneratedMessage::new(
            Message::build_alert(AlertLevel::Fatal, self.description),
            CommonState::AfterEmit(Box::new(CommonState::Poisoned(self.error))),
        )
    }
}

pub(crate) trait IntermediateState: 'static + Send {
    fn next_state(self: Box<Self>, common: &mut LlConnectionCommon) -> Result<CommonState, Error>;
}

pub(crate) enum CommonState {
    Unreachable,
    Process {
        message: Message,
        curr_state: Box<dyn ExpectState>,
    },
    Expect(Box<dyn ExpectState>),
    Emit(Box<dyn EmitState>),
    AfterEmit(Box<Self>),
    Intermediate(Box<dyn IntermediateState>),
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
    pub(crate) state: CommonState,
    pub(crate) record_layer: RecordLayer,
    pub(crate) offset: usize,
}

impl LlConnectionCommon {
    /// FIXME: docs
    pub(crate) fn new(state: CommonState) -> Result<Self, Error> {
        Ok(Self {
            state,
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
                    return self.gen_status(|_| State::ConnectionClosed)
                }
                CommonState::Poisoned(err) => {
                    return Err(err);
                }
                CommonState::Emit(state) => {
                    let generated_message = state.generate_message();

                    return self.gen_status(|conn| {
                        State::MustEncryptTlsData(MustEncryptTlsData {
                            conn,
                            generated_message,
                        })
                    });
                }
                CommonState::AfterEmit(next_state) => {
                    return self.gen_status(|conn| {
                        State::MustTransmitTlsData(MustTransmitTlsData {
                            conn,
                            next_state: *next_state,
                        })
                    });
                }
                CommonState::Expect(mut curr_state) => {
                    let transcript = curr_state.get_transcript_mut();
                    let message = match self.read_message(incoming_tls, transcript) {
                        Ok(message) => message,
                        Err(Error::InvalidMessage(InvalidMessage::MessageTooShort)) => {
                            self.state = CommonState::Expect(curr_state);

                            return self
                                .gen_status(|_| State::NeedsMoreTlsData { num_bytes: None });
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
                    self.state = curr_state.process_message(message)?;
                }
                CommonState::Intermediate(state) => {
                    self.state = state.next_state(self)?;
                }
                state @ CommonState::HandshakeDone => {
                    let mut reader = Reader::init(&incoming_tls[self.offset..]);
                    match OpaqueMessage::read(&mut reader) {
                        Ok(msg) => match msg.typ {
                            ContentType::ApplicationData => {
                                self.state = state;

                                return self.gen_status(|conn| {
                                    State::AppDataAvailable(AppDataAvailable {
                                        incoming_tls: Some(incoming_tls),
                                        conn,
                                    })
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

                            return self
                                .gen_status(|conn| State::TrafficTransit(TrafficTransit { conn }));
                        }
                    }
                }
            }
        }
    }

    fn gen_status<'c, 'i>(
        &'c mut self,
        f: impl FnOnce(&'c mut Self) -> State<'c, 'i>,
    ) -> Result<Status<'c, 'i>, Error> {
        Ok(Status {
            discard: core::mem::take(&mut self.offset),
            state: f(self),
        })
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
        curr_state: CommonState,
    ) -> Result<(), Error> {
        self.state = if let AlertLevel::Unknown(_) = alert.level {
            CommonState::Emit(Box::new(EmitAlert::new(
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
    generated_message: GeneratedMessage,
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
        let message_fragmenter = MessageFragmenter::default();
        let GeneratedMessage {
            ref plain_msg,
            needs_encryption,
            skip_index,
            ref mut next_state,
        } = self.generated_message;

        let mut written_bytes = 0;

        let mut iter = message_fragmenter
            .fragment_message(plain_msg)
            .enumerate()
            .skip(skip_index);

        while let Some((index, m)) = iter.next() {
            let opaque_msg = if needs_encryption {
                self.conn
                    .record_layer
                    .encrypt_outgoing(m)
            } else {
                m.to_unencrypted_opaque()
            };

            let bytes = opaque_msg.encode();

            if bytes.len() > outgoing_tls.len() {
                let required_size = bytes.len();

                self.generated_message.skip_index = index;

                return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                    required_size,
                }));
            }

            outgoing_tls[written_bytes..written_bytes + bytes.len()].copy_from_slice(&bytes);
            written_bytes += bytes.len();
        }

        self.conn.state = next_state.take();

        Ok(written_bytes)
    }
}

/// FIXME: docs
pub struct MustTransmitTlsData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
    /// FIXME: docs
    next_state: CommonState,
}

impl<'c> MustTransmitTlsData<'c> {
    /// FIXME: docs
    pub fn done(self) {
        self.conn.state = self.next_state;
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
