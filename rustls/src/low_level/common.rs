//! FIXME: docs

use core::num::NonZeroUsize;

use alloc::boxed::Box;

use crate::crypto::cipher::{OpaqueMessage, PlainMessage};
use crate::hash_hs::HandshakeHash;
use crate::internal::record_layer::RecordLayer;
use crate::msgs::alert::AlertMessagePayload;
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
    Error,
};
use crate::{AlertDescription, ContentType, InvalidMessage};

use super::{
    AppDataAvailable, AppDataRecord, EncodeError, InsufficientSizeError, MustEncodeTlsData,
    MustTransmitTlsData, State, Status, TrafficTransit,
};

/// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon {
    state: ConnectionState,
    pub(crate) record_layer: RecordLayer,
    message_fragmenter: MessageFragmenter,
    /// How much of `incoming_tls` has been read while borrowing it. This is used as the `discard`
    /// field of `Status` when returning from [`LlConnectionCommon::process_tls_records`].
    offset: usize,
}

impl LlConnectionCommon {
    /// FIXME: docs
    pub(crate) fn new(state: ConnectionState) -> Result<Self, Error> {
        Ok(Self {
            state,
            record_layer: RecordLayer::new(),
            message_fragmenter: MessageFragmenter::default(),
            offset: 0,
        })
    }

    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i>, Error> {
        loop {
            // Take the current state.
            match core::mem::replace(&mut self.state, ConnectionState::Taken) {
                // We should never take the state without setting it back.
                ConnectionState::Taken => unreachable!(),
                // The connection is closed.
                state @ ConnectionState::ConnectionClosed => {
                    // Restore the current state as we cannot do anything else.
                    self.state = state;
                    // Return the connection closed status.
                    return self.gen_status(|_| State::ConnectionClosed);
                }
                // We just emitted a fatal alert.
                ConnectionState::FatalError(err) => {
                    // Restore the current state as we cannot do anything else.
                    self.state = ConnectionState::FatalError(err.clone());
                    // Return the error provided by the alert.
                    return Err(err.clone());
                }
                // We have to emit a message to continue the handshake.
                ConnectionState::Emit(state) => {
                    // FIXME: `state` is still `Taken` but it is not clear what should happen if
                    // the application layer calls [`Self::process_tls_records`] instead of
                    // handling `MustEncodeTlsData`.
                    let generated_message = state.generate_message(self)?;
                    // Return the `MustEncodeTlsData` status so the message is written to the
                    // `outgoing_tls` buffer once `MustEncodeTlsData::encode` is called. This
                    // method will restore the connection state based on the information provided
                    // by `generated_message`.
                    return self.gen_status(|conn| {
                        State::MustEncodeTlsData(MustEncodeTlsData {
                            conn,
                            generated_message,
                        })
                    });
                }
                // We just encoded a message into `outgoing_tls`.
                ConnectionState::AfterEncode(next_state) => {
                    // FIXME: `state` is still `Taken` but it is not clear what should happen if
                    // the application layer calls [`Self::process_tls_records`] instead of
                    // handling `MustTransmitTlsData`.

                    // Return the `MustEncodeTlsData` status so the message that was encoded into
                    // `outgoing_tls` is sent once `MustTransmitTlsData::done` is called. This
                    // method will set the state to `next_state`.
                    return self.gen_status(|conn| {
                        State::MustTransmitTlsData(MustTransmitTlsData {
                            conn,
                            next_state: *next_state,
                        })
                    });
                }
                // We are expecting a message.
                ConnectionState::Expect(mut state) => {
                    let transcript = state.get_transcript_mut();
                    // Read a message from `incoming_tls`.
                    let message = match self.read_message(incoming_tls, transcript) {
                        Ok(message) => message,
                        // If the message is too short, we need more bytes in `incoming_tls`.
                        Err(Error::InvalidMessage(InvalidMessage::MessageTooShort)) => {
                            // Restore the curren state as we should expect the message again once
                            // we get more data.
                            self.state = ConnectionState::Expect(state);
                            // Return the `NeedsMoreTlsData` state.
                            return self
                                .gen_status(|_| State::NeedsMoreTlsData { num_bytes: None });
                        }
                        Err(err) => return Err(err),
                    };
                    self.state = if let MessagePayload::Alert(alert) = message.payload {
                        // If the message is an alert, handle it and restore the current state as
                        // we should expect the message again if the alert is not bad enough..
                        handle_alert(alert, ConnectionState::Expect(state))
                    } else {
                        // Process the message otherwise.
                        state.process_message(self, message)?
                    };
                }
                // The handshake is done and we are exchanging application data.
                state @ ConnectionState::HandshakeDone => {
                    let unread_data = &incoming_tls[self.offset..];
                    // If there is no data to read, we can write.
                    if unread_data.is_empty() {
                        // We restore the current state as we caan keep exchanging
                        // application data.
                        self.state = state;
                        // Return the `TrafficTransit` stsatus so the application layer can send
                        // data.
                        return self
                            .gen_status(|conn| State::TrafficTransit(TrafficTransit { conn }));
                    }
                    // Read a message from `incoming_tls` and inspect its content type to decide
                    // what to do.
                    //
                    // We don't call `LlConnectionCommon::read_message` here because we don't want
                    // to completely read and decrypt the message. Just inspect its header.
                    let mut reader = Reader::init(&unread_data);
                    let msg = OpaqueMessage::read(&mut reader).map_err(|err| match err {
                        MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                            InvalidMessage::MessageTooShort
                        }
                        MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                        MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                        MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                        MessageError::UnknownProtocolVersion => {
                            InvalidMessage::UnknownProtocolVersion
                        }
                    })?;

                    match msg.typ {
                        // We received application data.
                        ContentType::ApplicationData => {
                            // We restore the current state as we caan keep exchanging
                            // application data.
                            self.state = state;
                            // Return the `AppDataAvailable` status so the application layer
                            // can process the available application data.
                            return self.gen_status(|conn| {
                                State::AppDataAvailable(AppDataAvailable {
                                    incoming_tls: Some(incoming_tls),
                                    conn,
                                })
                            });
                        }
                        // We received an alert.
                        ContentType::Alert => {
                            // Read the complete alert message.
                            let Message {
                                payload: MessagePayload::Alert(alert),
                                ..
                            } = self.read_message(incoming_tls, None)?
                            else {
                                unreachable!()
                            };
                            // Handle it and keep exchanging application data afterwards unless
                            // the alert is critical.
                            self.state = handle_alert(alert, ConnectionState::HandshakeDone);
                        }
                        // FIXME: handle other types of messages.
                        content_type => {
                            panic!("{:?}", content_type);
                        }
                    }
                }
            }
        }
    }

    /// Encode `plain_msg` into `outgoing_tls`. Returns the number of written bytes when
    /// successful.
    pub(super) fn encode_plain_msg(
        &mut self,
        plain_msg: &PlainMessage,
        needs_encryption: bool,
        outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSizeError> {
        // Compute the size required to encode `plain_msg`
        let required_size = self.fragments_len(plain_msg, needs_encryption);
        // Return an error if `plain_msg` won't fit in `outgoing_tls`.
        if required_size > outgoing_tls.len() {
            return Err(InsufficientSizeError { required_size });
        }

        let mut written_bytes = 0;
        // Fragment the message and write each fragment into `outgoing_tls`.
        for m in self
            .message_fragmenter
            .fragment_message(&plain_msg)
        {
            // Encrypt the message if required
            let opaque_msg = if needs_encryption {
                self.record_layer.encrypt_outgoing(m)
            } else {
                m.to_unencrypted_opaque()
            };
            // Encode the message into bytes.
            let bytes = opaque_msg.encode();
            // Write the bytes into `outgoing_tls. This won't panic because we know that the whole
            // message already fits.`
            outgoing_tls[written_bytes..written_bytes + bytes.len()].copy_from_slice(&bytes);
            written_bytes += bytes.len();
        }

        Ok(written_bytes)
    }

    /// Read a message from `incoming_tls` and add it to `transcript` if it is `Some`.
    fn read_message(
        &mut self,
        incoming_tls: &[u8],
        transcript_opt: Option<&mut HandshakeHash>,
    ) -> Result<Message, Error> {
        // Initialize a new reader with the unread section of `incoming_tls`.
        let mut reader = Reader::init(&incoming_tls[self.offset..]);
        // Read an opaque message. I'm not sure why `InvalidMessage` doesn't implement
        // `From<MessageError>`.
        let m = OpaqueMessage::read(&mut reader).map_err(|err| match err {
            MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                InvalidMessage::MessageTooShort
            }
            MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
            MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
            MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
            MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
        })?;
        // Update `offset` as we were able to read a message successfully.
        self.offset += reader.used();
        // Decrypt the opaque message. This method works for unencrypted data as well so we don't
        // have to worry about it.
        let decrypted = self
            .record_layer
            .decrypt_incoming(m)?
            // The result of `decrypt_incoming` can only be `None` when dealing with early data.
            .expect("we don't support early data yet");

        let msg = decrypted.plaintext.try_into()?;
        // Add the message to the transcript.
        if let Some(transcript) = transcript_opt {
            transcript.add_message(&msg);
        }
        // Log the message.
        log_msg(&msg, true);

        Ok(msg)
    }

    pub(super) fn encode_tls_data(
        &mut self,
        outgoing_tls: &mut [u8],
        generated_message: &mut GeneratedMessage,
    ) -> Result<usize, EncodeError> {
        let GeneratedMessage {
            plain_msg,
            needs_encryption,
            after_encode,
        } = generated_message;

        let Some(taken_after_encode) = after_encode.take() else {
            return Err(EncodeError::AlreadyEncoded);
        };

        let encode_result = self.encode_plain_msg(plain_msg, *needs_encryption, outgoing_tls);

        match encode_result {
            Ok(written_bytes) => {
                self.state = ConnectionState::AfterEncode(Box::new(taken_after_encode));
                Ok(written_bytes)
            }
            Err(err) => {
                // Restore the state on failure.
                *after_encode = Some(taken_after_encode);

                Err(EncodeError::InsufficientSize(err))
            }
        }
    }

    pub(super) fn transmit_tls_data_done(&mut self, next_state: ConnectionState) {
        self.state = next_state;
    }

    pub(super) fn next_app_data_record<'i>(
        &mut self,
        incoming_tls: &'i mut [u8],
    ) -> Option<Result<AppDataRecord<'i>, Error>> {
        let offset = self.offset;

        let msg = Ok(()).and_then(|()| {
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
            if let ContentType::ApplicationData = m.typ {
                self.offset += reader.used();

                let decrypted = self
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
                    discard: self.offset.try_into().unwrap(),
                    payload: slice,
                }))
            } else {
                Ok(None)
            }
        });

        msg.transpose()
    }

    pub(super) fn peek_app_data_record_len<'i>(
        &self,
        incoming_tls: &'i [u8],
    ) -> Option<NonZeroUsize> {
        let mut reader = Reader::init(&incoming_tls[self.offset..]);

        match OpaqueMessage::read(&mut reader) {
            Ok(OpaqueMessage {
                typ: ContentType::ApplicationData,
                ..
            }) => Some(reader.used().try_into().unwrap()),
            _ => None,
        }
    }

    /// Generate a new status to be returned by [`Self::process_tls_records`].
    ///
    /// This method sets the `discard` field of the status to `offset`.
    fn gen_status<'c, 'i>(
        &'c mut self,
        f: impl FnOnce(&'c mut Self) -> State<'c, 'i>,
    ) -> Result<Status<'c, 'i>, Error> {
        Ok(Status {
            discard: core::mem::take(&mut self.offset),
            state: f(self),
        })
    }

    /// Return the total number of bytes required to write all the fragments of `msg` if it were to be
    /// fragmented and possibly encrypted.
    fn fragments_len(&self, msg: &PlainMessage, needs_encryption: bool) -> usize {
        // This is the payload length of the fragments that would use the maximum fragment size
        // provided by the fragmenter, called complete fragments from now on.
        let complete_fragment_len = self
            .message_fragmenter
            .get_max_fragment_size();
        // This is the length of the message payload.
        let payload_len = msg.payload.0.len();

        // When fragmenting a message payload, we would have a certain number of complete fragments
        // and a trailing fragment.

        // This is the number of complete fragments
        let num_complete_fragments = payload_len / complete_fragment_len;
        // This is the payload length of the trailing fragmente
        let trailing_fragment_len = payload_len % complete_fragment_len;

        if needs_encryption {
            // This is the length of the complete fragments after being encrypted.
            let complete_encrypted_fragment_len = self
                .record_layer
                .encrypted_len(complete_fragment_len);
            // This is the length of the trailing fragment after being encrypted.
            let trailing_encrypted_fragment_len = self
                .record_layer
                .encrypted_len(trailing_fragment_len);

            num_complete_fragments * complete_encrypted_fragment_len
                + trailing_encrypted_fragment_len
        } else {
            num_complete_fragments * OpaqueMessage::encoded_len(complete_fragment_len)
                + OpaqueMessage::encoded_len(trailing_fragment_len)
        }
    }
}

/// Represents the state of `LlConnectionCommon`.
pub(crate) enum ConnectionState {
    /// A poisoned state that is only produced inside [`LlConnectionCommon::process_tls_records`]
    /// as a placeholder to compute the new state without having borrowing issues.
    Taken,
    /// The connection is expecting a specific kind of [`Message`].
    Expect(Box<dyn ExpectState>),
    /// The connection needs to emit an already generated [`Message`].
    Emit(Box<dyn EmitState>),
    /// The state that the connection will have after [`MustEncodeTlsData::done`] is called.
    AfterEncode(Box<Self>),
    /// The handshake has been successful.
    HandshakeDone,
    /// A fatal error happened and the connection cannot continue. Calling
    /// [`LlConnectionCommon::process_tls_records`] will return the error contained in this state.
    FatalError(Error),
    /// The connection is closed
    ConnectionClosed,
}

impl ConnectionState {
    pub(crate) fn expect(state: impl ExpectState) -> Self {
        Self::Expect(Box::new(state))
    }

    pub(crate) fn emit(state: impl EmitState) -> Self {
        Self::Emit(Box::new(state))
    }

    pub(crate) fn emit_alert(description: AlertDescription, err: impl Into<Error>) -> Self {
        Self::emit(EmitAlert {
            description,
            error: err.into(),
        })
    }
}

/// A connection state that is expecting for a specific kind of [`Message`]
pub(crate) trait ExpectState: 'static {
    /// Process an incomming message and return the next connection state if the message has the
    /// right kind.
    fn process_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
        msg: Message,
    ) -> Result<ConnectionState, Error>;

    /// Get the transcript contained on this state. This is used to call
    /// [`HandshakeHash::add_message`] before calling [`ExpectState::process_message`] so we do not
    /// forget to add it to the transcript by accident.
    fn get_transcript_mut(&mut self) -> Option<&mut HandshakeHash> {
        None
    }
}

/// A connection state that will generate a [`Message`] that will be emitted during
/// [`MustEncodeTlsData::encode`].
pub(crate) trait EmitState: 'static {
    /// Generate the message to be emitted. See [`GeneratedMessage`] for more information.
    fn generate_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
    ) -> Result<GeneratedMessage, Error>;
}

struct EmitAlert {
    description: AlertDescription,
    error: Error,
}

impl EmitState for EmitAlert {
    fn generate_message(
        self: Box<Self>,
        _conn: &mut LlConnectionCommon,
    ) -> Result<GeneratedMessage, Error> {
        Ok(GeneratedMessage::new(
            Message::build_alert(AlertLevel::Fatal, self.description),
            ConnectionState::FatalError(self.error),
        ))
    }
}

pub(crate) struct GeneratedMessage {
    plain_msg: PlainMessage,
    needs_encryption: bool,
    after_encode: Option<ConnectionState>,
}

impl GeneratedMessage {
    pub(crate) fn new(msg: Message, after_encode: ConnectionState) -> Self {
        log_msg(&msg, false);

        Self {
            plain_msg: msg.into(),
            needs_encryption: false,
            after_encode: Some(after_encode),
        }
    }

    pub(crate) fn require_encryption(mut self, needs_encryption: bool) -> Self {
        self.needs_encryption = needs_encryption;
        self
    }
}

/// Handle an incoming alert and compute the next connection state.
///
///
/// This function returns `next_state` if the alert received doesn't require any change of state to
/// be handled.
fn handle_alert(alert: AlertMessagePayload, next_state: ConnectionState) -> ConnectionState {
    // This code is based on `CommonState::process_alert`.
    if let AlertLevel::Unknown(_) = alert.level {
        // Reject unknown alert levels.
        ConnectionState::emit_alert(
            AlertDescription::IllegalParameter,
            Error::AlertReceived(alert.description),
        )
    } else if alert.description == AlertDescription::CloseNotify {
        // Set the connection state to closed if we receive a close notify alert.
        ConnectionState::ConnectionClosed
    } else if alert.level == AlertLevel::Warning {
        // Set the connection state to `next_state` if the alert is a warning.
        std::println!("TLS alert warning received: {:#?}", alert);
        next_state
    } else {
        // Otherwise, the alert is fatal and we shouldn't continue the connection.
        ConnectionState::FatalError(Error::AlertReceived(alert.description))
    }
}

fn log_msg(msg: &Message, read: bool) {
    let verb = if read { "Read" } else { "Emit" };
    match &msg.payload {
        MessagePayload::Handshake {
            parsed: HandshakeMessagePayload { typ, .. },
            ..
        } => std::println!("{} Handshake::{:?}", verb, typ),
        payload => std::println!("{} {:?}", verb, payload.content_type()),
    };
}
