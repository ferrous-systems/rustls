//! FIXME: docs

use core::num::NonZeroUsize;

use alloc::vec;
use alloc::vec::Vec;
use std::sync::Arc;

use crate::msgs::enums::ECPointFormat;
use crate::msgs::handshake::{CertificateStatusRequest, ClientExtension};
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

/// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
#[derive(Debug)]
pub struct LlConnectionCommon {
    config: Arc<ClientConfig>,
    must_send_hello: bool,
    did_send_hello: bool,
}

impl LlConnectionCommon {
    /// FIXME: docs
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            config,
            must_send_hello: true,
            did_send_hello: false,
        }
    }

    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        _incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i>, Error> {
        if self.must_send_hello {
            Ok(Status {
                discard: 0,
                state: State::MustEncryptTlsData(MustEncryptTlsData { conn: self }),
            })
        } else if self.did_send_hello {
            panic!("Did send client hello")
        } else {
            Ok(Status {
                discard: 0,
                state: State::MustTransmitTlsData(MustTransmitTlsData { conn: self }),
            })
        }
    }

    fn encrypt_app_data(
        &self,
        _application_data: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSizeError> {
        todo!()
    }

    fn app_data_done(&self) {
        todo!()
    }

    fn encrypt_tls_data(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        let message_fragmenter = MessageFragmenter::default();
        let support_tls12 = self
            .config
            .supports_version(ProtocolVersion::TLSv1_2);

        let mut supported_versions = Vec::new();
        if support_tls12 {
            supported_versions.push(ProtocolVersion::TLSv1_2);
        }
        let parsed = HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                client_version: ProtocolVersion::TLSv1_2,
                random: Random([0u8; 32]),
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
                    ClientExtension::ECPointFormats(ECPointFormat::SUPPORTED.to_vec()),
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
            payload: MessagePayload::handshake(parsed),
        };

        let mut written_bytes = 0;

        for m in message_fragmenter.fragment_message(&msg.into()) {
            let bytes = m.to_unencrypted_opaque().encode();

            if bytes.len() > outgoing_tls.len() {
                return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                    required_size: bytes.len(),
                }));
            }

            outgoing_tls[written_bytes..written_bytes + bytes.len()].copy_from_slice(&bytes);
            written_bytes += bytes.len();
        }

        self.must_send_hello = false;

        Ok(written_bytes)
    }

    fn tls_data_done(&mut self) {
        self.did_send_hello = true;
    }

    fn encrypt_traffic_transit(
        &self,
        _application_data: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        todo!()
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
#[derive(Debug)]
pub enum State<'c, 'i> {
    /// One, or more, application data record is available
    AppDataAvailable(AppDataAvailable<'c, 'i>),

    /// Application data may be encrypted at this stage of the handshake
    MayEncryptAppData(MayEncryptAppData<'c>),

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
#[derive(Debug)]
pub struct AppDataAvailable<'c, 'i> {
    /// FIXME: docs
    _conn: &'c mut LlConnectionCommon,
    /// FIXME: docs
    _incoming_tls: Option<&'i mut [u8]>,
}

impl<'c: 'i, 'i> Iterator for AppDataAvailable<'c, 'i> {
    type Item = Result<AppDataRecord<'i>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}

impl<'c, 'i> AppDataAvailable<'c, 'i> {
    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        todo!()
    }
}

/// FIXME: docs
#[derive(Debug)]
pub struct MayEncryptAppData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

/// Provided buffer was too small
#[derive(Debug)]
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}

impl<'c> MayEncryptAppData<'c> {
    /// encrypts `application_data` into `outgoing_tls`
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSizeError> {
        self.conn
            .encrypt_app_data(application_data, outgoing_tls)
    }

    /// No more encryption will be performed; continue with the handshake process
    pub fn done(self) {
        self.conn.app_data_done()
    }
}

/// FIXME: docs
#[derive(Debug)]
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
#[derive(Debug)]
pub struct MustTransmitTlsData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

impl<'c> MustTransmitTlsData<'c> {
    /// FIXME: docs
    pub fn done(self) {
        self.conn.tls_data_done()
    }
}

/// FIXME: docs
#[derive(Debug)]
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
