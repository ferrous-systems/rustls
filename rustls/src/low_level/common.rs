//! FIXME: docs

use core::num::NonZeroUsize;

use crate::Error;

/// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon {}

impl LlConnectionCommon {
    /// FIXME: docs
    pub fn new() -> Self {
        todo!()
    }

    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        _incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i>, Error> {
        todo!()
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

    fn encrypt_tls_data(&self, _outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        todo!()
    }

    fn tls_data_done(&self) {
        todo!()
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
pub struct MayEncryptAppData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

/// Provided buffer was too small
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
pub struct MustEncryptTlsData<'c> {
    /// FIXME: docs
    conn: &'c mut LlConnectionCommon,
}

/// An error occurred while encrypting a handshake record
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
