//! FIXME: docs

use core::ops::{Deref, DerefMut};

use alloc::sync::Arc;

use crate::{low_level::LlConnectionCommon, Error, ServerConfig};

/// FIXME: docs
pub struct LlServerConnection {
    conn: LlConnectionCommon,
}

impl Deref for LlServerConnection {
    type Target = LlConnectionCommon;

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
    pub fn new(_config: Arc<ServerConfig>) -> Result<Self, Error> {
        todo!()
    }
}
