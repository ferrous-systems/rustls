//! FIXME: docs

use core::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::{ClientConfig, Error, ServerName};

use crate::low_level::LlConnectionCommon;

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
