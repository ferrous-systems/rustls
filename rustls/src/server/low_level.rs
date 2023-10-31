//! FIXME: docs

use core::ops::{Deref, DerefMut};

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::{
    low_level::{CommonState, ExpectState, LlConnectionCommon},
    msgs::message::Message,
    Error, ServerConfig,
};

/// FIXME: docs
pub struct LlServerConnection {
    conn: LlConnectionCommon<Arc<ServerConfig>>,
}

impl Deref for LlServerConnection {
    type Target = LlConnectionCommon<Arc<ServerConfig>>;

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
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            conn: LlConnectionCommon::new(
                config,
                CommonState::Expect(Box::new(ExpectClientHello::new())),
            )?,
        })
    }
}

struct ExpectClientHello {}

impl ExpectClientHello {
    fn new() -> Self {
        Self {}
    }
}

impl ExpectState for ExpectClientHello {
    type Data = Arc<ServerConfig>;

    fn process_message(
        self: Box<Self>,
        _common: &mut LlConnectionCommon<Self::Data>,
        _msg: Message,
    ) -> Result<CommonState<Self::Data>, Error> {
        todo!()
    }
}
