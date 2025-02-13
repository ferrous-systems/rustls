use crate::crypto;
use crate::msgs::enums::HashAlgorithm;
use ring;

use alloc::boxed::Box;

pub(crate) static SHA256: Hash = Hash(&ring::digest::SHA256, HashAlgorithm::SHA256);
pub(crate) static SHA384: Hash = Hash(&ring::digest::SHA384, HashAlgorithm::SHA384);

pub(crate) struct Hash(&'static ring::digest::Algorithm, HashAlgorithm);

impl crypto::hash::Hash for Hash {
    fn start(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Context(ring::digest::Context::new(self.0)))
    }

    fn hash(&self, bytes: &[u8]) -> crypto::hash::Output {
        let mut ctx = ring::digest::Context::new(self.0);
        ctx.update(bytes);
        convert(ctx.finish())
    }

    fn output_len(&self) -> usize {
        self.0.output_len()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }
}

struct Context(ring::digest::Context);

impl crypto::hash::Context for Context {
    fn fork_finish(&self) -> crypto::hash::Output {
        convert(self.0.clone().finish())
    }

    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> crypto::hash::Output {
        convert(self.0.finish())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

fn convert(val: ring::digest::Digest) -> crypto::hash::Output {
    crypto::hash::Output::new(val.as_ref())
}
