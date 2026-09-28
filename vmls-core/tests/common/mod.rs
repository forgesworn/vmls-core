#![allow(dead_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use vmls_core::record::RecordAead;

/// AES-128-GCM for suite 0x0001, standing in for the MLS provider's AEAD.
pub struct TestAead;

impl RecordAead for TestAead {
    fn seal(&self, key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        Aes128Gcm::new(key.into())
            .encrypt(Nonce::from_slice(nonce), Payload { msg, aad })
            .ok()
    }

    fn open(&self, key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        Aes128Gcm::new(key.into())
            .decrypt(Nonce::from_slice(nonce), Payload { msg, aad })
            .ok()
    }
}

pub fn hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit()));
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
        .collect()
}

pub fn hex32(value: &str) -> [u8; 32] {
    hex(value).try_into().expect("32-byte hex")
}

/// The deterministic byte source every hostile suite uses.
pub struct Lcg(pub u32);

impl Lcg {
    pub fn byte(&mut self) -> u8 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (self.0 >> 24) as u8
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}
