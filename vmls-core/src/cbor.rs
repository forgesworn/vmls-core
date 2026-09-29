//! The deterministic RFC 8949 subset every VMLS/1 structure uses.
//!
//! Only unsigned integers, byte strings, text strings, arrays and maps with
//! definite, shortest-form lengths exist. Map keys are small unsigned
//! integers in one fixed ascending order per structure, so the reader checks
//! each key where it expects it instead of sorting. Every length is checked
//! against the remaining input before a slice is taken; nothing allocates in
//! proportion to a claimed length.

use crate::ErrorCode;

const MAJOR_UINT: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;

/// The largest integer JavaScript represents exactly. Timestamps above it are
/// refused so that every implementation compares the same numbers.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.at
    }

    pub(crate) fn finish(&self) -> Result<(), ErrorCode> {
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(ErrorCode::NonCanonical)
        }
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], ErrorCode> {
        let end = self.at.checked_add(len).ok_or(ErrorCode::Malformed)?;
        let bytes = self.input.get(self.at..end).ok_or(ErrorCode::Malformed)?;
        self.at = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, ErrorCode> {
        Ok(self.take(1)?[0])
    }

    /// Reads one head of the expected major type and returns its argument.
    fn head(&mut self, major: u8) -> Result<u64, ErrorCode> {
        let initial = self.byte()?;
        if initial >> 5 != major {
            return Err(ErrorCode::NonCanonical);
        }
        let info = initial & 0x1f;
        let (value, shortest_floor) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.byte()?), 24),
            25 => (u64::from(u16::from_be_bytes(self.array()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.array()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.array()?), 0x1_0000_0000),
            // 28-30 are reserved and 31 is indefinite length.
            _ => return Err(ErrorCode::NonCanonical),
        };
        if value < shortest_floor {
            return Err(ErrorCode::NonCanonical);
        }
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ErrorCode> {
        self.take(N)?.try_into().map_err(|_| ErrorCode::Malformed)
    }

    /// A length argument bounded by `max`. The comparison is on the raw
    /// 64-bit argument, before any conversion, so every target (including
    /// 32-bit wasm) reports the same code for the same input.
    fn bounded(&mut self, major: u8, max: usize) -> Result<usize, ErrorCode> {
        let len = self.head(major)?;
        if len > max as u64 {
            return Err(ErrorCode::TooLarge);
        }
        // `len <= max`, which is a `usize`.
        Ok(len as usize)
    }

    pub(crate) fn map(&mut self, entries: u64) -> Result<(), ErrorCode> {
        if self.head(MAJOR_MAP)? == entries {
            Ok(())
        } else {
            Err(ErrorCode::NonCanonical)
        }
    }

    pub(crate) fn key(&mut self, expected: u64) -> Result<(), ErrorCode> {
        if self.head(MAJOR_UINT)? == expected {
            Ok(())
        } else {
            Err(ErrorCode::NonCanonical)
        }
    }

    pub(crate) fn uint(&mut self) -> Result<u64, ErrorCode> {
        self.head(MAJOR_UINT)
    }

    /// A timestamp: an unsigned integer no larger than `MAX_SAFE_INTEGER`.
    pub(crate) fn timestamp(&mut self) -> Result<u64, ErrorCode> {
        let value = self.uint()?;
        if value > MAX_SAFE_INTEGER {
            Err(ErrorCode::Malformed)
        } else {
            Ok(value)
        }
    }

    /// A byte string of at most `max` bytes. The bound is checked before the
    /// remaining input, so an oversize claim is `TooLarge`, not `Malformed`.
    pub(crate) fn bytes(&mut self, max: usize) -> Result<&'a [u8], ErrorCode> {
        let len = self.bounded(MAJOR_BYTES, max)?;
        self.take(len)
    }

    /// A byte string of exactly `N` bytes; any other length is `Malformed`.
    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ErrorCode> {
        if self.head(MAJOR_BYTES)? != N as u64 {
            return Err(ErrorCode::Malformed);
        }
        self.array()
    }

    /// UTF-8 text of at most `max` bytes. A control character other than
    /// the five JSON writes as a short escape (backspace, tab, line feed,
    /// form feed, carriage return) is `Malformed`, so `JSON.stringify` and a
    /// literal NIP-01 serialisation of the text agree.
    pub(crate) fn text(&mut self, max: usize) -> Result<&'a str, ErrorCode> {
        let len = self.bounded(MAJOR_TEXT, max)?;
        let bytes = self.take(len)?;
        let text = core::str::from_utf8(bytes).map_err(|_| ErrorCode::Malformed)?;
        if bytes
            .iter()
            .any(|byte| *byte < 0x20 && !matches!(byte, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d))
        {
            return Err(ErrorCode::Malformed);
        }
        Ok(text)
    }

    pub(crate) fn array_len(&mut self, max: usize) -> Result<usize, ErrorCode> {
        self.bounded(MAJOR_ARRAY, max)
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    if value <= 23 {
        out.push(major | value as u8);
    } else if value <= u64::from(u8::MAX) {
        out.extend_from_slice(&[major | 24, value as u8]);
    } else if value <= u64::from(u16::MAX) {
        out.push(major | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(major | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) fn write_map(out: &mut Vec<u8>, entries: u64) {
    write_head(out, MAJOR_MAP, entries);
}

pub(crate) fn write_uint(out: &mut Vec<u8>, value: u64) {
    write_head(out, MAJOR_UINT, value);
}

pub(crate) fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_head(out, MAJOR_BYTES, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub(crate) fn write_text(out: &mut Vec<u8>, text: &str) {
    write_head(out, MAJOR_TEXT, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

pub(crate) fn write_array(out: &mut Vec<u8>, len: usize) {
    write_head(out, MAJOR_ARRAY, len as u64);
}

/// A signed integer: major type 0 for `value >= 0`, major type 1 (`-1 - n`)
/// below zero.
pub(crate) fn write_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        write_head(out, MAJOR_UINT, value as u64);
    } else {
        write_head(out, MAJOR_NEGATIVE, !(value as u64));
    }
}

pub(crate) fn write_null(out: &mut Vec<u8>) {
    out.push(0xf6);
}

/// The encoded size of a byte-string head for `len` bytes.
pub(crate) fn bytes_head_len(len: usize) -> usize {
    match len {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_are_shortest_form_only() {
        for value in [0u64, 23, 24, 255, 256, 65_535, 65_536, u32::MAX as u64 + 1] {
            let mut out = Vec::new();
            write_uint(&mut out, value);
            assert_eq!(out.len(), bytes_head_len(value as usize));
            assert_eq!(Reader::new(&out).uint(), Ok(value));
        }
        assert_eq!(
            Reader::new(&[0x18, 0x17]).uint(),
            Err(ErrorCode::NonCanonical)
        );
        assert_eq!(
            Reader::new(&[0x19, 0x00, 0xff]).uint(),
            Err(ErrorCode::NonCanonical)
        );
        assert_eq!(Reader::new(&[0x1f]).uint(), Err(ErrorCode::NonCanonical));
        assert_eq!(Reader::new(&[0x5f]).bytes(8), Err(ErrorCode::NonCanonical));
        assert_eq!(Reader::new(&[0x19, 0x01]).uint(), Err(ErrorCode::Malformed));
        assert_eq!(
            Reader::new(&[0x62, 0xff, 0xfe]).text(8),
            Err(ErrorCode::Malformed)
        );
        assert_eq!(
            Reader::new(&[0x61, 0x01]).text(8),
            Err(ErrorCode::Malformed)
        );
        assert_eq!(Reader::new(&[0x62, 0x09, 0x0a]).text(8), Ok("\t\n"));
        // A huge claim is TooLarge on every target, before any conversion.
        let huge = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Reader::new(&huge).bytes(8), Err(ErrorCode::TooLarge));
        assert_eq!(Reader::new(&huge).fixed::<32>(), Err(ErrorCode::Malformed));
        assert_eq!(
            Reader::new(&[0x1b, 0, 0x20, 0, 0, 0, 0, 0, 0]).timestamp(),
            Err(ErrorCode::Malformed)
        );
    }
}
