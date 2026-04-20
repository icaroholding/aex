//! Magic-byte MIME verification.
//!
//! Catches the "renamed executable" smuggling pattern: a sender declares
//! `mime=application/pdf` but the first bytes are actually a Windows PE
//! header. Flagging this keeps policy engines honest about what they're
//! authorizing.
//!
//! The MVP table covers ~20 common formats. For a full-fidelity sniffer the
//! plan is to drop in the `infer` crate in Phase 2 once the policy engine
//! has richer MIME handling.

use std::time::Instant;

use async_trait::async_trait;

use crate::{pipeline::ScanInput, verdict::ScanVerdict, Scanner};

/// (mime, signature-at-offset-0) pairs. An entry with multiple signatures
/// means ANY of them matches.
struct Sig {
    mime: &'static str,
    magic: &'static [&'static [u8]],
}

const SIGS: &[Sig] = &[
    Sig {
        mime: "application/pdf",
        magic: &[b"%PDF-"],
    },
    Sig {
        mime: "image/png",
        magic: &[b"\x89PNG\r\n\x1a\n"],
    },
    Sig {
        mime: "image/jpeg",
        magic: &[b"\xff\xd8\xff"],
    },
    Sig {
        mime: "image/gif",
        magic: &[b"GIF87a", b"GIF89a"],
    },
    Sig {
        mime: "image/webp",
        // RIFF....WEBP — we match RIFF + WEBP at offset 8.
        magic: &[b"RIFF"],
    },
    Sig {
        mime: "application/zip",
        magic: &[b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    },
    Sig {
        mime: "application/x-7z-compressed",
        magic: &[b"7z\xbc\xaf\x27\x1c"],
    },
    Sig {
        mime: "application/gzip",
        magic: &[b"\x1f\x8b"],
    },
    Sig {
        mime: "application/x-tar",
        // tar has "ustar" at offset 257; fall back to any (handled below).
        magic: &[],
    },
    Sig {
        mime: "application/octet-stream",
        magic: &[],
    },
    Sig {
        mime: "text/plain",
        magic: &[],
    },
    Sig {
        mime: "application/json",
        magic: &[],
    },
    Sig {
        mime: "application/x-msdownload",
        magic: &[b"MZ"],
    },
    Sig {
        mime: "application/x-mach-binary",
        magic: &[
            b"\xcf\xfa\xed\xfe", // MH_MAGIC_64
            b"\xfe\xed\xfa\xcf",
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
        ],
    },
    Sig {
        mime: "application/x-executable",
        magic: &[b"\x7fELF"],
    },
];

#[derive(Default)]
pub struct MagicByteScanner;

impl MagicByteScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for MagicByteScanner {
    fn name(&self) -> &'static str {
        "magic-bytes"
    }

    async fn scan(&self, input: &ScanInput<'_>) -> ScanVerdict {
        let t0 = Instant::now();
        let declared = match input.declared_mime {
            Some(m) => m,
            None => {
                return ScanVerdict::clean(self.name(), t0.elapsed().as_millis() as u64);
            }
        };

        let detected = detect_mime(input.bytes);
        let dur = t0.elapsed().as_millis() as u64;

        match detected {
            Some(d) if mimes_compatible(declared, d) => ScanVerdict::clean(self.name(), dur),
            Some(d) => ScanVerdict::suspicious(
                self.name(),
                format!("declared {} but bytes look like {}", declared, d),
                dur,
            ),
            // Unknown bytes: suspicious only if the declared mime is one
            // we DO know a signature for (meaning we SHOULD have matched).
            None => {
                if declared_has_known_signature(declared) {
                    ScanVerdict::suspicious(
                        self.name(),
                        format!("declared {} but no magic matched", declared),
                        dur,
                    )
                } else {
                    ScanVerdict::clean(self.name(), dur)
                }
            }
        }
    }
}

fn detect_mime(bytes: &[u8]) -> Option<&'static str> {
    for sig in SIGS {
        for m in sig.magic {
            if bytes.starts_with(m) {
                // WebP refinement: RIFF header must be followed by WEBP.
                if sig.mime == "image/webp" {
                    if bytes.len() >= 12 && &bytes[8..12] == b"WEBP" {
                        return Some("image/webp");
                    } else {
                        continue;
                    }
                }
                return Some(sig.mime);
            }
        }
    }
    None
}

fn declared_has_known_signature(declared: &str) -> bool {
    SIGS.iter()
        .any(|s| s.mime == declared && !s.magic.is_empty())
}

/// Two MIME strings are "compatible" when exact-equal or when the caller
/// declared a generic type we can't contradict (`application/octet-stream`).
fn mimes_compatible(declared: &str, detected: &str) -> bool {
    if declared == detected {
        return true;
    }
    if declared == "application/octet-stream" {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::ScanResult;

    fn png_bytes() -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        v.extend_from_slice(&[0u8; 100]);
        v
    }

    fn pdf_bytes() -> Vec<u8> {
        let mut v = b"%PDF-1.7\n".to_vec();
        v.extend_from_slice(&[0u8; 100]);
        v
    }

    fn elf_bytes() -> Vec<u8> {
        let mut v = b"\x7fELF".to_vec();
        v.extend_from_slice(&[0u8; 100]);
        v
    }

    #[tokio::test]
    async fn no_declared_mime_passes() {
        let s = MagicByteScanner::new();
        let png = png_bytes();
        let v = s.scan(&ScanInput::new(&png)).await;
        assert_eq!(v.result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn declared_matches_magic() {
        let s = MagicByteScanner::new();
        let png = png_bytes();
        let input = ScanInput::new(&png).with_declared_mime("image/png");
        let v = s.scan(&input).await;
        assert_eq!(v.result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn declared_mismatch_flagged() {
        let s = MagicByteScanner::new();
        let elf = elf_bytes();
        let input = ScanInput::new(&elf).with_declared_mime("application/pdf");
        let v = s.scan(&input).await;
        assert_eq!(v.result, ScanResult::Suspicious);
        assert!(v.details.contains("application/pdf"));
    }

    #[tokio::test]
    async fn declared_with_unknown_bytes_flagged() {
        let s = MagicByteScanner::new();
        let input = ScanInput::new(b"hello not a pdf").with_declared_mime("application/pdf");
        let v = s.scan(&input).await;
        assert_eq!(v.result, ScanResult::Suspicious);
    }

    #[tokio::test]
    async fn octet_stream_compatible_with_anything() {
        let s = MagicByteScanner::new();
        let pdf = pdf_bytes();
        let input = ScanInput::new(&pdf).with_declared_mime("application/octet-stream");
        let v = s.scan(&input).await;
        assert_eq!(v.result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn text_declared_but_no_signature_passes() {
        // text/plain has no magic — we don't know what plain text looks like.
        let s = MagicByteScanner::new();
        let input = ScanInput::new(b"hello world").with_declared_mime("text/plain");
        let v = s.scan(&input).await;
        assert_eq!(v.result, ScanResult::Clean);
    }
}
