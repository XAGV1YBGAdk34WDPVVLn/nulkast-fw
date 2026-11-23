use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    pub sni: Option<String>,
    pub tls_version: String,
    pub alpn: Option<String>,
    pub ja4: String,
}

#[inline]
fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && ((val >> 8) == (val & 0x00ff))
}

#[inline]
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

fn sha256_12(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".to_string();
    }
    let digest = Sha256::digest(input.as_bytes());
    let mut hex = String::with_capacity(12);
    for b in &digest[..6] {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

/// Parse a raw TCP payload as a TLS ClientHello and compute its official FoxIO JA4 fingerprint.
/// Memory-safe and zero-panic on arbitrary/malformed WAN/LAN bytes.
pub fn parse_client_hello(payload: &[u8]) -> Option<TlsClientHello> {
    // TLS record header: type(1)=0x16 (Handshake), version(2)=0x03xx, length(2)
    if payload.len() < 43 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    let record_len = read_u16(payload, 3)? as usize;
    let rec = payload.get(5..payload.len().min(5 + record_len))?;
    if rec.len() < 38 || rec[0] != 0x01 {
        return None; // Not ClientHello
    }
    let hs_len = ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | (rec[3] as usize);
    let body = rec.get(4..rec.len().min(4 + hs_len))?;
    if body.len() < 34 {
        return None;
    }

    let client_version = read_u16(body, 0)?;
    let mut off = 2 + 32; // version + random

    // Session ID
    let sid_len = *body.get(off)? as usize;
    off = off.checked_add(1)?.checked_add(sid_len)?;

    // Cipher suites
    let cs_len = read_u16(body, off)? as usize;
    off = off.checked_add(2)?;
    let cs_end = off.checked_add(cs_len)?;
    if cs_end > body.len() || cs_len % 2 != 0 {
        return None;
    }
    let mut ciphers: Vec<u16> = Vec::new();
    let mut p = off;
    while p + 2 <= cs_end {
        let c = read_u16(body, p)?;
        if !is_grease(c) {
            ciphers.push(c);
        }
        p += 2;
    }
    off = cs_end;

    // Compression methods
    let comp_len = *body.get(off)? as usize;
    off = off.checked_add(1)?.checked_add(comp_len)?;

    let mut sni: Option<String> = None;
    let mut alpn: Option<String> = None;
    let mut best_version = client_version;
    let mut exts_all: Vec<u16> = Vec::new();
    let mut exts_for_hash: Vec<u16> = Vec::new();
    let mut sig_algs: Vec<u16> = Vec::new();

    // Extensions (optional)
    if off + 2 <= body.len() {
        let ext_total = read_u16(body, off)? as usize;
        off += 2;
        let ext_end = body.len().min(off.saturating_add(ext_total));
        while off + 4 <= ext_end {
            let ext_type = read_u16(body, off)?;
            let ext_len = read_u16(body, off + 2)? as usize;
            off += 4;
            let data = body.get(off..off.checked_add(ext_len)?)?;
            off += ext_len;

            if !is_grease(ext_type) {
                exts_all.push(ext_type);
                if ext_type != 0x0000 && ext_type != 0x0010 {
                    exts_for_hash.push(ext_type);
                }
            }

            match ext_type {
                // SNI (0x0000)
                0x0000 if data.len() >= 5 => {
                    let list_len = read_u16(data, 0)? as usize;
                    let mut sp = 2;
                    let send = data.len().min(2 + list_len);
                    while sp + 3 <= send {
                        let name_type = data[sp];
                        let name_len = read_u16(data, sp + 1)? as usize;
                        sp += 3;
                        if let Some(name_bytes) = data.get(sp..sp + name_len) {
                            if name_type == 0x00 {
                                if let Ok(host) = std::str::from_utf8(name_bytes) {
                                    sni = Some(host.to_lowercase());
                                    break;
                                }
                            }
                        }
                        sp = sp.saturating_add(name_len);
                    }
                }
                // Signature Algorithms (0x000d) — keep wire order for FoxIO JA4 Part C
                0x000d if data.len() >= 2 => {
                    let slen = read_u16(data, 0)? as usize;
                    let mut sp = 2;
                    let send = data.len().min(2 + slen);
                    while sp + 2 <= send {
                        let sa = read_u16(data, sp)?;
                        if !is_grease(sa) {
                            sig_algs.push(sa);
                        }
                        sp += 2;
                    }
                }
                // ALPN (0x0010) — first protocol string
                0x0010 if data.len() >= 3 => {
                    let list_len = read_u16(data, 0)? as usize;
                    if list_len >= 2 && data.len() >= 3 {
                        let plen = data[2] as usize;
                        if let Some(pb) = data.get(3..3 + plen) {
                            if let Ok(proto) = std::str::from_utf8(pb) {
                                if !proto.is_empty() {
                                    alpn = Some(proto.to_string());
                                }
                            }
                        }
                    }
                }
                // Supported Versions (0x002b)
                0x002b if !data.is_empty() => {
                    let vlen = data[0] as usize;
                    let mut vp = 1;
                    let vend = data.len().min(1 + vlen);
                    let mut max_v: u16 = 0;
                    while vp + 2 <= vend {
                        let v = read_u16(data, vp)?;
                        if !is_grease(v) && v > max_v {
                            max_v = v;
                        }
                        vp += 2;
                    }
                    if max_v > 0 {
                        best_version = max_v;
                    }
                }
                _ => {}
            }
        }
    }

    // FoxIO JA4 Part A: <t><ver><d|i><ciphers:02d><exts:02d><alpn_first_last|00>
    let ver = version_code(best_version);
    let sni_flag = if sni.is_some() { 'd' } else { 'i' };
    let c_cnt = ciphers.len().min(99);
    let e_cnt = exts_all.len().min(99);
    let alpn_tag = match &alpn {
        Some(a) if !a.is_empty() => {
            let bytes = a.as_bytes();
            let first = bytes[0] as char;
            let last = bytes[bytes.len() - 1] as char;
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
                format!("{}{}", first, last)
            } else {
                format!("{:02x}", bytes[0])
            }
        }
        _ => "00".to_string(),
    };
    let part_a = format!("t{}{}{:02}{:02}{}", ver, sni_flag, c_cnt, e_cnt, alpn_tag);

    // Part B: sorted non-GREASE ciphers hex joined by ',' -> SHA-256[:12]
    ciphers.sort_unstable();
    let ciphers_str = ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    let part_b = sha256_12(&ciphers_str);

    // Part C: sorted non-GREASE/SNI/ALPN extensions + '_' + wire-order sigalgs -> SHA-256[:12]
    exts_for_hash.sort_unstable();
    let exts_str = exts_for_hash
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");
    let sigs_str = sig_algs
        .iter()
        .map(|s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join(",");
    let part_c_in = if sigs_str.is_empty() {
        exts_str
    } else if exts_str.is_empty() {
        format!("_{}", sigs_str)
    } else {
        format!("{}_{}", exts_str, sigs_str)
    };
    let part_c = sha256_12(&part_c_in);

    Some(TlsClientHello {
        sni,
        tls_version: ver.to_string(),
        alpn,
        ja4: format!("{}_{}_{}", part_a, part_b, part_c),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample_client_hello(host: &str) -> Vec<u8> {
        let mut exts = Vec::new();
        // GREASE extension 0x0a0a (must be excluded from counts & hash)
        exts.extend_from_slice(&[0x0a, 0x0a, 0x00, 0x00]);
        // SNI extension (0x0000)
        let hbytes = host.as_bytes();
        let sni_list_len = (3 + hbytes.len()) as u16;
        let sni_ext_len = 2 + sni_list_len;
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&sni_ext_len.to_be_bytes());
        exts.extend_from_slice(&sni_list_len.to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&(hbytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(hbytes);
        // ALPN extension (0x0010): "h2"
        exts.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
        // Supported Versions (0x002b): GREASE + TLS 1.3 (0x0304) + TLS 1.2 (0x0303)
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x07, 0x06, 0x1a, 0x1a, 0x03, 0x04, 0x03, 0x03]);
        // Signature Algorithms (0x000d): 0x0403, 0x0804
        exts.extend_from_slice(&[0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
        body.extend_from_slice(&[0x55; 32]); // random
        body.push(0x00); // session id len = 0
        // Ciphers: GREASE 0x2a2a, 0x1301, 0x1302
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0x2a, 0x2a, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]); // compression: null
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let blen = body.len();
        hs.push(((blen >> 16) & 0xff) as u8);
        hs.push(((blen >> 8) & 0xff) as u8);
        hs.push((blen & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_and_computes_foxio_ja4() {
        let pkt = build_sample_client_hello("Evil.Test");
        let ch = parse_client_hello(&pkt).expect("must parse ClientHello");
        assert_eq!(ch.sni.as_deref(), Some("evil.test"));
        assert_eq!(ch.tls_version, "13");
        assert_eq!(ch.alpn.as_deref(), Some("h2"));
        // Part A: t + 13 + d + 02 (2 non-GREASE ciphers) + 04 (4 non-GREASE exts) + h2
        assert!(ch.ja4.starts_with("t13d0204h2_"), "ja4={}", ch.ja4);
        let parts: Vec<&str> = ch.ja4.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn safely_rejects_malformed_and_truncated_buffers() {
        assert!(parse_client_hello(&[]).is_none());
        assert!(parse_client_hello(&[0x16, 0x03, 0x01, 0xff, 0xff]).is_none());
        assert!(parse_client_hello(&[0x17; 100]).is_none());
    }
}
