#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsWireQuery {
    pub domain: String,
    pub qtype: u16,
}

/// Memory-safe DNS wire-format query parser (UDP/53 payload).
pub fn parse_dns_query(payload: &[u8]) -> Option<DnsWireQuery> {
    if payload.len() < 17 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if (flags & 0x8000) != 0 {
        return None; // QR=1 means response, not query
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut off = 12usize;
    let mut labels: Vec<String> = Vec::new();
    let mut steps = 0usize;

    while off < payload.len() && steps < 128 {
        steps += 1;
        let len = payload[off] as usize;
        if len == 0 {
            off += 1;
            break;
        }
        // Reject compression pointers in question QNAME (malformed / pointer bomb)
        if (len & 0xc0) != 0 {
            return None;
        }
        off += 1;
        let end = off.checked_add(len)?;
        let label = payload.get(off..end)?;
        let s = std::str::from_utf8(label).ok()?;
        labels.push(s.to_lowercase());
        off = end;
    }

    if labels.is_empty() || off + 4 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[off], payload[off + 1]]);
    Some(DnsWireQuery {
        domain: labels.join("."),
        qtype,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_dns_wire_query() {
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.push(4);
        pkt.extend_from_slice(b"evil");
        pkt.push(4);
        pkt.extend_from_slice(b"test");
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

        let q = parse_dns_query(&pkt).expect("must parse DNS query");
        assert_eq!(q.domain, "evil.test");
        assert_eq!(q.qtype, 1);
    }

    #[test]
    fn rejects_pointer_bomb_and_truncated_dns() {
        assert!(parse_dns_query(&[0; 10]).is_none());
        let bomb = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1,
        ];
        assert!(parse_dns_query(&bomb).is_none());
    }
}
