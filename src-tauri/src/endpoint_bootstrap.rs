//! Fail-closed encrypted DNS bootstrap for VPN endpoint hostnames.
//!
//! This preparation primitive uses numeric-address DoH bootstrap and never
//! falls back to the Windows/system resolver. It is not a Connect implementation.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};

const DOH_HOST: &str = "cloudflare-dns.com";
const DOH_URL: &str = "https://cloudflare-dns.com/dns-query";
const DNS_MEDIA_TYPE: &str = "application/dns-message";
const MAX_MESSAGE_BYTES: usize = 4096;
const MAX_ANSWERS: usize = 128;
const MAX_CNAME_HOPS: usize = 8;

fn bootstrap_addresses() -> [SocketAddr; 4] {
    [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 443),
        SocketAddr::new(IpAddr::V6("2606:4700:4700::1111".parse().expect("valid IPv6 resolver")), 443),
        SocketAddr::new(IpAddr::V6("2606:4700:4700::1001".parse().expect("valid IPv6 resolver")), 443),
    ]
}

/// HTTPS-only DoH with numeric resolver addresses, normal TLS verification,
/// proxy environment variables disabled, and redirects disabled.
pub struct EndpointBootstrapResolver {
    client: reqwest::Client,
}

impl EndpointBootstrapResolver {
    pub fn new() -> Result<Self, String> {
        let addresses = bootstrap_addresses();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(DOH_HOST, &addresses)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| "Could not initialize the encrypted VPN endpoint bootstrap client.".to_string())?;
        Ok(Self { client })
    }

    /// Resolve a numeric address directly, or query A and AAAA over DoH.
    /// All failures are fatal; system DNS and plaintext DNS are never fallback paths.
    pub async fn resolve_server(&self, server: &str) -> Result<Vec<IpAddr>, String> {
        let literal = server.strip_suffix('.').unwrap_or(server);
        if let Ok(address) = literal.parse::<IpAddr>() {
            return if is_usable_unicast(address) {
                Ok(vec![address])
            } else {
                Err("The VPN endpoint address is not a supported unicast destination.".into())
            };
        }

        let domain = normalize_domain(server)?;
        let (ipv4, ipv6) = tokio::try_join!(
            self.resolve_family(&domain, RecordType::A),
            self.resolve_family(&domain, RecordType::Aaaa),
        )?;
        let mut addresses = BTreeSet::new();
        for address in ipv4.into_iter().chain(ipv6) {
            if !is_usable_unicast(address) {
                return Err("Encrypted DNS returned an unsupported non-unicast VPN endpoint address.".into());
            }
            addresses.insert(address);
        }
        if addresses.is_empty() {
            return Err("Encrypted DNS returned no A or AAAA address for the VPN endpoint.".into());
        }
        Ok(addresses.into_iter().collect())
    }

    async fn resolve_family(&self, domain: &str, kind: RecordType) -> Result<Vec<IpAddr>, String> {
        let mut name = domain.to_string();
        let mut visited = BTreeSet::new();
        for _ in 0..=MAX_CNAME_HOPS {
            if !visited.insert(name.clone()) {
                return Err("Encrypted DNS returned a CNAME loop for the VPN endpoint.".into());
            }
            let query = encode_query(&name, kind)?;
            let response = self.exchange(&query).await?;
            match parse_response(&response, &name, kind)? {
                QueryAnswer::Addresses(values) => return Ok(values),
                QueryAnswer::Alias(alias) => name = alias,
                QueryAnswer::NoData => return Ok(Vec::new()),
            }
        }
        Err("Encrypted DNS exceeded the maximum VPN endpoint CNAME depth.".into())
    }

    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let response = self.client
            .post(DOH_URL)
            .header(ACCEPT, DNS_MEDIA_TYPE)
            .header(CONTENT_TYPE, DNS_MEDIA_TYPE)
            .body(query.to_vec())
            .send()
            .await
            .map_err(|_| "The encrypted VPN endpoint DNS request failed; system DNS fallback is disabled.".to_string())?;

        if !response.status().is_success() {
            return Err(format!("The encrypted VPN endpoint DNS resolver returned HTTP status {}.", response.status().as_u16()));
        }
        let media_type = response.headers().get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .unwrap_or("")
            .trim();
        if !media_type.eq_ignore_ascii_case(DNS_MEDIA_TYPE) {
            return Err("The encrypted VPN endpoint DNS resolver returned an unexpected media type.".into());
        }
        if response.headers().get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_MESSAGE_BYTES)
        {
            return Err("The encrypted VPN endpoint DNS response exceeded the size limit.".into());
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "The encrypted VPN endpoint DNS response could not be read.".to_string())?;
            if body.len().saturating_add(chunk.len()) > MAX_MESSAGE_BYTES {
                return Err("The encrypted VPN endpoint DNS response exceeded the size limit.".into());
            }
            body.extend_from_slice(&chunk);
        }
        if body.is_empty() {
            return Err("The encrypted VPN endpoint DNS resolver returned an empty response.".into());
        }
        Ok(body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordType { A, Aaaa }

impl RecordType {
    fn code(self) -> u16 { match self { Self::A => 1, Self::Aaaa => 28 } }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QueryAnswer { Addresses(Vec<IpAddr>), Alias(String), NoData }

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordData { A(Ipv4Addr), Aaaa(Ipv6Addr), Cname(String), Other }

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnswerRecord { owner: String, data: RecordData }

fn normalize_domain(value: &str) -> Result<String, String> {
    if value.trim() != value || value.is_empty() || !value.is_ascii() {
        return Err("The VPN endpoint must be a valid ASCII DNS hostname or numeric IP address.".into());
    }
    let name = value.strip_suffix('.').unwrap_or(value);
    if name.is_empty() || name.len() > 253 || name.ends_with('.') {
        return Err("The VPN endpoint DNS hostname has an invalid length or root label.".into());
    }
    let labels = name.split('.').collect::<Vec<_>>();
    if labels.len() < 2 || labels.iter().any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Err("The VPN endpoint must be a fully qualified DNS hostname.".into());
    }
    Ok(name.to_ascii_lowercase())
}

fn is_usable_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v) => !v.is_unspecified() && !v.is_loopback() && !v.is_multicast() && v != Ipv4Addr::BROADCAST,
        IpAddr::V6(v) => !v.is_unspecified() && !v.is_loopback() && !v.is_multicast() && !v.is_unicast_link_local(),
    }
}

fn encode_query(name: &str, kind: RecordType) -> Result<Vec<u8>, String> {
    let name = normalize_domain(name)?;
    let mut packet = vec![0u8; 12];
    // RFC 8484 recommends ID zero because HTTP correlates each exchange.
    packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD
    packet[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&kind.code().to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(packet)
}

fn parse_response(packet: &[u8], expected_name: &str, expected_type: RecordType) -> Result<QueryAnswer, String> {
    if packet.len() < 12 || packet.len() > MAX_MESSAGE_BYTES {
        return Err("The encrypted DNS response has an invalid message length.".into());
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let questions = read_u16(packet, 4)?;
    let answer_count = read_u16(packet, 6)? as usize;
    if id != 0 || flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0
        || questions != 1 || answer_count > MAX_ANSWERS
    {
        return Err("The encrypted DNS response failed header validation.".into());
    }
    match flags & 0x000f {
        0 => {}
        3 => return Err("Encrypted DNS reports that the VPN endpoint hostname does not exist.".into()),
        _ => return Err("Encrypted DNS could not resolve the VPN endpoint hostname.".into()),
    }

    let (question_name, mut offset) = decode_name(packet, 12)?;
    let question_type = read_u16(packet, offset)?;
    let question_class = read_u16(packet, offset + 2)?;
    offset += 4;
    if question_name != expected_name || question_type != expected_type.code() || question_class != 1 {
        return Err("The encrypted DNS response question did not match the VPN endpoint query.".into());
    }

    let mut answers = Vec::with_capacity(answer_count);
    for _ in 0..answer_count {
        let (owner, next) = decode_name(packet, offset)?;
        offset = next;
        let rr_type = read_u16(packet, offset)?;
        let rr_class = read_u16(packet, offset + 2)?;
        let data_length = read_u16(packet, offset + 8)? as usize;
        offset += 10;
        let end = offset.checked_add(data_length)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| "The encrypted DNS response contains a truncated resource record.".to_string())?;

        if rr_class == 1 {
            let data = match rr_type {
                1 if data_length == 4 => RecordData::A(Ipv4Addr::new(packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3])),
                28 if data_length == 16 => {
                    let octets: [u8; 16] = packet[offset..end].try_into()
                        .map_err(|_| "The encrypted DNS response contains an invalid IPv6 record.".to_string())?;
                    RecordData::Aaaa(Ipv6Addr::from(octets))
                }
                5 => {
                    let (target, consumed) = decode_name(packet, offset)?;
                    if consumed != end || target.is_empty() {
                        return Err("The encrypted DNS response contains an invalid CNAME record.".into());
                    }
                    RecordData::Cname(target)
                }
                _ => RecordData::Other,
            };
            answers.push(AnswerRecord { owner, data });
        }
        offset = end;
    }
    follow_answer_chain(&answers, expected_name, expected_type)
}

fn follow_answer_chain(answers: &[AnswerRecord], initial: &str, kind: RecordType) -> Result<QueryAnswer, String> {
    let mut current = initial.to_string();
    let mut visited = BTreeSet::new();
    for _ in 0..=MAX_CNAME_HOPS {
        if !visited.insert(current.clone()) {
            return Err("The encrypted DNS response contains a CNAME loop.".into());
        }
        let mut addresses = Vec::new();
        let mut aliases = BTreeSet::new();
        for answer in answers.iter().filter(|answer| answer.owner == current) {
            match (&answer.data, kind) {
                (RecordData::A(v), RecordType::A) => addresses.push(IpAddr::V4(*v)),
                (RecordData::Aaaa(v), RecordType::Aaaa) => addresses.push(IpAddr::V6(*v)),
                (RecordData::Cname(alias), _) => { aliases.insert(alias.clone()); }
                _ => {}
            }
        }
        if !addresses.is_empty() && !aliases.is_empty() {
            return Err("The encrypted DNS response has conflicting address and CNAME records.".into());
        }
        if !addresses.is_empty() {
            addresses.sort();
            addresses.dedup();
            return Ok(QueryAnswer::Addresses(addresses));
        }
        if aliases.len() > 1 {
            return Err("The encrypted DNS response contains conflicting CNAME targets.".into());
        }
        if let Some(alias) = aliases.into_iter().next() {
            current = alias;
        } else {
            return if current == initial { Ok(QueryAnswer::NoData) } else { Ok(QueryAnswer::Alias(current)) };
        }
    }
    Err("The encrypted DNS response exceeded the maximum CNAME depth.".into())
}

fn decode_name(packet: &[u8], start: usize) -> Result<(String, usize), String> {
    if start >= packet.len() { return Err("The encrypted DNS response contains an out-of-range name.".into()); }
    let mut cursor = start;
    let mut next_offset = None;
    let mut labels = Vec::new();
    let mut steps = 0usize;
    let mut wire_length = 0usize;
    loop {
        steps += 1;
        if steps > packet.len() || cursor >= packet.len() {
            return Err("The encrypted DNS response contains a compression-pointer loop or truncated name.".into());
        }
        let length = packet[cursor];
        if length & 0xc0 == 0xc0 {
            if cursor + 1 >= packet.len() { return Err("The encrypted DNS response contains a truncated compression pointer.".into()); }
            let target = (((length as usize & 0x3f) << 8) | packet[cursor + 1] as usize) as usize;
            if target >= packet.len() { return Err("The encrypted DNS response contains an invalid compression pointer.".into()); }
            next_offset.get_or_insert(cursor + 2);
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 { return Err("The encrypted DNS response contains an unsupported DNS label encoding.".into()); }
        cursor += 1;
        if length == 0 {
            let next = next_offset.unwrap_or(cursor);
            return Ok((labels.join("."), next));
        }
        let len = length as usize;
        let end = cursor.checked_add(len).filter(|end| *end <= packet.len())
            .ok_or_else(|| "The encrypted DNS response contains a truncated DNS label.".to_string())?;
        let bytes = &packet[cursor..end];
        if !bytes.is_ascii() || !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
            return Err("The encrypted DNS response contains a non-hostname label.".into());
        }
        let label = std::str::from_utf8(bytes)
            .map_err(|_| "The encrypted DNS response contains an invalid DNS label.".to_string())?
            .to_ascii_lowercase();
        if label.starts_with('-') || label.ends_with('-') {
            return Err("The encrypted DNS response contains an invalid hostname label.".into());
        }
        wire_length = wire_length.saturating_add(len + 1);
        if wire_length > 255 { return Err("The encrypted DNS response contains an oversized DNS name.".into()); }
        labels.push(label);
        cursor = end;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = packet.get(offset..offset + 2)
        .ok_or_else(|| "The encrypted DNS response contains a truncated field.".to_string())?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_response(name: &str, kind: RecordType, records: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut packet = encode_query(name, kind).unwrap();
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for (rr_type, data) in records {
            packet.extend_from_slice(&[0xc0, 0x0c]);
            packet.extend_from_slice(&rr_type.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&60u32.to_be_bytes());
            packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
            packet.extend_from_slice(data);
        }
        packet
    }

    fn encoded_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') { out.push(label.len() as u8); out.extend_from_slice(label.as_bytes()); }
        out.push(0);
        out
    }

    #[test]
    fn query_uses_zero_id_and_exact_fully_qualified_question() {
        let packet = encode_query("Proxy.Example.org.", RecordType::A).unwrap();
        assert_eq!(&packet[..2], &[0, 0]);
        assert_eq!(read_u16(&packet, 2).unwrap(), 0x0100);
        assert_eq!(read_u16(&packet, 4).unwrap(), 1);
        let (name, end) = decode_name(&packet, 12).unwrap();
        assert_eq!(name, "proxy.example.org");
        assert_eq!(read_u16(&packet, end).unwrap(), 1);
    }

    #[test]
    fn parses_a_and_aaaa_records() {
        let a = query_response("proxy.example.org", RecordType::A, &[(1, vec![203, 0, 113, 8])]);
        assert_eq!(parse_response(&a, "proxy.example.org", RecordType::A).unwrap(),
            QueryAnswer::Addresses(vec!["203.0.113.8".parse::<IpAddr>().unwrap()]));
        let aaaa = query_response("proxy.example.org", RecordType::Aaaa,
            &[(28, "2001:db8::8".parse::<Ipv6Addr>().unwrap().octets().to_vec())]);
        assert_eq!(parse_response(&aaaa, "proxy.example.org", RecordType::Aaaa).unwrap(),
            QueryAnswer::Addresses(vec!["2001:db8::8".parse().unwrap()]));
    }

    #[test]
    fn follows_cname_to_an_address_in_the_same_response() {
        let mut packet = encode_query("proxy.example.org", RecordType::A).unwrap();
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&5u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        let cname = encoded_name("edge.example.net");
        packet.extend_from_slice(&(cname.len() as u16).to_be_bytes());
        packet.extend_from_slice(&cname);
        packet.extend_from_slice(&encoded_name("edge.example.net"));
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[203, 0, 113, 9]);
        assert_eq!(parse_response(&packet, "proxy.example.org", RecordType::A).unwrap(),
            QueryAnswer::Addresses(vec!["203.0.113.9".parse().unwrap()]));
    }

    #[test]
    fn rejects_wrong_question_id_truncation_and_nxdomain() {
        let mut packet = query_response("proxy.example.org", RecordType::A, &[(1, vec![203, 0, 113, 8])]);
        assert!(parse_response(&packet, "other.example.org", RecordType::A).is_err());
        packet[0] = 1;
        assert!(parse_response(&packet, "proxy.example.org", RecordType::A).is_err());
        let mut truncated = query_response("proxy.example.org", RecordType::A, &[]);
        truncated[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
        assert!(parse_response(&truncated, "proxy.example.org", RecordType::A).is_err());
        let mut nxdomain = query_response("proxy.example.org", RecordType::A, &[]);
        nxdomain[2..4].copy_from_slice(&0x8183u16.to_be_bytes());
        assert!(parse_response(&nxdomain, "proxy.example.org", RecordType::A).is_err());
    }

    #[test]
    fn rejects_invalid_hosts_and_non_unicast_addresses() {
        for host in ["", "localhost", "proxy..example.org", "-bad.example.org",
            "bad-.example.org", "has space.example.org", "proxy.example.org.."] {
            assert!(normalize_domain(host).is_err(), "accepted invalid hostname: {host}");
        }
        for address in [IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::BROADCAST), IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpAddr::V6("fe80::1".parse().unwrap())] {
            assert!(!is_usable_unicast(address));
        }
    }

    #[tokio::test]
    async fn literal_endpoint_returns_without_a_dns_exchange() {
        let resolver = EndpointBootstrapResolver::new().unwrap();
        assert_eq!(resolver.resolve_server("203.0.113.8").await.unwrap(),
            vec!["203.0.113.8".parse::<IpAddr>().unwrap()]);
    }
}
