use crate::parser::{
    CnameEntry, ForwardZone, HostValue, MxEntry, NameserverEntry, ReverseEntry, ReverseZone,
    SessionDefaults, SrvEntry, Zone, ZoneBase,
};
use crate::record::{CnameRecord, NsRecord, PtrRecord, SrvRecord};
use crate::validation::validate_dns_name;
use crate::validation::validate_email;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::{
    parser::{SingleOrVecValue, StringOrTableValue},
    record::{ARecord, MxRecord},
};
use anyhow::{bail, Result};

/// Converts a hostname to FQDN (Fully Qualified Domain Name)
pub fn parse_host_str(name: &str, zone_name: &str) -> Result<String> {
    let host = name.trim();

    if host.ends_with(".") {
        return Ok(host.to_string());
    }

    if zone_name.is_empty() {
        bail!("Host must be a FQDN, got {host}")
    }

    if host == "@" {
        return Ok(zone_name.to_string());
    }

    Ok(format!("{host}.{zone_name}"))
}

pub fn parse_srv_name(name: &str, zone_name: &str) -> Result<String> {
    let srv_name = name.trim();

    let parts: Vec<&str> = srv_name.split('.').collect();

    if parts.len() < 2 {
        bail!("SRV name must have at least service and protocol (e.g., '_http._tcp'), got: {srv_name}")
    }

    if !parts[0].starts_with('_') {
        bail!("SRV service name must start with '_', got: '{}'", parts[0])
    }

    if !parts[1].starts_with('_') {
        bail!("SRV protocol name must start with '_', got: '{}'", parts[1])
    }

    parse_host_str(srv_name, zone_name)
}

pub fn parse_email(raw: &str) -> Result<String> {
    let (local, domain) = raw
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("Email is missing @, got: {raw}"))?;

    let escaped_local = local.replace('.', "\\.");

    let mut dom = domain.to_string();
    if !dom.ends_with('.') {
        dom.push('.');
    }
    let email = format!("{escaped_local}.{dom}");

    validate_email(&email)?;

    Ok(email)
}

pub fn parse_mx(
    raw: Option<SingleOrVecValue<StringOrTableValue<MxEntry>>>,
    zone_name: &str,
    default_ttl: u32,
    default_mx_prio: u16,
    default_mx: &Vec<MxEntry>,
) -> Result<Vec<MxRecord>> {
    match raw {
        Some(entry) => entry
            .to_vec()
            .into_iter()
            .map(|entry| {
                let (name, ttl, prio) = match entry {
                    StringOrTableValue::Entry(e) => (e, default_ttl, default_mx_prio),
                    StringOrTableValue::Table(t) => (
                        t.name,
                        t.ttl.unwrap_or(default_ttl),
                        t.prio.unwrap_or(default_mx_prio),
                    ),
                };
                let fqdn = parse_host_str(&name, &zone_name)?;
                validate_dns_name(&fqdn)?;
                Ok(MxRecord {
                    name: fqdn,
                    ttl,
                    prio,
                })
            })
            .collect(),
        None => default_mx
            .into_iter()
            .map(|entry| {
                Ok(MxRecord {
                    name: entry.name.clone(),
                    ttl: entry.ttl.unwrap_or(default_ttl),
                    prio: entry.prio.unwrap_or(default_mx_prio),
                })
            })
            .collect(),
    }
}

pub fn parse_ns(
    raw: Option<SingleOrVecValue<StringOrTableValue<NameserverEntry>>>,
    zone_name: &str,
    default_ttl: u32,
    default_ns: &Vec<String>,
) -> Result<Vec<NsRecord>> {
    match raw {
        Some(zone_ns) => zone_ns
            .to_vec()
            .into_iter()
            .map(|entry| {
                let (name, ttl) = match entry {
                    StringOrTableValue::Entry(e) => (e, default_ttl),
                    StringOrTableValue::Table(t) => (t.name, t.ttl.unwrap_or(default_ttl)),
                };
                let fqdn = parse_host_str(&name, &zone_name)?;
                validate_dns_name(&fqdn)?;
                Ok(NsRecord { name: fqdn, ttl })
            })
            .collect(),
        None => {
            if default_ns.is_empty() {
                bail!("Forward zone {zone_name} needs a nameserver")
            }
            let records: Vec<NsRecord> = default_ns
                .into_iter()
                .map(|name| NsRecord {
                    name: name.clone(),
                    ttl: default_ttl,
                })
                .collect();
            Ok(records)
        }
    }
}

pub fn parse_cname(
    raw: Option<HashMap<String, StringOrTableValue<CnameEntry>>>,
    zone_name: &str,
    default_ttl: u32,
) -> Result<Vec<CnameRecord>> {
    raw.unwrap_or_default()
        .into_iter()
        .map(|(cname, entry)| {
            let name = parse_host_str(&cname, zone_name)?;
            let (host, ttl) = match entry {
                StringOrTableValue::Entry(e) => (e, default_ttl),
                StringOrTableValue::Table(t) => (t.target, t.ttl.unwrap_or(default_ttl)),
            };
            let target = parse_host_str(&host, zone_name)?;
            Ok(CnameRecord { name, target, ttl })
        })
        .collect()
}

pub fn parse_srv(
    raw: Option<HashMap<String, SrvEntry>>,
    zone_name: &str,
    default_ttl: u32,
    default_srv_prio: u16,
    default_srv_weight: u16,
) -> Result<Vec<SrvRecord>> {
    raw.unwrap_or_default()
        .into_iter()
        .map(|(srv_name, entry)| {
            let name = parse_srv_name(&srv_name, zone_name)?;
            let target = parse_host_str(&entry.target, zone_name)?;
            let ttl = entry.ttl.unwrap_or(default_ttl);
            let prio = entry.prio.unwrap_or(default_srv_prio);
            let weight = entry.weight.unwrap_or(default_srv_weight);
            Ok(SrvRecord {
                name,
                port: entry.port,
                target,
                ttl,
                prio,
                weight,
            })
        })
        .collect()
}

pub fn parse_hosts(
    raw: Option<std::collections::HashMap<String, HostValue>>,
    zone_name: &str,
    default_ttl: u32,
    default_with_ptr: bool,
) -> Result<(Vec<ARecord>, Vec<PtrRecord>)> {
    let mut a_records: Vec<ARecord> = Vec::new();
    let mut ptr_records: Vec<PtrRecord> = Vec::new();

    for (hostname, value) in raw.unwrap_or_default() {
        let fqdn = parse_host_str(&hostname, zone_name)?;

        let (ips, aliases, ttl, with_ptr) = match value {
            HostValue::Ip(ip) => (ip.to_vec(), vec![], default_ttl, default_with_ptr),
            HostValue::Entry(entry) => (
                entry.ip.to_vec(),
                entry.alias.map(|a| a.to_vec()).unwrap_or_default(),
                entry.ttl.unwrap_or(default_ttl),
                entry.with_ptr.unwrap_or(default_with_ptr),
            ),
        };
        for ip in ips {
            a_records.push(ARecord {
                name: fqdn.clone(),
                ip,
                ttl,
            });
            for alias in &aliases {
                let name = parse_host_str(&alias, zone_name)?;
                a_records.push(ARecord { name, ip, ttl });
            }
            if with_ptr && !fqdn.starts_with('*') {
                ptr_records.push(PtrRecord {
                    name: fqdn.clone(),
                    ip,
                    ttl,
                });
            }
        }
    }

    Ok((a_records, ptr_records))
}

pub fn create_reverse_zone_name(network: &IpNetwork) -> (String, usize) {
    match network {
        IpNetwork::V4(net) => {
            let prefix_len = net.prefix();
            let split = ((32 - prefix_len) / 8) as usize;

            let ip = net.network();
            let octets = ip.octets();

            let zone_octets = (prefix_len / 8) as usize;

            let mut parts = Vec::new();
            for i in (0..zone_octets).rev() {
                parts.push(octets[i].to_string());
            }

            let zone_name = format!("{}.in-addr.arpa.", parts.join("."));
            (zone_name, split)
        }
        IpNetwork::V6(net) => {
            let prefix_len = net.prefix();
            let split = ((128 - prefix_len) / 4) as usize;

            let ip = net.network();
            let hex_str = format!("{:032x}", u128::from(ip));
            let nibbles: Vec<char> = hex_str.chars().collect();
            let zone_nibbles = (prefix_len / 4) as usize;

            let parts: Vec<String> = nibbles
                .iter()
                .take(zone_nibbles)
                .rev()
                .map(|c| c.to_string())
                .collect();

            let zone_name = format!("{}.ip6.arpa.", parts.join("."));
            (zone_name, split)
        }
    }
}

pub fn ip_name(address: &IpAddr, split: usize) -> String {
    match address {
        IpAddr::V4(addr) => {
            let octets = addr.octets();

            let mut parts = Vec::new();
            for i in 0..split {
                parts.push(octets[3 - i].to_string());
            }

            parts.join(".")
        }
        IpAddr::V6(addr) => {
            let hex_str = format!("{:032x}", u128::from(*addr));
            let u: Vec<String> = hex_str
                .chars()
                .rev()
                .take(split)
                .map(|c| c.to_string())
                .collect();
            u.join(".")
        }
    }
}

pub fn parse_forward(
    raw: Zone,
    defaults: &SessionDefaults,
) -> Result<(ForwardZone, Vec<PtrRecord>)> {
    let mut zone_name = raw.name.clone();
    if !zone_name.ends_with('.') {
        zone_name.push('.')
    }

    let serial = raw.serial.unwrap_or(defaults.serial);
    let expire = raw.expire.unwrap_or(defaults.expire);
    let mx_prio = raw.mx_prio.unwrap_or(defaults.mx_prio);
    let nrc_ttl = raw.nrc_ttl.unwrap_or(defaults.nrc_ttl);
    let refresh = raw.refresh.unwrap_or(defaults.refresh);
    let retry = raw.retry.unwrap_or(defaults.retry);
    let srv_prio = raw.srv_prio.unwrap_or(defaults.srv_prio);
    let srv_weight = raw.srv_weight.unwrap_or(defaults.srv_weight);
    let ttl = raw.ttl.unwrap_or(defaults.ttl);
    let with_ptr = raw.with_ptr.unwrap_or(defaults.with_ptr);

    if retry >= refresh {
        bail!("retry ({retry}) must be less than refresh {refresh}")
    }

    let email = match raw.email {
        Some(mail) => parse_email(&mail)?,
        None => match defaults.email.clone() {
            Some(default_mail) => default_mail,
            None => bail!("Email is required"),
        },
    };

    let (hosts, ptr) = parse_hosts(raw.hosts, &zone_name, ttl, with_ptr)?;
    let mx = parse_mx(raw.mx, &zone_name, ttl, mx_prio, &defaults.mx)?;
    let nameserver = parse_ns(raw.nameserver, &zone_name, ttl, &defaults.nameserver)?;
    let cname: Vec<CnameRecord> = parse_cname(raw.cname, &zone_name, ttl)?;
    let srv: Vec<SrvRecord> = parse_srv(raw.srv, &zone_name, ttl, srv_prio, srv_weight)?;

    Ok((
        ForwardZone {
            base: ZoneBase {
                serial,
                name: zone_name,
                email,
                expire,
                nameserver,
                nrc_ttl,
                refresh,
                retry,
                ttl,
            },
            mx,
            hosts,
            cname,
            srv,
        },
        ptr,
    ))
}

pub fn parse_reverse(
    raw: Option<HashMap<IpNetwork, ReverseEntry>>,
    defaults: &SessionDefaults,
    mut ptrs: HashMap<IpAddr, PtrRecord>,
) -> Result<Vec<ReverseZone>> {
    let mut net4: Vec<Ipv4Network> = vec![];
    let mut net6: Vec<Ipv6Network> = vec![];
    let zones: Result<Vec<ReverseZone>> = raw
        .unwrap_or_default()
        .into_iter()
        .map(|(net, entry)| {
            match net {
                IpNetwork::V4(n4) => {
                    for n in &net4 {
                        if n.overlaps(n4) {
                            bail!("Reverse zone networks overlap: {n4} and {n}")
                        }
                    }
                    net4.push(n4)
                }
                IpNetwork::V6(n6) => {
                    for n in &net6 {
                        if n.overlaps(n6) {
                            bail!("Reverse zone networks overlap: {n6} and {n}")
                        }
                    }
                    net6.push(n6)
                }
            }
            let (name, split) = create_reverse_zone_name(&net);
            let serial = entry.serial.unwrap_or(defaults.serial);
            let expire = entry.expire.unwrap_or(defaults.expire);
            let nrc_ttl = entry.nrc_ttl.unwrap_or(defaults.nrc_ttl);
            let refresh = entry.refresh.unwrap_or(defaults.refresh);
            let retry = entry.retry.unwrap_or(defaults.retry);
            let ttl = entry.ttl.unwrap_or(defaults.ttl);

            if retry >= refresh {
                bail!("retry ({retry}) must be less than refresh {refresh}")
            }

            let email = match entry.email {
                Some(mail) => parse_email(&mail)?,
                None => match defaults.email.clone() {
                    Some(default_mail) => default_mail,
                    None => bail!("Email is required"),
                },
            };

            let nameserver = parse_ns(entry.nameserver, &name, ttl, &defaults.nameserver)?;

            let ptr: Vec<PtrRecord> = ptrs
                .extract_if(|ip, _ptr| net.contains(*ip))
                .map(|(_ip, ptr)| ptr)
                .collect();

            Ok(ReverseZone {
                base: ZoneBase {
                    serial,
                    name,
                    email,
                    expire,
                    nameserver,
                    nrc_ttl,
                    refresh,
                    retry,
                    ttl,
                },
                ptr,
                split,
            })
        })
        .collect();

    zones
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_str_fqdn() {
        let result = parse_host_str("example.com.", "zone.com.").unwrap();
        assert_eq!(result, "example.com.");
    }

    #[test]
    fn test_parse_host_str_relative() {
        let result = parse_host_str("host", "example.com.").unwrap();
        assert_eq!(result, "host.example.com.");
    }

    #[test]
    fn test_parse_host_str_apex() {
        let result = parse_host_str("@", "example.com.").unwrap();
        assert_eq!(result, "example.com.");
    }

    #[test]
    fn test_parse_host_str_with_trim() {
        let result = parse_host_str("  host  ", "example.com.").unwrap();
        assert_eq!(result, "host.example.com.");
    }

    #[test]
    fn test_parse_host_str_no_zone() {
        let result = parse_host_str("host", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_srv_name_valid() {
        let result = parse_srv_name("_http._tcp", "example.com.").unwrap();
        assert_eq!(result, "_http._tcp.example.com.");
    }

    #[test]
    fn test_parse_srv_name_fqdn() {
        let result = parse_srv_name("_http._tcp.example.com.", "zone.com.").unwrap();
        assert_eq!(result, "_http._tcp.example.com.");
    }

    #[test]
    fn test_parse_srv_name_missing_underscore_service() {
        let result = parse_srv_name("http._tcp", "example.com.");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_srv_name_missing_underscore_protocol() {
        let result = parse_srv_name("_http.tcp", "example.com.");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_srv_name_too_short() {
        let result = parse_srv_name("_http", "example.com.");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_email_valid() {
        let result = parse_email("admin@example.com").unwrap();
        assert_eq!(result, "admin.example.com.");
    }

    #[test]
    fn test_parse_email_with_dot() {
        let result = parse_email("john.doe@example.com").unwrap();
        assert_eq!(result, "john\\.doe.example.com.");
    }

    #[test]
    fn test_parse_email_already_fqdn() {
        let result = parse_email("admin@example.com.").unwrap();
        assert_eq!(result, "admin.example.com.");
    }

    #[test]
    fn test_parse_email_no_at() {
        let result = parse_email("admin.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_reverse_zone_name_ipv4_24() {
        use ipnetwork::Ipv4Network;
        let net = IpNetwork::V4("192.168.1.0/24".parse::<Ipv4Network>().unwrap());
        let (name, split) = create_reverse_zone_name(&net);
        assert_eq!(name, "1.168.192.in-addr.arpa.");
        assert_eq!(split, 1);
    }

    #[test]
    fn test_create_reverse_zone_name_ipv4_16() {
        use ipnetwork::Ipv4Network;
        let net = IpNetwork::V4("10.0.0.0/16".parse::<Ipv4Network>().unwrap());
        let (name, split) = create_reverse_zone_name(&net);
        assert_eq!(name, "0.10.in-addr.arpa.");
        assert_eq!(split, 2);
    }

    #[test]
    fn test_create_reverse_zone_name_ipv6() {
        use ipnetwork::Ipv6Network;
        let net = IpNetwork::V6("fd00:1234:5678:1::/64".parse::<Ipv6Network>().unwrap());
        let (name, split) = create_reverse_zone_name(&net);
        assert_eq!(name, "1.0.0.0.8.7.6.5.4.3.2.1.0.0.d.f.ip6.arpa.");
        assert_eq!(split, 16);
    }

    #[test]
    fn test_ip_name_ipv4() {
        use std::net::Ipv4Addr;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let name = ip_name(&ip, 1);
        assert_eq!(name, "10");
    }

    #[test]
    fn test_ip_name_ipv4_split_2() {
        use std::net::Ipv4Addr;
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5));
        let name = ip_name(&ip, 2);
        assert_eq!(name, "5.1");
    }

    #[test]
    fn test_ip_name_ipv6() {
        use std::net::Ipv6Addr;
        let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1234, 0x5678, 0x1, 0, 0, 0, 0x5));
        let name = ip_name(&ip, 4);
        assert_eq!(name, "5.0.0.0");
    }
}
