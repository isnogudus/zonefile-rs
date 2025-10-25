use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;

use crate::record::CnameRecord;
use crate::record::MxRecord;
use crate::record::NsRecord;
use crate::record::PtrRecord;
use crate::record::SrvRecord;
use crate::transform::parse_email;
use crate::transform::parse_forward;
use crate::transform::parse_reverse;
use crate::validation::validate_dns_name;
use crate::{
    constants::{
        DEFAULT_EXPIRE, DEFAULT_MX_PRIO, DEFAULT_NRC_TTL, DEFAULT_REFRESH, DEFAULT_RETRY,
        DEFAULT_SRV_PRIO, DEFAULT_SRV_WEIGHT, DEFAULT_TTL, DEFAULT_WITH_PTR,
    },
    record::ARecord,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameserverEntry {
    pub name: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MxEntry {
    pub name: String,
    pub prio: Option<u16>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    pub ip: SingleOrVecValue<IpAddr>,
    pub alias: Option<SingleOrVecValue<String>>,
    pub ttl: Option<u32>,
    #[serde(rename = "with-ptr")]
    pub with_ptr: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum HostValue {
    Ip(SingleOrVecValue<IpAddr>),
    Entry(HostEntry),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CnameEntry {
    pub target: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SrvEntry {
    pub target: String,
    pub port: u16,
    pub ttl: Option<u32>,
    pub prio: Option<u16>,
    pub weight: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrTableValue<T> {
    Entry(String),
    Table(T),
}

impl StringOrTableValue<MxEntry> {
    pub fn to_entry(self) -> MxEntry {
        match self {
            StringOrTableValue::Entry(val) => MxEntry {
                name: val,
                prio: None,
                ttl: None,
            },
            Self::Table(val) => val,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum SingleOrVecValue<T> {
    Single(T),
    Multiple(Vec<T>),
}
impl<T> SingleOrVecValue<T> {
    pub fn to_vec(self) -> Vec<T> {
        match self {
            SingleOrVecValue::Single(val) => vec![val],
            SingleOrVecValue::Multiple(vec) => vec,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseEntry {
    pub serial: Option<u32>,
    pub email: Option<String>,
    pub expire: Option<u32>,
    pub nameserver: Option<SingleOrVecValue<StringOrTableValue<NameserverEntry>>>,
    #[serde(rename = "nrc-ttl")]
    pub nrc_ttl: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Content {
    #[serde(default = "RawDefaults::default")]
    pub defaults: RawDefaults,
    pub reverse: Option<HashMap<IpNetwork, ReverseEntry>>,
    pub zone: Option<Vec<Zone>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default = "RawDefaults::default")]
#[serde(deny_unknown_fields)]
pub struct RawDefaults {
    pub serial: Option<u32>,
    pub email: Option<String>,
    pub expire: u32,
    pub mx: Option<SingleOrVecValue<StringOrTableValue<MxEntry>>>,
    #[serde(rename = "mx-prio")]
    pub mx_prio: u16,
    pub nameserver: Option<SingleOrVecValue<String>>,
    #[serde(rename = "nrc-ttl")]
    pub nrc_ttl: u32,
    pub refresh: u32,
    pub retry: u32,
    #[serde(rename = "srv-prio")]
    pub srv_prio: u16,
    #[serde(rename = "srv-weight")]
    pub srv_weight: u16,
    pub ttl: u32,
    #[serde(rename = "with-ptr")]
    pub with_ptr: bool,
}

impl RawDefaults {
    fn default() -> Self {
        Self {
            serial: None,
            email: None,
            expire: DEFAULT_EXPIRE,
            mx: None,
            mx_prio: DEFAULT_MX_PRIO,
            nameserver: None,
            nrc_ttl: DEFAULT_NRC_TTL,
            refresh: DEFAULT_REFRESH,
            retry: DEFAULT_RETRY,
            srv_prio: DEFAULT_SRV_PRIO,
            srv_weight: DEFAULT_SRV_WEIGHT,
            ttl: DEFAULT_TTL,
            with_ptr: DEFAULT_WITH_PTR,
        }
    }
}

#[derive(Debug)]
pub struct SessionDefaults {
    pub serial: u32,
    pub email: Option<String>,
    pub expire: u32,
    pub mx: Vec<MxEntry>,
    pub mx_prio: u16,
    pub nameserver: Vec<String>,
    pub nrc_ttl: u32,
    pub refresh: u32,
    pub retry: u32,
    pub srv_prio: u16,
    pub srv_weight: u16,
    pub ttl: u32,
    pub with_ptr: bool,
}

impl SessionDefaults {
    pub fn from_raw(raw: RawDefaults, gen_serial: u32) -> Result<Self> {
        let serial = match raw.serial {
            Some(s) => s,
            None => gen_serial,
        };
        if raw.retry >= raw.refresh {
            let retry = raw.retry;
            let refresh = raw.refresh;
            bail!("retry ({retry}) must be less than refresh {refresh}");
        }
        let email = match raw.email {
            Some(raw_email) => Some(parse_email(&raw_email)?),
            None => None,
        };
        let nameserver = raw
            .nameserver
            .map(SingleOrVecValue::to_vec)
            .unwrap_or_default();

        for ns_entry in &nameserver {
            validate_dns_name(&ns_entry)?
        }

        let mx = raw
            .mx
            .map(SingleOrVecValue::to_vec)
            .unwrap_or_default()
            .into_iter()
            .map(StringOrTableValue::<MxEntry>::to_entry)
            .collect();

        Ok(Self {
            serial,
            email,
            expire: raw.expire,
            mx,
            mx_prio: raw.mx_prio,
            nameserver,
            nrc_ttl: raw.nrc_ttl,
            refresh: raw.refresh,
            retry: raw.retry,
            srv_prio: raw.srv_prio,
            srv_weight: raw.srv_weight,
            ttl: raw.ttl,
            with_ptr: raw.with_ptr,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub serial: Option<u32>,
    pub name: String,
    pub email: Option<String>,
    pub expire: Option<u32>,
    pub mx: Option<SingleOrVecValue<StringOrTableValue<MxEntry>>>,
    #[serde(rename = "mx-prio")]
    pub mx_prio: Option<u16>,
    pub nameserver: Option<SingleOrVecValue<StringOrTableValue<NameserverEntry>>>,
    #[serde(rename = "nrc-ttl")]
    pub nrc_ttl: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    #[serde(rename = "srv-prio")]
    pub srv_prio: Option<u16>,
    #[serde(rename = "srv-weight")]
    pub srv_weight: Option<u16>,
    pub ttl: Option<u32>,
    #[serde(rename = "with-ptr")]
    pub with_ptr: Option<bool>,

    pub hosts: Option<std::collections::HashMap<String, HostValue>>,
    pub cname: Option<std::collections::HashMap<String, StringOrTableValue<CnameEntry>>>,
    pub srv: Option<std::collections::HashMap<String, SrvEntry>>,
}

#[derive(Debug)]
pub struct ZoneBase {
    pub serial: u32,
    pub name: String,
    pub email: String,
    pub expire: u32,
    pub nameserver: Vec<NsRecord>,
    pub nrc_ttl: u32,
    pub refresh: u32,
    pub retry: u32,
    pub ttl: u32,
}

#[derive(Debug)]
pub struct ForwardZone {
    pub base: ZoneBase,
    pub mx: Vec<MxRecord>,
    pub hosts: Vec<ARecord>,
    pub cname: Vec<CnameRecord>,
    pub srv: Vec<SrvRecord>,
}

#[derive(Debug)]
pub struct ReverseZone {
    pub base: ZoneBase,
    pub ptr: Vec<PtrRecord>,
    pub split: usize,
}

pub fn parse_toml(content: &str, serial: u32) -> Result<(Vec<ForwardZone>, Vec<ReverseZone>)> {
    let content: Content = toml::from_str(content)?;
    let defaults: SessionDefaults = SessionDefaults::from_raw(content.defaults, serial)?;

    let mut ips: HashMap<IpAddr, PtrRecord> = HashMap::new();
    let zones = content.zone.unwrap_or_default();
    let mut forward: Vec<ForwardZone> = vec![];
    for zone in zones {
        let (z, ptrs) = parse_forward(zone, &defaults)?;
        forward.push(z);
        for ptr in ptrs {
            if ips.contains_key(&ptr.ip) {
                bail!("Duplicate Ptr Record: {:?}", ptr)
            }
            ips.insert(ptr.ip, ptr);
        }
    }
    let reverse = parse_reverse(content.reverse, &defaults, ips)?;
    Ok((forward, reverse))
}
