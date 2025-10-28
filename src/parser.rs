use anyhow::anyhow;
use ipnetwork::IpNetwork;
use serde_path_to_error;
use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;

use crate::args::InputFormat;
use crate::record::CnameRecord;
use crate::record::MxRecord;
use crate::record::NsRecord;
use crate::record::PtrRecord;
use crate::record::SrvRecord;
use crate::transform::parse_email;
use crate::transform::parse_forward;
use crate::transform::parse_reverse;
use crate::validation::{validate_dns_name, validate_email};
use crate::{
    constants::{
        DEFAULT_EXPIRE, DEFAULT_MX_PRIO, DEFAULT_NRC_TTL, DEFAULT_REFRESH, DEFAULT_RETRY,
        DEFAULT_SRV_PRIO, DEFAULT_SRV_WEIGHT, DEFAULT_TTL, DEFAULT_WITH_PTR,
    },
    record::ARecord,
};

#[derive(Debug, Default)]
pub struct TTL(pub u32);

impl<'de> Deserialize<'de> for TTL {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct TTLVisitor;

        impl<'de> Visitor<'de> for TTLVisitor {
            type Value = TTL;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a positive TTL value (1-2147483647)")
            }

            fn visit_u32<E>(self, value: u32) -> Result<TTL, E>
            where
                E: de::Error,
            {
                if value == 0 {
                    return Err(E::custom("TTL cannot be zero"));
                }
                if value > 2147483647 {
                    return Err(E::custom("TTL too large (max 2147483647)"));
                }
                Ok(TTL(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<TTL, E>
            where
                E: de::Error,
            {
                if value > 2147483647 {
                    return Err(E::custom("TTL too large (max 2147483647)"));
                }
                self.visit_u32(value as u32)
            }

            fn visit_i64<E>(self, value: i64) -> Result<TTL, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    return Err(E::custom("TTL cannot be negative"));
                }
                self.visit_u32(value as u32)
            }
        }

        deserializer.deserialize_u32(TTLVisitor)
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameserverEntry {
    pub name: String,
    pub ttl: Option<TTL>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MxEntry {
    pub name: String,
    pub prio: Option<u16>,
    pub ttl: Option<TTL>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    pub ip: SingleOrVecValue<IpAddr>,
    pub alias: Option<SingleOrVecValue<String>>,
    pub ttl: Option<TTL>,
    #[serde(rename = "with-ptr")]
    pub with_ptr: Option<bool>,
}

#[derive(Debug)]
pub enum HostValue {
    Ip(SingleOrVecValue<IpAddr>),
    Entry(HostEntry),
}

impl<'de> Deserialize<'de> for HostValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        struct HostValueVisitor;

        impl<'de> Visitor<'de> for HostValueVisitor {
            type Value = HostValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter
                    .write_str("an IP address, array of IP addresses, or object with 'ip' field")
            }

            fn visit_str<E>(self, v: &str) -> Result<HostValue, E>
            where
                E: de::Error,
            {
                v.parse::<IpAddr>()
                    .map(|ip| HostValue::Ip(SingleOrVecValue::Single(ip)))
                    .map_err(|_| E::custom(format!("'{}' is not a valid IP address", v)))
            }

            fn visit_seq<V>(self, seq: V) -> Result<HostValue, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let ips = Vec::<IpAddr>::deserialize(de::value::SeqAccessDeserializer::new(seq))
                    .map_err(|e| {
                        de::Error::custom(format!(
                            "Expected array of IP addresses, but got invalid values: {}",
                            e
                        ))
                    })?;
                Ok(HostValue::Ip(SingleOrVecValue::Multiple(ips)))
            }

            fn visit_map<M>(self, map: M) -> Result<HostValue, M::Error>
            where
                M: MapAccess<'de>,
            {
                HostEntry::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(HostValue::Entry)
                    .map_err(|e| de::Error::custom(format!("Invalid host entry object: {}", e)))
            }
        }

        deserializer.deserialize_any(HostValueVisitor)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CnameEntry {
    pub target: String,
    pub ttl: Option<TTL>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SrvEntry {
    pub target: String,
    pub port: u16,
    pub ttl: Option<TTL>,
    pub prio: Option<u16>,
    pub weight: Option<u16>,
}

// Wrapper für Email-Validierung mit besseren Fehlermeldungen
#[derive(Debug, Clone)]
pub struct Email(pub String);

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct EmailVisitor;

        impl<'de> Visitor<'de> for EmailVisitor {
            type Value = Email;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid email address (user@example.com)")
            }

            fn visit_str<E>(self, value: &str) -> Result<Email, E>
            where
                E: de::Error,
            {
                validate_email(value)
                    .map(|_| Email(value.to_string()))
                    .map_err(|e| E::custom(format!("Invalid email: {}", e)))
            }
        }

        deserializer.deserialize_str(EmailVisitor)
    }
}

// Wrapper für bessere Fehlermeldungen bei SRV-Einträgen
#[derive(Debug)]
pub struct SrvMap(pub HashMap<String, SrvEntry>);

impl<'de> Deserialize<'de> for SrvMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct SrvMapVisitor;

        impl<'de> Visitor<'de> for SrvMapVisitor {
            type Value = SrvMap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map of service names to SRV record entries")
            }

            fn visit_map<M>(self, mut map: M) -> Result<SrvMap, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut entries = HashMap::new();
                let mut index = 0;
                while let Some(key) = map.next_key::<String>()? {
                    index += 1;
                    // Validiere den SRV-Namen bereits beim Deserialisieren
                    let parts: Vec<&str> = key.split('.').collect();

                    if parts.len() < 2 {
                        return Err(de::Error::custom(format!(
                            "SRV entry #{} '{}': must have at least service and protocol (e.g., '_http._tcp')",
                            index, key
                        )));
                    }

                    if !parts[0].starts_with('_') {
                        return Err(de::Error::custom(format!(
                            "SRV entry #{} '{}': service name '{}' must start with '_' (e.g., '_http')",
                            index, key, parts[0]
                        )));
                    }

                    if !parts[1].starts_with('_') {
                        return Err(de::Error::custom(format!(
                            "SRV entry #{} '{}': protocol name '{}' must start with '_' (e.g., '_tcp')",
                            index, key, parts[1]
                        )));
                    }

                    match map.next_value::<SrvEntry>() {
                        Ok(entry) => {
                            entries.insert(key, entry);
                        }
                        Err(e) => {
                            return Err(de::Error::custom(format!(
                                "SRV entry #{} '{}': {} (expected object with 'target' and 'port' fields)",
                                index, key, e
                            )));
                        }
                    }
                }
                Ok(SrvMap(entries))
            }
        }

        deserializer.deserialize_map(SrvMapVisitor)
    }
}

#[derive(Debug)]
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

impl<'de, T> Deserialize<'de> for StringOrTableValue<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct StringOrTableVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for StringOrTableVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = StringOrTableValue<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or object")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StringOrTableValue::Entry(v.to_string()))
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                T::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(StringOrTableValue::Table)
                    .map_err(|e| de::Error::custom(format!("Invalid object: {}", e)))
            }
        }

        deserializer.deserialize_any(StringOrTableVisitor(std::marker::PhantomData))
    }
}

#[derive(Debug)]
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

impl<'de, T> Deserialize<'de> for SingleOrVecValue<T>
where
    T: Deserialize<'de> + std::fmt::Debug,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, SeqAccess, Visitor};

        struct SingleOrVecVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for SingleOrVecVisitor<T>
        where
            T: Deserialize<'de> + std::fmt::Debug,
        {
            type Value = SingleOrVecValue<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a single value or array of values")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match T::deserialize(de::value::StrDeserializer::<E>::new(v)) {
                    Ok(val) => Ok(SingleOrVecValue::Single(val)),
                    Err(e) => Err(E::custom(format!("Invalid value '{}': {}", v, e))),
                }
            }

            fn visit_seq<V>(self, seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                match Vec::<T>::deserialize(de::value::SeqAccessDeserializer::new(seq)) {
                    Ok(vals) => Ok(SingleOrVecValue::Multiple(vals)),
                    Err(e) => Err(de::Error::custom(format!("Invalid array: {}", e))),
                }
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match T::deserialize(de::value::U64Deserializer::<E>::new(v)) {
                    Ok(val) => Ok(SingleOrVecValue::Single(val)),
                    Err(e) => Err(E::custom(format!("Invalid number {}: {}", v, e))),
                }
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match T::deserialize(de::value::I64Deserializer::<E>::new(v)) {
                    Ok(val) => Ok(SingleOrVecValue::Single(val)),
                    Err(e) => Err(E::custom(format!("Invalid number {}: {}", v, e))),
                }
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                match T::deserialize(de::value::MapAccessDeserializer::new(map)) {
                    Ok(val) => Ok(SingleOrVecValue::Single(val)),
                    Err(e) => Err(de::Error::custom(format!("Invalid object: {}", e))),
                }
            }
        }

        deserializer.deserialize_any(SingleOrVecVisitor(std::marker::PhantomData))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneBaseEntry {
    pub serial: Option<u32>,
    pub email: Option<String>,
    pub expire: Option<u32>,
    pub nameserver: Option<SingleOrVecValue<StringOrTableValue<NameserverEntry>>>,
    #[serde(rename = "nrc-ttl")]
    pub nrc_ttl: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub ttl: Option<TTL>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseEntry {
    #[serde(flatten)]
    pub base: ZoneBaseEntry,
}

#[derive(Debug)]
pub enum ReverseValue {
    Net(SingleOrVecValue<IpNetwork>),
    Entry(HashMap<IpNetwork, ReverseEntry>),
}

impl<'de> Deserialize<'de> for ReverseValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        struct ReverseValueVisitor;

        impl<'de> Visitor<'de> for ReverseValueVisitor {
            type Value = ReverseValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a network string (e.g. '192.168.0.0/16'), array of networks, or map of networks to reverse zone entries")
            }

            fn visit_str<E>(self, v: &str) -> Result<ReverseValue, E>
            where
                E: de::Error,
            {
                match v.parse::<IpNetwork>() {
                    Ok(net) => Ok(ReverseValue::Net(SingleOrVecValue::Single(net))),
                    Err(e) => Err(E::custom(format!(
                        "'{}' is not a valid IP network: {}",
                        v, e
                    ))),
                }
            }

            fn visit_seq<V>(self, seq: V) -> Result<ReverseValue, V::Error>
            where
                V: SeqAccess<'de>,
            {
                match Vec::<IpNetwork>::deserialize(de::value::SeqAccessDeserializer::new(seq)) {
                    Ok(nets) => Ok(ReverseValue::Net(SingleOrVecValue::Multiple(nets))),
                    Err(e) => Err(de::Error::custom(format!(
                        "Invalid network array - expected IP networks like '192.168.0.0/16': {}",
                        e
                    ))),
                }
            }

            fn visit_map<V>(self, map: V) -> Result<ReverseValue, V::Error>
            where
                V: MapAccess<'de>,
            {
                match HashMap::<IpNetwork, ReverseEntry>::deserialize(
                    de::value::MapAccessDeserializer::new(map),
                ) {
                    Ok(entries) => Ok(ReverseValue::Entry(entries)),
                    Err(e) => Err(de::Error::custom(format!(
                        "Invalid reverse zone map: {}",
                        e
                    ))),
                }
            }
        }

        deserializer.deserialize_any(ReverseValueVisitor)
    }
}

#[derive(Debug)]
pub enum Zones {
    Map(HashMap<String, ZoneWithoutName>),
    Array(Vec<Zone>),
}

impl<'de> Deserialize<'de> for Zones {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        struct ZonesVisitor;

        impl<'de> Visitor<'de> for ZonesVisitor {
            type Value = Zones;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter
                    .write_str("a map of zones {name: {...}} or array of zones with 'name' field")
            }

            fn visit_seq<V>(self, seq: V) -> Result<Zones, V::Error>
            where
                V: SeqAccess<'de>,
            {
                match Vec::<Zone>::deserialize(de::value::SeqAccessDeserializer::new(seq)) {
                    Ok(zones) => Ok(Zones::Array(zones)),
                    Err(e) => Err(de::Error::custom(format!(
                        "Invalid zone array - each zone must have a 'name' field: {}",
                        e
                    ))),
                }
            }

            fn visit_map<V>(self, map: V) -> Result<Zones, V::Error>
            where
                V: MapAccess<'de>,
            {
                match HashMap::<String, ZoneWithoutName>::deserialize(
                    de::value::MapAccessDeserializer::new(map),
                ) {
                    Ok(zones) => Ok(Zones::Map(zones)),
                    Err(e) => Err(de::Error::custom(format!("Invalid zone map: {}", e))),
                }
            }
        }

        deserializer.deserialize_any(ZonesVisitor)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Content {
    #[serde(default = "RawDefaults::default")]
    pub defaults: RawDefaults,
    pub reverse: Option<ReverseValue>,
    pub zone: Option<Zones>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default = "RawDefaults::default")]
#[serde(deny_unknown_fields)]
pub struct RawDefaults {
    pub serial: Option<u32>,
    pub email: Option<Email>,
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
    pub ttl: TTL,
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
            ttl: TTL(DEFAULT_TTL),
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
            Some(validated_email) => Some(parse_email(&validated_email.0)?),
            None => None,
        };
        let nameserver = raw
            .nameserver
            .map(SingleOrVecValue::to_vec)
            .unwrap_or_default();

        for ns_entry in &nameserver {
            validate_dns_name(ns_entry)?
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
            ttl: raw.ttl.0,
            with_ptr: raw.with_ptr,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    #[serde(flatten)]
    pub base: ZoneBaseEntry,
    pub name: String,
    pub mx: Option<SingleOrVecValue<StringOrTableValue<MxEntry>>>,
    #[serde(rename = "mx-prio")]
    pub mx_prio: Option<u16>,
    #[serde(rename = "srv-prio")]
    pub srv_prio: Option<u16>,
    #[serde(rename = "srv-weight")]
    pub srv_weight: Option<u16>,
    #[serde(rename = "with-ptr")]
    pub with_ptr: Option<bool>,

    pub hosts: Option<std::collections::HashMap<String, HostValue>>,
    pub cname: Option<std::collections::HashMap<String, StringOrTableValue<CnameEntry>>>,
    pub srv: Option<SrvMap>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneWithoutName {
    #[serde(flatten)]
    pub base: ZoneBaseEntry,
    pub mx: Option<SingleOrVecValue<StringOrTableValue<MxEntry>>>,
    #[serde(rename = "mx-prio")]
    pub mx_prio: Option<u16>,
    #[serde(rename = "srv-prio")]
    pub srv_prio: Option<u16>,
    #[serde(rename = "srv-weight")]
    pub srv_weight: Option<u16>,
    #[serde(rename = "with-ptr")]
    pub with_ptr: Option<bool>,

    pub hosts: Option<std::collections::HashMap<String, HostValue>>,
    pub cname: Option<std::collections::HashMap<String, StringOrTableValue<CnameEntry>>>,
    pub srv: Option<SrvMap>,
}
impl ZoneWithoutName {
    pub fn with_name(self, name: String) -> Zone {
        Zone {
            base: self.base,
            name,
            mx: self.mx,
            mx_prio: self.mx_prio,
            srv_prio: self.srv_prio,
            srv_weight: self.srv_weight,
            with_ptr: self.with_ptr,
            hosts: self.hosts,
            cname: self.cname,
            srv: self.srv, // Beide nutzen jetzt SrvMap
        }
    }
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

fn extract_location(error_msg: &str) -> String {
    // Extrahiere das ERSTE "at line X column Y" aus der Fehlermeldung
    // Das ist die spezifischste Position
    if let Some(pos) = error_msg.find("at line ") {
        let rest = &error_msg[pos..];
        // Finde das Ende dieser Location (entweder " at line " oder Ende des Strings)
        if let Some(next_at) = rest[8..].find(" at line ") {
            // Es gibt noch ein weiteres "at line", nimm nur bis dahin
            return format!(" ({})", rest[..8 + next_at].trim());
        } else if let Some(newline) = rest.find('\n') {
            // Nimm bis zum Newline
            return format!(" ({})", rest[..newline].trim());
        } else {
            // Nimm den Rest, aber maximal ~50 Zeichen
            let end = rest.len().min(50);
            return format!(" ({})", rest[..end].trim());
        }
    }
    String::new()
}

pub fn parse(
    raw: &str,
    serial: u32,
    input_format: InputFormat,
) -> Result<(Vec<ForwardZone>, Vec<ReverseZone>)> {
    let content: Content = match input_format {
        #[cfg(feature = "toml")]
        InputFormat::Toml => {
            let deserializer = toml::Deserializer::new(raw);
            serde_path_to_error::deserialize(deserializer).map_err(|e| {
                let inner_err = e.inner().to_string();
                // Versuche Zeile/Spalte aus der Fehlermeldung zu extrahieren
                let location = extract_location(&inner_err);
                anyhow!(
                    "TOML parse error:\n  Path:  '{}'\n. Location: {}\n. Error: {}",
                    e.path(),
                    location.trim_start_matches(" (").trim_end_matches(")"),
                    inner_err
                )
            })?
        }
        #[cfg(feature = "yaml")]
        InputFormat::Yaml => {
            let deserializer = serde_yml::Deserializer::from_str(raw);
            serde_path_to_error::deserialize(deserializer).map_err(|e| {
                let inner_err = e.inner().to_string();
                let location = extract_location(&inner_err);
                anyhow!(
                    "YAML parse error:\n  Path:  '{}'\n. Location: {}\n. Error: {}",
                    e.path(),
                    location.trim_start_matches(" (").trim_end_matches(")"),
                    inner_err
                )
            })?
        }
    };

    let defaults: SessionDefaults = SessionDefaults::from_raw(content.defaults, serial)?;

    let mut ips: HashMap<IpAddr, PtrRecord> = HashMap::new();
    let zones = match content.zone {
        Some(Zones::Array(a)) => a,
        Some(Zones::Map(m)) => m
            .into_iter()
            .map(|(name, zwn)| zwn.with_name(name))
            .collect(),
        None => Vec::new(),
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== TTL Tests ====================

    #[test]
    #[cfg(feature = "yaml")]
    fn test_ttl_deserialize_valid() {
        let yaml = "1";
        let ttl: TTL = serde_yml::from_str(yaml).unwrap();
        assert_eq!(ttl.0, 1);

        let yaml = "3600";
        let ttl: TTL = serde_yml::from_str(yaml).unwrap();
        assert_eq!(ttl.0, 3600);

        let yaml = "2147483647";
        let ttl: TTL = serde_yml::from_str(yaml).unwrap();
        assert_eq!(ttl.0, 2147483647);
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_ttl_deserialize_zero() {
        let yaml = "0";
        let result: Result<TTL, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("TTL cannot be zero"));
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_ttl_deserialize_too_large() {
        let yaml = "2147483648";
        let result: Result<TTL, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("TTL too large"));
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_ttl_deserialize_negative() {
        let yaml = "-1";
        let result: Result<TTL, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
        // YAML gibt einen Type Error für negative Zahlen bei u32
        // Das ist auch ein korrekter Fehler
    }

    #[test]
    #[cfg(feature = "toml")]
    fn test_ttl_deserialize_from_toml() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Config {
            ttl: TTL,
        }

        let toml = "ttl = 10800";
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.ttl.0, 10800);
    }

    #[test]
    #[cfg(feature = "toml")]
    fn test_ttl_deserialize_from_toml_error() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Config {
            ttl: TTL,
        }

        let toml = "ttl = 0";
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    // ==================== Email Tests ====================

    #[test]
    #[cfg(feature = "yaml")]
    fn test_email_deserialize_valid() {
        let yaml = "\"admin@example.com\"";
        let email: Email = serde_yml::from_str(yaml).unwrap();
        assert_eq!(email.0, "admin@example.com");

        let yaml = "\"test+tag@sub.example.com\"";
        let email: Email = serde_yml::from_str(yaml).unwrap();
        assert_eq!(email.0, "test+tag@sub.example.com");

        let yaml = "\"user_name@example.co.uk\"";
        let email: Email = serde_yml::from_str(yaml).unwrap();
        assert_eq!(email.0, "user_name@example.co.uk");
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_email_deserialize_missing_at() {
        let yaml = "\"admin.example.com\"";
        let result: Result<Email, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("must contain '@'"));
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_email_deserialize_invalid_local_part() {
        // Starts with dot
        let yaml = "\".user@example.com\"";
        let result: Result<Email, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());

        // Ends with dot
        let yaml = "\"user.@example.com\"";
        let result: Result<Email, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());

        // Consecutive dots
        let yaml = "\"user..name@example.com\"";
        let result: Result<Email, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_email_deserialize_invalid_domain() {
        // No dot in domain
        let yaml = "\"user@example\"";
        let result: Result<Email, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("must contain at least one dot"));

        // TLD all numeric
        let yaml = "\"user@example.123\"";
        let result: Result<Email, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_email_deserialize_too_long() {
        // Total length > 254
        let long_email = format!("{}@example.com", "a".repeat(250));
        let yaml = format!("\"{}\"", long_email);
        let result: Result<Email, _> = serde_yml::from_str(&yaml);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("too long"));
    }

    #[test]
    #[cfg(feature = "toml")]
    fn test_email_deserialize_from_toml() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Config {
            email: Email,
        }

        let toml = "email = \"admin@example.com\"";
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.email.0, "admin@example.com");
    }

    #[test]
    #[cfg(feature = "toml")]
    fn test_email_deserialize_from_toml_error() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Config {
            email: Email,
        }

        let toml = "email = \"invalid-email\"";
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_email_deserialize_in_struct() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Defaults {
            email: Email,
            ttl: TTL,
        }

        let yaml = r#"
email: "admin@example.com"
ttl: 3600
"#;
        let defaults: Defaults = serde_yml::from_str(yaml).unwrap();
        assert_eq!(defaults.email.0, "admin@example.com");
        assert_eq!(defaults.ttl.0, 3600);
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_email_deserialize_in_struct_error() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Defaults {
            email: Email,
            ttl: TTL,
        }

        // Invalid email
        let yaml = r#"
email: "not-an-email"
ttl: 3600
"#;
        let result: Result<Defaults, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());

        // Invalid TTL
        let yaml = r#"
email: "admin@example.com"
ttl: 0
"#;
        let result: Result<Defaults, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
    }
}
