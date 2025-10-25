use std::net::IpAddr;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ARecord {
    pub name: String,
    pub ip: IpAddr,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrRecord {
    pub name: String,
    pub ip: IpAddr,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsRecord {
    pub name: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub name: String,
    pub ttl: u32,
    pub prio: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameRecord {
    pub name: String,
    pub target: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub name: String,
    pub target: String,
    pub ttl: u32,
    pub prio: u16,
    pub weight: u16,
    pub port: u16,
}
