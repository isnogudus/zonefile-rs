use std::fmt::Write;

use crate::output::UNBOUND_COLUMN_WIDTH;

fn format_ttl(record_ttl: u32, zone_ttl: u32) -> String {
    if record_ttl == zone_ttl {
        String::new()
    } else {
        record_ttl.to_string()
    }
}

pub fn generate_unbound(
    forward: &[crate::parser::ForwardZone],
    reverse: &[crate::parser::ReverseZone],
) -> String {
    let mut output = String::new();

    writeln!(output, "server:").unwrap();

    for zone in forward {
        let zone_name = zone.base.name.as_str();
        let zone_ttl = zone.base.ttl;
        writeln!(output, "local-zone:  {} static", zone_name).unwrap();
        let ttl = zone.base.ttl.to_string();
        let nameserver = &zone
            .base
            .nameserver
            .first()
            .expect("Zone needs one nameserver")
            .name;
        let email = &zone.base.email;
        let retry = zone.base.retry;
        let refresh = zone.base.refresh;
        let serial = zone.base.serial;
        let expire = zone.base.expire;
        let nrc_ttl = zone.base.nrc_ttl;
        writeln!(output, r#"local-data: "{zone_name:width$} {ttl} IN SOA  {nameserver} {email} {serial} {refresh} {retry} {expire} {nrc_ttl}""#, width=UNBOUND_COLUMN_WIDTH-ttl.len()).unwrap();

        for ns in &zone.base.nameserver {
            let ttl = format_ttl(ns.ttl, zone_ttl);
            let name = &ns.name;
            writeln!(
                output,
                r#"local-data: "{zone_name:width$} {ttl} IN NS   {name}""#,
                width = UNBOUND_COLUMN_WIDTH - ttl.len()
            )
            .unwrap();
        }

        for mx in &zone.mx {
            let ttl = format_ttl(mx.ttl, zone_ttl);
            let name = &mx.name;
            let prio = &mx.prio;
            writeln!(
                output,
                r#"local-data: "{zone_name:width$} {ttl} IN MX   {prio} {name}""#,
                width = UNBOUND_COLUMN_WIDTH - ttl.len()
            )
            .unwrap();
        }

        let mut hosts: Vec<_> = zone.hosts.iter().collect();

        hosts.sort_by(|a, b| a.name.cmp(&b.name));
        for host in hosts {
            let ttl = format_ttl(host.ttl, zone_ttl);
            let name = &host.name;
            let ip = &host.ip;
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    writeln!(
                        output,
                        r#"local-data: "{name:width$} {ttl} IN A    {ipv4}""#,
                        width = UNBOUND_COLUMN_WIDTH - ttl.len()
                    )
                    .unwrap();
                }
                std::net::IpAddr::V6(ipv6) => {
                    writeln!(
                        output,
                        r#"local-data: "{name:width$} {ttl} IN AAAA {ipv6}""#,
                        width = UNBOUND_COLUMN_WIDTH - ttl.len()
                    )
                    .unwrap();
                }
            }
        }

        for srv in &zone.srv {
            let ttl = format_ttl(srv.ttl, zone_ttl);
            let name = &srv.name;
            let prio = &srv.prio;
            let weight = &srv.weight;
            let port = &srv.port;
            let target = &srv.target;
            writeln!(
                output,
                r#"local-data: "{name:width$} {ttl} IN SRV  {prio} {weight} {port} {target}""#,
                width = UNBOUND_COLUMN_WIDTH - ttl.len()
            )
            .unwrap();
        }

        for cname in &zone.cname {
            let ttl = format_ttl(cname.ttl, zone_ttl);
            let name = &cname.name;
            let target = &cname.target;
            writeln!(
                output,
                r#"local-data: "{name:width$} {ttl} CNAME   {target}""#,
                width = UNBOUND_COLUMN_WIDTH - ttl.len()
            )
            .unwrap();
        }

        output.push_str("\n");
    }

    for zone in reverse {
        let zone_name = zone.base.name.as_str();
        writeln!(output, "local-zone:      {} static", zone_name).unwrap();
        let zone_ttl = zone.base.ttl;
        let ttl = zone_ttl.to_string();
        let nameserver = &zone
            .base
            .nameserver
            .first()
            .expect("Zone needs one nameserver")
            .name;
        let email = &zone.base.email;
        let retry = zone.base.retry;
        let refresh = zone.base.refresh;
        let serial = zone.base.serial;
        let expire = zone.base.expire;
        let nrc_ttl = zone.base.nrc_ttl;
        writeln!(output, r#"local-data:     "{zone_name:width$} {ttl} IN SOA  {nameserver} {email} {serial} {refresh} {retry} {expire} {nrc_ttl}""#, width=UNBOUND_COLUMN_WIDTH-ttl.len()).unwrap();

        for ns in &zone.base.nameserver {
            let ttl = format_ttl(ns.ttl, zone_ttl);
            let name = &ns.name;
            writeln!(
                output,
                r#"local-data:     "{zone_name:width$} {ttl} IN NS   {name}""#,
                width = UNBOUND_COLUMN_WIDTH - ttl.len()
            )
            .unwrap();
        }

        let mut ptrs: Vec<_> = zone.ptr.iter().collect();
        ptrs.sort_by(|a, b| a.ip.cmp(&b.ip));
        for ptr in ptrs {
            let ttl = format_ttl(ptr.ttl, zone_ttl);
            let name = &ptr.name;
            let ip = ptr.ip;
            writeln!(
                output,
                r#"local-data-ptr: "{ip:width$} {ttl} {name}""#,
                width = UNBOUND_COLUMN_WIDTH - ttl.len()
            )
            .unwrap();
        }

        output.push_str("\n");
    }
    output
}
