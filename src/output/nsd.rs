use std::cmp::{max, Ordering};
use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::path::Path;

use crate::output::NSD_COLUMN_WIDTH;
use crate::parser::ZoneBase;
use crate::transform::ip_name;

fn nsd_format(
    value: &str,
    record_ttl: u32,
    zone_ttl: u32,
    record_type: &str,
    data: &str,
) -> String {
    let space = NSD_COLUMN_WIDTH as i32;
    let uspace = space as usize;
    let ttl = if record_ttl == zone_ttl {
        String::new()
    } else {
        record_ttl.to_string()
    };
    let value_ttl = if record_ttl == zone_ttl {
        format!("{value:width$}", width = (uspace - 1))
    } else {
        format!("{value:width$} {ttl}", width = (uspace - ttl.len() - 2))
    };
    let value_ttl_len = value_ttl.len() as i32;
    let type_len = max(0, 7 - (max(0, value_ttl_len - space - 1))) as usize;
    format!(
        "{value_ttl} {record_type:width$} {data}\n",
        width = type_len
    )
}

fn write_soa(base: &ZoneBase) -> String {
    let mut output = String::new();
    let indent = " ".repeat(NSD_COLUMN_WIDTH);
    let ns = &base
        .nameserver
        .first()
        .expect("Zone needs one nameserver")
        .name;
    let name = base.name.as_str();
    let email = base.email.as_str();
    let serial = base.serial;
    let refresh = base.refresh;
    let retry = base.retry;
    let expire = base.expire;
    let ttl = base.ttl;
    let nrc_ttl = base.nrc_ttl;

    writeln!(output, "$ORIGIN {name}").unwrap();
    writeln!(output, "$TTL {ttl}").unwrap();
    writeln!(output).unwrap();

    writeln!(
        output,
        "@                            IN SOA     {ns} {email} (",
    )
    .unwrap();
    writeln!(output, "{indent}           {serial:<12}; serial number").unwrap();
    writeln!(output, "{indent}           {refresh:<12}; refresh").unwrap();
    writeln!(output, "{indent}           {retry:<12}; retry").unwrap();
    writeln!(output, "{indent}           {expire:<12}; expire").unwrap();
    writeln!(output, "{indent}           {nrc_ttl:<12}; min ttl").unwrap();
    writeln!(output, "{indent}        )").unwrap();

    for ns in &base.nameserver {
        output.push_str(&nsd_format("", ns.ttl, ttl, "NS", &ns.name));
    }

    output
}

fn strip_name(name: &str, zone_name: &str) -> String {
    if name == zone_name {
        "@".to_string()
    } else {
        name.strip_suffix(&format!(".{zone_name}"))
            .unwrap_or(name)
            .to_string()
    }
}

pub fn write_nsd(
    output_dir: &Path,
    forward: &[crate::parser::ForwardZone],
    reverse: &[crate::parser::ReverseZone],
) -> anyhow::Result<()> {
    let master_dir = output_dir.join("master");
    let master = master_dir.display();
    fs::create_dir_all(output_dir).or_else(
        |e| {
            if output_dir.is_dir() {
                Ok(())
            } else {
                Err(e)
            }
        },
    )?;
    fs::create_dir_all(&master_dir).or_else(
        |e| {
            if output_dir.is_dir() {
                Ok(())
            } else {
                Err(e)
            }
        },
    )?;

    let mut conf = String::new();
    let mut files: HashMap<String, String> = HashMap::new();

    for zone in forward {
        let zone_name = zone.base.name.as_str();
        let zone_ttl = zone.base.ttl;
        let mut output = String::new();

        writeln!(conf, "zone:").unwrap();
        writeln!(conf, "    name: {zone_name}").unwrap();
        writeln!(conf, "    zonefile: master/{zone_name}zone").unwrap();
        writeln!(conf).unwrap();

        output.push_str(&write_soa(&zone.base));

        for mx in &zone.mx {
            let record_type = format!("MX {:>4}", mx.prio);
            output.push_str(&nsd_format("", mx.ttl, zone_ttl, &record_type, &mx.name));
        }

        let mut a_records: Vec<_> = zone.hosts.iter().collect();
        a_records.sort_unstable_by(|a, b| {
            // Special order for zone apex "@"
            let a_is_apex = a.name == zone_name;
            let b_is_apex = b.name == zone_name;

            match (a_is_apex, b_is_apex) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => {
                    let ncmp = a.name.cmp(&b.name);
                    if ncmp == Ordering::Equal {
                        a.ip.cmp(&b.ip)
                    } else {
                        ncmp
                    }
                }
            }
        });

        let mut hostname = "".to_string();
        for record in a_records {
            let name = strip_name(&record.name, zone_name);
            let record_name = if hostname == name {
                ""
            } else {
                hostname = name.clone();
                &hostname
            };
            let record_type = if record.ip.is_ipv4() { "A" } else { "AAAA" };

            output.push_str(&nsd_format(
                record_name,
                record.ttl,
                zone_ttl,
                record_type,
                &record.ip.to_string(),
            ));
        }

        for srv in &zone.srv {
            let data = format!("{} {} {} {}", srv.prio, srv.weight, srv.port, &srv.target);
            let name = strip_name(&srv.name, zone_name);
            output.push_str(&nsd_format(&name, srv.ttl, zone_ttl, "SRV", &data));
        }

        for cname in &zone.cname {
            let name = strip_name(&cname.name, zone_name);
            output.push_str(&nsd_format(
                &name,
                cname.ttl,
                zone_ttl,
                "CNAME",
                &cname.target,
            ));
        }

        files.insert(format!("{master}/{zone_name}zone"), output);
    }

    for zone in reverse {
        let zone_name = zone.base.name.as_str();
        let zone_ttl = zone.base.ttl;
        let mut output = String::new();

        writeln!(conf, "zone:").unwrap();
        writeln!(conf, "    name: {zone_name}").unwrap();
        writeln!(conf, "    zonefile: master/{zone_name}zone").unwrap();
        writeln!(conf).unwrap();

        let soa = write_soa(&zone.base);
        output.push_str(&soa);

        let mut ptrs: Vec<_> = zone.ptr.iter().collect();
        ptrs.sort_by(|a, b| a.ip.cmp(&b.ip));
        for ptr in ptrs {
            let ip_entry = ip_name(&ptr.ip, zone.split);
            output.push_str(&nsd_format(&ip_entry, ptr.ttl, zone_ttl, "PTR", &ptr.name));
        }

        files.insert(format!("{master}/{zone_name}zone"), output);
    }

    fs::write(output_dir.join("zones.conf"), conf)?;

    for (path, content) in files {
        fs::write(path, content)?;
    }

    Ok(())
}
