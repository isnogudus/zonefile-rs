use std::fs;
use zonefile_rs::parser::parse_toml;

#[test]
fn test_parse_zones_toml() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let result = parse_toml(&content, 2025012500);

    assert!(result.is_ok(), "Failed to parse zones.toml: {:?}", result.err());

    let (forward, reverse) = result.unwrap();

    // Verify we have zones
    assert!(!forward.is_empty(), "No forward zones parsed");
    assert!(!reverse.is_empty(), "No reverse zones parsed");

    // Check specific zones exist
    let zone_names: Vec<&str> = forward.iter().map(|z| z.base.name.as_str()).collect();
    assert!(zone_names.contains(&"example.com."));
    assert!(zone_names.contains(&"unifi."));
    assert!(zone_names.contains(&"haus.example.com."));
    assert!(zone_names.contains(&"smart.example.com."));
    assert!(zone_names.contains(&"grid.example.com."));
}

#[test]
fn test_example_com_zone() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse_toml(&content, 2025012500).unwrap();

    let example_com = forward
        .iter()
        .find(|z| z.base.name == "example.com.")
        .expect("example.com zone not found");

    // Check zone has nameservers
    assert!(!example_com.base.nameserver.is_empty());
    assert_eq!(example_com.base.nameserver[0].name, "ns1.example.com.");

    // Check MX records
    assert!(!example_com.mx.is_empty());

    // Check hosts
    assert!(!example_com.hosts.is_empty());

    // Check specific host exists
    let wopr_records: Vec<_> = example_com
        .hosts
        .iter()
        .filter(|h| h.name == "wopr.example.com.")
        .collect();
    assert!(!wopr_records.is_empty(), "wopr host not found");

    // Check SRV records exist
    assert!(!example_com.srv.is_empty());
    let srv_names: Vec<&str> = example_com.srv.iter().map(|s| s.name.as_str()).collect();
    assert!(srv_names.iter().any(|n| n.contains("_mqtt._tcp")));
}

#[test]
fn test_reverse_zones() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (_, reverse) = parse_toml(&content, 2025012500).unwrap();

    // Check we have both IPv4 and IPv6 reverse zones
    let has_ipv4 = reverse.iter().any(|z| z.base.name.contains("in-addr.arpa"));
    let has_ipv6 = reverse.iter().any(|z| z.base.name.contains("ip6.arpa"));

    assert!(has_ipv4, "No IPv4 reverse zones found");
    assert!(has_ipv6, "No IPv6 reverse zones found");

    // Check specific reverse zone
    let reverse_10_0_1 = reverse
        .iter()
        .find(|z| z.base.name == "1.0.10.in-addr.arpa.")
        .expect("10.0.1.0/24 reverse zone not found");

    // Should have PTR records
    assert!(!reverse_10_0_1.ptr.is_empty());
}

#[test]
fn test_wildcard_host() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse_toml(&content, 2025012500).unwrap();

    let example_com = forward
        .iter()
        .find(|z| z.base.name == "example.com.")
        .unwrap();

    // Check wildcard record exists
    let wildcard = example_com
        .hosts
        .iter()
        .find(|h| h.name == "*.example.com.");

    assert!(wildcard.is_some(), "Wildcard record not found");
}

#[test]
fn test_cname_records() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse_toml(&content, 2025012500).unwrap();

    let smart_zone = forward
        .iter()
        .find(|z| z.base.name == "smart.example.com.")
        .expect("smart.example.com zone not found");

    // Check CNAME records exist
    assert!(!smart_zone.cname.is_empty());

    let cnames: Vec<&str> = smart_zone.cname.iter().map(|c| c.name.as_str()).collect();
    assert!(cnames.contains(&"buero_markus_heizung.smart.example.com."));
}

#[test]
fn test_ipv6_addresses() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse_toml(&content, 2025012500).unwrap();

    let example_com = forward
        .iter()
        .find(|z| z.base.name == "example.com.")
        .unwrap();

    // Check that we have IPv6 addresses
    let has_ipv6 = example_com.hosts.iter().any(|h| h.ip.is_ipv6());
    assert!(has_ipv6, "No IPv6 addresses found");

    // Check specific IPv6 host
    let ipv6_hosts: Vec<_> = example_com
        .hosts
        .iter()
        .filter(|h| h.ip.is_ipv6() && h.name == "wopr.example.com.")
        .collect();
    assert!(!ipv6_hosts.is_empty(), "No IPv6 address for wopr");
}
