#[cfg(any(feature = "toml", feature = "yaml"))]
use std::fs;
#[cfg(any(feature = "toml", feature = "yaml"))]
use zonefile_rs::{args::InputFormat, parser::parse};

#[test]
#[cfg(feature = "toml")]
fn test_parse_zones_toml() {
    let content: String = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let result = parse(&content, 2025012500, InputFormat::Toml);

    assert!(
        result.is_ok(),
        "Failed to parse zones.toml: {:?}",
        result.err()
    );

    let (forward, reverse) = result.unwrap();

    // Verify we have zones
    assert!(!forward.is_empty(), "No forward zones parsed");
    assert!(!reverse.is_empty(), "No reverse zones parsed");

    // Check specific zones exist
    let zone_names: Vec<&str> = forward.iter().map(|z| z.base.name.as_str()).collect();
    assert!(zone_names.contains(&"example.com."));
    assert!(zone_names.contains(&"unifi."));
    assert!(zone_names.contains(&"iot.example.com."));
    assert!(zone_names.contains(&"devices.example.com."));
    assert!(zone_names.contains(&"cluster.example.com."));
}

#[test]
#[cfg(feature = "toml")]
fn test_example_com_zone() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Toml).unwrap();

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
    let router_records: Vec<_> = example_com
        .hosts
        .iter()
        .filter(|h| h.name == "router.example.com.")
        .collect();
    assert!(!router_records.is_empty(), "router host not found");

    // Check SRV records exist
    assert!(!example_com.srv.is_empty());
    let srv_names: Vec<&str> = example_com.srv.iter().map(|s| s.name.as_str()).collect();
    assert!(srv_names.iter().any(|n| n.contains("_mqtt._tcp")));
}

#[test]
#[cfg(feature = "toml")]
fn test_reverse_zones() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (_, reverse) = parse(&content, 2025012500, InputFormat::Toml).unwrap();

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
#[cfg(feature = "toml")]
fn test_wildcard_host() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Toml).unwrap();

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
#[cfg(feature = "toml")]
fn test_cname_records() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Toml).unwrap();

    let devices_zone = forward
        .iter()
        .find(|z| z.base.name == "devices.example.com.")
        .expect("devices.example.com zone not found");

    // Check CNAME records exist
    assert!(!devices_zone.cname.is_empty());

    let cnames: Vec<&str> = devices_zone.cname.iter().map(|c| c.name.as_str()).collect();
    assert!(cnames.contains(&"thermostat-office.devices.example.com."));
}

#[test]
#[cfg(feature = "toml")]
fn test_ipv6_addresses() {
    let content = fs::read_to_string("zones.toml").expect("Failed to read zones.toml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Toml).unwrap();

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
        .filter(|h| h.ip.is_ipv6() && h.name == "router.example.com.")
        .collect();
    assert!(!ipv6_hosts.is_empty(), "No IPv6 address for router");
}

// YAML Integration Tests

#[test]
#[cfg(feature = "yaml")]
fn test_parse_zones_yaml() {
    let content: String = fs::read_to_string("zones.yaml").expect("Failed to read zones.yaml");
    let result = parse(&content, 2025012500, InputFormat::Yaml);

    assert!(
        result.is_ok(),
        "Failed to parse zones.yaml: {:?}",
        result.err()
    );

    let (forward, reverse) = result.unwrap();

    // Verify we have zones
    assert!(!forward.is_empty(), "No forward zones parsed");
    assert!(!reverse.is_empty(), "No reverse zones parsed");

    // Check specific zones exist
    let zone_names: Vec<&str> = forward.iter().map(|z| z.base.name.as_str()).collect();
    assert!(zone_names.contains(&"example.com."));
    assert!(zone_names.contains(&"apps.example.com."));
}

#[test]
#[cfg(feature = "yaml")]
fn test_example_com_zone_yaml() {
    let content = fs::read_to_string("zones.yaml").expect("Failed to read zones.yaml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Yaml).unwrap();

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
    let router_records: Vec<_> = example_com
        .hosts
        .iter()
        .filter(|h| h.name == "router.example.com.")
        .collect();
    assert!(!router_records.is_empty(), "router host not found");

    // Check SRV records exist
    assert!(!example_com.srv.is_empty());
    let srv_names: Vec<&str> = example_com.srv.iter().map(|s| s.name.as_str()).collect();
    assert!(srv_names.iter().any(|n| n.contains("_mqtt._tcp")));
}

#[test]
#[cfg(feature = "yaml")]
fn test_reverse_zones_yaml() {
    let content = fs::read_to_string("zones.yaml").expect("Failed to read zones.yaml");
    let (_, reverse) = parse(&content, 2025012500, InputFormat::Yaml).unwrap();

    // Check we have both IPv4 and IPv6 reverse zones
    let has_ipv4 = reverse.iter().any(|z| z.base.name.contains("in-addr.arpa"));
    let has_ipv6 = reverse.iter().any(|z| z.base.name.contains("ip6.arpa"));

    assert!(has_ipv4, "No IPv4 reverse zones found");
    assert!(has_ipv6, "No IPv6 reverse zones found");

    // Check specific reverse zone (192.168.0.0/16)
    let reverse_192_168 = reverse
        .iter()
        .find(|z| z.base.name == "168.192.in-addr.arpa.")
        .expect("192.168.0.0/16 reverse zone not found");

    // Should have PTR records
    assert!(!reverse_192_168.ptr.is_empty());
}

#[test]
#[cfg(feature = "yaml")]
fn test_wildcard_host_yaml() {
    let content = fs::read_to_string("zones.yaml").expect("Failed to read zones.yaml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Yaml).unwrap();

    let apps_zone = forward
        .iter()
        .find(|z| z.base.name == "apps.example.com.")
        .unwrap();

    // Check wildcard record exists (docker host with alias "*")
    let wildcard = apps_zone
        .hosts
        .iter()
        .find(|h| h.name == "*.apps.example.com.");

    assert!(wildcard.is_some(), "Wildcard record not found");
}

#[test]
#[cfg(feature = "yaml")]
fn test_cname_records_yaml() {
    let content = fs::read_to_string("zones.yaml").expect("Failed to read zones.yaml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Yaml).unwrap();

    let apps_zone = forward
        .iter()
        .find(|z| z.base.name == "apps.example.com.")
        .expect("apps.example.com zone not found");

    // Check CNAME records exist
    assert!(!apps_zone.cname.is_empty());

    let cnames: Vec<&str> = apps_zone.cname.iter().map(|c| c.name.as_str()).collect();
    assert!(cnames.contains(&"addresses.apps.example.com."));
}

#[test]
#[cfg(feature = "yaml")]
fn test_ipv6_addresses_yaml() {
    let content = fs::read_to_string("zones.yaml").expect("Failed to read zones.yaml");
    let (forward, _) = parse(&content, 2025012500, InputFormat::Yaml).unwrap();

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
        .filter(|h| h.ip.is_ipv6() && h.name == "router.example.com.")
        .collect();
    assert!(!ipv6_hosts.is_empty(), "No IPv6 address for router");
}
