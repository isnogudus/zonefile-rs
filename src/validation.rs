use anyhow::{bail, Result};

pub fn validate_dns_name(name: &str) -> Result<()> {
    if name.len() > 253 {
        bail!("DNS name too long (max 253 chars): {name}")
    }
    if !name.ends_with(".") {
        bail!("Host must be fully qualified: {name}")
    }
    let labels = name.trim_end_matches(".").split(".");
    for (i, label) in labels.enumerate() {
        if label.is_empty() {
            bail!("DNS name has empty label: {name}")
        }
        if label.len() > 63 {
            bail!("DNS label too long (max 63 chars): {label}")
        }
        if label.contains("*") {
            if i != 0 {
                bail!("Wildcard '*' must be leftmost label, got: {name}")
            }
            if label != "*" {
                bail!("Wildcard '*' must be entire label, got: {label}")
            }
            continue;
        }
        if label.starts_with("-") || label.ends_with("-") {
            bail!("DNS label cannot start/end with hyphen: {label}")
        }
        if !label
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            bail!("DNS label has invalid characters: {label}")
        }
    }

    Ok(())
}

pub fn validate_email(email: &str) -> Result<()> {
    if !email.ends_with(".") {
        bail!("Email has to end with a dot, got: {email}")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dns_name_valid() {
        assert!(validate_dns_name("example.com.").is_ok());
        assert!(validate_dns_name("sub.example.com.").is_ok());
        assert!(validate_dns_name("a.b.c.d.example.com.").is_ok());
        assert!(validate_dns_name("host-name.example.com.").is_ok());
        assert!(validate_dns_name("host_name.example.com.").is_ok());
        assert!(validate_dns_name("123.example.com.").is_ok());
    }

    #[test]
    fn test_validate_dns_name_wildcard() {
        assert!(validate_dns_name("*.example.com.").is_ok());
        assert!(validate_dns_name("*.sub.example.com.").is_ok());
    }

    #[test]
    fn test_validate_dns_name_wildcard_invalid() {
        assert!(validate_dns_name("sub.*.example.com.").is_err());
        assert!(validate_dns_name("*sub.example.com.").is_err());
        assert!(validate_dns_name("sub*.example.com.").is_err());
    }

    #[test]
    fn test_validate_dns_name_missing_dot() {
        assert!(validate_dns_name("example.com").is_err());
        assert!(validate_dns_name("sub.example.com").is_err());
    }

    #[test]
    fn test_validate_dns_name_too_long() {
        let long_name = "a".repeat(250) + ".com.";
        assert!(validate_dns_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_dns_name_label_too_long() {
        let long_label = "a".repeat(64) + ".example.com.";
        assert!(validate_dns_name(&long_label).is_err());
    }

    #[test]
    fn test_validate_dns_name_empty_label() {
        assert!(validate_dns_name("..example.com.").is_err());
        assert!(validate_dns_name("sub..example.com.").is_err());
    }

    #[test]
    fn test_validate_dns_name_hyphen() {
        assert!(validate_dns_name("va-lid.example.com.").is_ok());
        assert!(validate_dns_name("-invalid.example.com.").is_err());
        assert!(validate_dns_name("invalid-.example.com.").is_err());
    }

    #[test]
    fn test_validate_dns_name_invalid_chars() {
        assert!(validate_dns_name("in valid.example.com.").is_err());
        assert!(validate_dns_name("in@valid.example.com.").is_err());
        assert!(validate_dns_name("in!valid.example.com.").is_err());
    }

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("admin.example.com.").is_ok());
        assert!(validate_email("john\\.doe.example.com.").is_ok());
    }

    #[test]
    fn test_validate_email_missing_dot() {
        assert!(validate_email("admin.example.com").is_err());
    }
}
