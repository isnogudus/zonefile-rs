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
    // Validiere normale Email-Adresse (user@example.com)
    if email.len() > 254 {
        bail!("Email too long (max 254 chars): {}", email);
    }

    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("Email must contain '@', got: {}", email))?;

    // Validiere local part (vor dem @)
    if local.is_empty() {
        bail!("Email local part (before @) cannot be empty");
    }
    if local.len() > 64 {
        bail!("Email local part too long (max 64 chars): {}", local);
    }
    if local.starts_with('.') || local.ends_with('.') {
        bail!("Email local part cannot start or end with '.': {}", local);
    }
    if local.contains("..") {
        bail!("Email local part cannot contain consecutive dots: {}", local);
    }
    if !local.chars().all(|c| {
        c.is_alphanumeric() || c == '.' || c == '+' || c == '-' || c == '_'
    }) {
        bail!("Email local part contains invalid characters: {}", local);
    }

    // Validiere domain part (nach dem @)
    if domain.is_empty() {
        bail!("Email domain (after @) cannot be empty");
    }
    if !domain.contains('.') {
        bail!("Email domain must contain at least one dot (e.g., 'example.com'): {}", domain);
    }

    // Validiere Domain-Labels
    let labels: Vec<&str> = domain.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            bail!("Email domain cannot have empty labels: {}", domain);
        }
        if label.len() > 63 {
            bail!("Email domain label too long (max 63 chars): {}", label);
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("Email domain label cannot start/end with hyphen: {}", label);
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            bail!("Email domain label contains invalid characters: {}", label);
        }
    }

    // TLD darf nicht nur Zahlen sein
    if let Some(tld) = labels.last() {
        if tld.chars().all(|c| c.is_numeric()) {
            bail!("Email domain TLD cannot be all numeric: {}", tld);
        }
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
        assert!(validate_email("admin@example.com").is_ok());
        assert!(validate_email("john.doe@example.com").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());
        assert!(validate_email("user_name@example.co.uk").is_ok());
        assert!(validate_email("test-user@sub.example.com").is_ok());
    }

    #[test]
    fn test_validate_email_missing_at() {
        assert!(validate_email("admin.example.com").is_err());
        assert!(validate_email("adminexample.com").is_err());
    }

    #[test]
    fn test_validate_email_invalid_local() {
        assert!(validate_email(".user@example.com").is_err()); // Starts with dot
        assert!(validate_email("user.@example.com").is_err()); // Ends with dot
        assert!(validate_email("user..name@example.com").is_err()); // Consecutive dots
        assert!(validate_email("user name@example.com").is_err()); // Space
        assert!(validate_email("user@name@example.com").is_err()); // Multiple @
    }

    #[test]
    fn test_validate_email_invalid_domain() {
        assert!(validate_email("user@example").is_err()); // No dot in domain
        assert!(validate_email("user@.example.com").is_err()); // Starts with dot
        assert!(validate_email("user@example..com").is_err()); // Consecutive dots
        assert!(validate_email("user@-example.com").is_err()); // Starts with hyphen
        assert!(validate_email("user@example-.com").is_err()); // Ends with hyphen
        assert!(validate_email("user@123").is_err()); // TLD all numeric
    }
}
