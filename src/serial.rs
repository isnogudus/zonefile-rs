use anyhow::Result;
use chrono::Datelike;
use chrono::Utc;
use std::cmp::max;
use std::fs;
use std::path::Path;

pub fn load_serial(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn calc_serial(old_serial: u32) -> u32 {
    let now = Utc::now();
    let year = now.year() as u32;
    let month = now.month();
    let day = now.day();

    max(
        old_serial + 1,
        year * 1_000_000 + month * 10_000 + day * 100,
    )
}

pub fn save_serial(path: &Path, serial: u32) -> Result<()> {
    fs::write(path, serial.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_serial_exists() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "2025012301").unwrap();

        let serial = load_serial(file.path());
        assert_eq!(serial, 2025012301);
    }

    #[test]
    fn test_load_serial_missing_file() {
        let serial = load_serial(Path::new("/nonexistent/file"));
        assert_eq!(serial, 0);
    }

    #[test]
    fn test_load_serial_invalid_content() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not a number").unwrap();

        let serial = load_serial(file.path());
        assert_eq!(serial, 0);
    }

    #[test]
    fn test_load_serial_with_whitespace() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  2025012301  ").unwrap();

        let serial = load_serial(file.path());
        assert_eq!(serial, 2025012301);
    }

    #[test]
    fn test_calc_serial_first_time() {
        let serial = calc_serial(0);
        // Serial should be at least YYYYMMDD00
        assert!(serial >= 2025000000);
        assert!(serial < 2026000000);
    }

    #[test]
    fn test_calc_serial_increment() {
        // Test that serial is always incremented when old is less than today
        let old = 2020012301; // Old date
        let new = calc_serial(old);
        // Should be at least old + 1, and at least today's date
        assert!(new > old);
        assert!(new >= 2025000000);
    }

    #[test]
    fn test_calc_serial_date_based() {
        // When old serial is from yesterday, new should be today's date
        let old = 2020010199; // Old date with high sequence
        let new = calc_serial(old);
        // New serial should be current date based (YYYYMMDD00)
        assert!(new >= 2025000000);
        assert!(new % 100 == 0); // Sequence should start at 00
    }

    #[test]
    fn test_calc_serial_same_day_increment() {
        // Simulate multiple generations on same day
        let now = Utc::now();
        let year = now.year() as u32;
        let month = now.month();
        let day = now.day();
        let today_base = year * 1_000_000 + month * 10_000 + day * 100;

        let serial1 = calc_serial(today_base + 5);
        assert_eq!(serial1, today_base + 6);

        let serial2 = calc_serial(serial1);
        assert_eq!(serial2, today_base + 7);
    }

    #[test]
    fn test_save_serial() {
        let file = NamedTempFile::new().unwrap();

        save_serial(file.path(), 2025012301).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        assert_eq!(content, "2025012301");
    }

    #[test]
    fn test_round_trip() {
        let file = NamedTempFile::new().unwrap();

        save_serial(file.path(), 2025012301).unwrap();
        let loaded = load_serial(file.path());

        assert_eq!(loaded, 2025012301);
    }
}
