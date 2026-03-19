use crate::error::FilterError;

use bitflags::bitflags;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub device_class: Option<u8>,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub device_version_bcd: Option<u16>,
    pub allow: bool,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CheckFlags: u32 {
        const DEFAULT_ALLOW = 0x01;
        const DONT_SKIP_NON_BOOT_HID = 0x02;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterResult {
    Allow,
    Deny,
    NoMatch,
}

pub fn parse_rules(
    filter_str: &str,
    token_sep: &str,
    rule_sep: &str,
) -> Result<Vec<FilterRule>, FilterError> {
    if token_sep.is_empty() || rule_sep.is_empty() {
        return Err(FilterError::EmptySeparator);
    }

    let mut rules = Vec::new();

    // Split by rule_sep characters (strtok semantics: any char in rule_sep is a separator)
    for rule_str in split_by_chars(filter_str, rule_sep) {
        if rule_str.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = split_by_chars(rule_str, token_sep).collect();
        if tokens.len() != 5 {
            return Err(FilterError::InvalidString);
        }

        let device_class = parse_filter_int(tokens[0])?;
        let vendor_id = parse_filter_int(tokens[1])?;
        let product_id = parse_filter_int(tokens[2])?;
        let device_version_bcd = parse_filter_int(tokens[3])?;
        let allow_val = parse_filter_int(tokens[4])?;

        let rule = FilterRule {
            device_class: int_to_opt_u8(device_class, 255)?,
            vendor_id: int_to_opt_u16(vendor_id)?,
            product_id: int_to_opt_u16(product_id)?,
            device_version_bcd: int_to_opt_u16(device_version_bcd)?,
            allow: allow_val.map_or(false, |v| v != 0),
        };
        verify_single_rule(&rule)?;
        rules.push(rule);
    }

    Ok(rules)
}

fn split_by_chars<'a>(s: &'a str, chars: &'a str) -> impl Iterator<Item = &'a str> {
    s.split(|c: char| chars.contains(c))
}

fn parse_filter_int(s: &str) -> Result<Option<i64>, FilterError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(FilterError::InvalidString);
    }

    let val = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|_| FilterError::InvalidString)?
    } else {
        s.parse::<i64>().map_err(|_| FilterError::InvalidString)?
    };

    if val == -1 {
        Ok(None)
    } else {
        Ok(Some(val))
    }
}

fn int_to_opt_u8(val: Option<i64>, max: u8) -> Result<Option<u8>, FilterError> {
    match val {
        None => Ok(None),
        Some(v) if v >= 0 && v <= max as i64 => Ok(Some(v as u8)),
        _ => Err(FilterError::ValueOutOfRange),
    }
}

fn int_to_opt_u16(val: Option<i64>) -> Result<Option<u16>, FilterError> {
    match val {
        None => Ok(None),
        Some(v) if v >= 0 && v <= 65535 => Ok(Some(v as u16)),
        _ => Err(FilterError::ValueOutOfRange),
    }
}

fn verify_single_rule(_rule: &FilterRule) -> Result<(), FilterError> {
    // device_class must be None or 0..=255 (already ensured by Option<u8>)
    // vendor_id, product_id, device_version_bcd must be None or 0..=65535 (already ensured)
    Ok(())
}

pub fn verify_rules(rules: &[FilterRule]) -> Result<(), FilterError> {
    for rule in rules {
        verify_single_rule(rule)?;
    }
    Ok(())
}

pub fn rules_to_string(
    rules: &[FilterRule],
    token_sep: &str,
    rule_sep: &str,
) -> Result<String, FilterError> {
    if token_sep.is_empty() || rule_sep.is_empty() {
        return Err(FilterError::EmptySeparator);
    }
    verify_rules(rules)?;

    let tsep = token_sep.chars().next().unwrap();
    let rsep = rule_sep.chars().next().unwrap();

    let mut s = String::new();
    for (i, rule) in rules.iter().enumerate() {
        if i > 0 {
            s.push(rsep);
        }
        match rule.device_class {
            Some(c) => s.push_str(&format!("0x{:02x}{}", c, tsep)),
            None => s.push_str(&format!("-1{}", tsep)),
        }
        match rule.vendor_id {
            Some(v) => s.push_str(&format!("0x{:04x}{}", v, tsep)),
            None => s.push_str(&format!("-1{}", tsep)),
        }
        match rule.product_id {
            Some(p) => s.push_str(&format!("0x{:04x}{}", p, tsep)),
            None => s.push_str(&format!("-1{}", tsep)),
        }
        match rule.device_version_bcd {
            Some(d) => s.push_str(&format!("0x{:04x}{}", d, tsep)),
            None => s.push_str(&format!("-1{}", tsep)),
        }
        s.push_str(if rule.allow { "1" } else { "0" });
    }
    Ok(s)
}

fn check1(
    rules: &[FilterRule],
    device_class: u8,
    vendor_id: u16,
    product_id: u16,
    device_version_bcd: u16,
    default_allow: bool,
) -> FilterResult {
    for rule in rules {
        let class_match = rule.device_class.map_or(true, |c| c == device_class);
        let vendor_match = rule.vendor_id.map_or(true, |v| v == vendor_id);
        let product_match = rule.product_id.map_or(true, |p| p == product_id);
        let version_match = rule
            .device_version_bcd
            .map_or(true, |d| d == device_version_bcd);

        if class_match && vendor_match && product_match && version_match {
            return if rule.allow {
                FilterResult::Allow
            } else {
                FilterResult::Deny
            };
        }
    }

    if default_allow {
        FilterResult::Allow
    } else {
        FilterResult::NoMatch
    }
}

pub fn check(
    rules: &[FilterRule],
    device_class: u8,
    device_subclass: u8,
    device_protocol: u8,
    interfaces: &[(u8, u8, u8)], // (class, subclass, protocol)
    vendor_id: u16,
    product_id: u16,
    device_version_bcd: u16,
    flags: CheckFlags,
) -> Result<FilterResult, FilterError> {
    verify_rules(rules)?;

    let default_allow = flags.contains(CheckFlags::DEFAULT_ALLOW);

    // Check device class (skip for 0x00 and 0xef)
    if device_class != 0x00 && device_class != 0xef {
        let rc = check1(
            rules,
            device_class,
            vendor_id,
            product_id,
            device_version_bcd,
            default_allow,
        );
        match rc {
            FilterResult::Deny | FilterResult::NoMatch => return Ok(rc),
            FilterResult::Allow => {}
        }
    }

    // Check interface classes
    let mut num_skipped = 0;
    for &(iface_class, iface_subclass, iface_protocol) in interfaces {
        if !flags.contains(CheckFlags::DONT_SKIP_NON_BOOT_HID)
            && interfaces.len() > 1
            && iface_class == 0x03
            && iface_subclass == 0x00
            && iface_protocol == 0x00
        {
            num_skipped += 1;
            continue;
        }
        let rc = check1(
            rules,
            iface_class,
            vendor_id,
            product_id,
            device_version_bcd,
            default_allow,
        );
        match rc {
            FilterResult::Deny | FilterResult::NoMatch => return Ok(rc),
            FilterResult::Allow => {}
        }
    }

    // If all interfaces were skipped, recurse with DONT_SKIP_NON_BOOT_HID
    if !interfaces.is_empty() && num_skipped == interfaces.len() {
        return check(
            rules,
            device_class,
            device_subclass,
            device_protocol,
            interfaces,
            vendor_id,
            product_id,
            device_version_bcd,
            flags | CheckFlags::DONT_SKIP_NON_BOOT_HID,
        );
    }

    Ok(FilterResult::Allow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter() {
        let rules = parse_rules("", ",", "|").unwrap();
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn separators_only() {
        let rules = parse_rules("|||", ",", "|").unwrap();
        assert_eq!(rules.len(), 0);
        let s = rules_to_string(&rules, ",", "|").unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn one_rule() {
        let rules = parse_rules("0x03,-1,-1,-1,0", ",", "|").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].device_class, Some(0x03));
        assert_eq!(rules[0].vendor_id, None);
        assert!(!rules[0].allow);
    }

    #[test]
    fn two_rules() {
        let rules = parse_rules("0x03,-1,-1,-1,0|-1,-1,-1,-1,1", ",", "|").unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn ignore_trailing_rule_sep() {
        let rules = parse_rules("|0x03,-1,-1,-1,0|-1,-1,-1,-1,1|", ",", "|").unwrap();
        assert_eq!(rules.len(), 2);
        let s = rules_to_string(&rules, ",", "|").unwrap();
        assert_eq!(s, "0x03,-1,-1,-1,0|-1,-1,-1,-1,1");
    }

    #[test]
    fn ignores_empty_rules() {
        let rules = parse_rules("0x03,-1,-1,-1,0|||-1,-1,-1,-1,1", ",", "|").unwrap();
        assert_eq!(rules.len(), 2);
        let s = rules_to_string(&rules, ",", "|").unwrap();
        assert_eq!(s, "0x03,-1,-1,-1,0|-1,-1,-1,-1,1");
    }

    #[test]
    fn several_trailing_and_empty() {
        let rules =
            parse_rules("||||0x03,-1,-1,-1,0|||-1,-1,-1,-1,1||||", ",", "|").unwrap();
        assert_eq!(rules.len(), 2);
        let s = rules_to_string(&rules, ",", "|").unwrap();
        assert_eq!(s, "0x03,-1,-1,-1,0|-1,-1,-1,-1,1");
    }

    #[test]
    fn multi_char_separators() {
        let rules = parse_rules("0x03,-1,-1,-1,0", ",;", " \t\n").unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn mix_of_separators() {
        let rules = parse_rules("\t 0x03,-1;-1;-1,0\n\n", ",;", " \t\n").unwrap();
        assert_eq!(rules.len(), 1);
        let s = rules_to_string(&rules, ",", " ").unwrap();
        assert_eq!(s, "0x03,-1,-1,-1,0");
    }

    #[test]
    fn multiple_rules_multi_sep() {
        let rules =
            parse_rules("\n\t0x03;-1,-1,-1,0\n\n-1,-1,-1;-1;1", ",;", " \t\n").unwrap();
        assert_eq!(rules.len(), 2);
        let s = rules_to_string(&rules, ",", " ").unwrap();
        assert_eq!(s, "0x03,-1,-1,-1,0 -1,-1,-1,-1,1");
    }

    #[test]
    fn upper_limit_class() {
        assert!(parse_rules("0x100,-1,-1,-1,0", ",", "|").is_err());
    }

    #[test]
    fn lower_limit_class() {
        assert!(parse_rules("-2,-1,-1,-1,0", ",", "|").is_err());
    }

    #[test]
    fn upper_limit_vendor() {
        assert!(parse_rules("0x03,,0x10000-1,-1,0", ",", "|").is_err());
    }

    #[test]
    fn lower_limit_vendor() {
        assert!(parse_rules("0x03,-2,-1,-1,0", ",", "|").is_err());
    }

    #[test]
    fn upper_limit_product() {
        assert!(parse_rules("0x03,-1,0x10000-1,,0", ",", "|").is_err());
    }

    #[test]
    fn lower_limit_product() {
        assert!(parse_rules("0x03,-1,-2,-1,0", ",", "|").is_err());
    }

    #[test]
    fn upper_limit_bcd() {
        assert!(parse_rules("0x03,-1,-1,0x10000,0", ",", "|").is_err());
    }

    #[test]
    fn lower_limit_bcd() {
        assert!(parse_rules("0x03,-1,-1,-2,0", ",", "|").is_err());
    }

    #[test]
    fn extra_argument() {
        assert!(parse_rules("0x03,-1,-1,-1,0,1", ",", "|").is_err());
    }

    #[test]
    fn missing_argument() {
        assert!(parse_rules("0x03,-1,-1,-1", ",", "|").is_err());
    }

    #[test]
    fn missing_value_in_argument() {
        assert!(parse_rules("0x03,-1,-1,,-1", ",", "|").is_err());
    }

    #[test]
    fn letter_as_value() {
        assert!(parse_rules("0x03,-1,-1,a,-1", ",", "|").is_err());
    }

    #[test]
    fn number_sign_as_value() {
        assert!(parse_rules("0x03,-1,-1,#,-1", ",", "|").is_err());
    }

    #[test]
    fn space_as_value() {
        assert!(parse_rules("0x03,-1,-1, ,-1", ",", "|").is_err());
    }

    #[test]
    fn invalid_token_sep() {
        assert!(parse_rules("0x03;-1;-1;-1;0", ",", "|").is_err());
    }

    #[test]
    fn invalid_rule_sep() {
        assert!(parse_rules("0x03,-1,-1,-1,0;-1,-1,-1,-1,1", ",", "|").is_err());
    }

    #[test]
    fn bad_rule_in_many() {
        assert!(parse_rules("0x03,-1,-1,-1,0|3|-1,-1,-1,-1,1", ",", "|").is_err());
    }

    #[test]
    fn empty_token_separator() {
        assert!(parse_rules("0x03,-1,-1,-1,0", "", "|").is_err());
    }

    #[test]
    fn empty_rule_separator() {
        assert!(parse_rules("0x03,-1,-1,-1,0", ",", "").is_err());
    }
}
