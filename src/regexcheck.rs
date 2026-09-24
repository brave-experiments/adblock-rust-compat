//! Validation of full-regex network rules (`/pattern/`) against the `regex` crate - the same
//! crate adblock-rust uses to compile them.
//!
//! adblock-rust parses regex rules *without* compiling the pattern: the regex build
//! happens lazily at match time (`regex_manager::compile_regex`), and a rule whose
//! pattern fails to compile silently never matches (see `CompiledRegex::RegexParsingError`,
//! which always yields "no match"). Such rules therefore parse cleanly and would look
//! supported even though they can never block anything (e.g. the lookahead rules in
//! brave/adblock-rust#672 and #729). This module mirrors adblock-rust's own compile step
//! eagerly, so a compile failure here is exactly what the engine would hit.
//!
//! Detection (compiles or not) and classification (which syntax feature) are separate:
//! the `regex` crate reports *that* a pattern is unsupported, not which feature caused
//! it, so classification scans the pattern for the known constructs.

use adblock::filters::network::{NetworkFilter, NetworkFilterMaskHelper};

/// Reason prefix used for rules whose regex cannot compile ("unsupported regex (...)").
/// Kept groupable so reports can count unsupported regexes by prefix.
pub const REASON_PREFIX: &str = "unsupported regex";

/// Fallback feature label when a pattern fails to compile but no specific known feature
/// is found (e.g. syntax invalid for both engines, or a construct the scanner can't
/// attribute).
const OTHER: &str = "unsupported syntax";

/// The outcome of checking a regex source against the `regex` crate.
pub struct RegexCheck {
    /// Whether adblock-rust can actually compile (and thus ever match) the rule.
    pub supported: bool,
    /// Unsupported features present in the pattern when `supported` is false (e.g.
    /// `"lookahead"`), or the fallback label when the cause is something else.
    pub features: Vec<&'static str>,
}

/// Extract the regex source of a complete-regex network filter (`/pattern/`), as
/// adblock-rust would compile it. `None` for other rules: their patterns are escaped by
/// adblock-rust before conversion and can never fail to compile.
pub fn regex_source(nf: &NetworkFilter) -> Option<String> {
    if !nf.is_complete_regex() {
        return None;
    }
    // The stored filter is the full pattern including the surrounding slashes
    // (lowercased unless the rule uses $match-case, mirroring adblock-rust).
    let pattern = nf.filter.string_view()?;
    if pattern.len() < 2 || !pattern.starts_with('/') || !pattern.ends_with('/') {
        return None;
    }
    Some(pattern[1..pattern.len() - 1].to_string())
}

/// Check a regex source (the pattern between the surrounding slashes) the same way
/// adblock-rust compiles it: unescape `\/` and `\:` first, then build a `regex::bytes`
/// regex with unicode disabled. A compile error means adblock-rust would silently never
/// match the rule.
pub fn check(pattern: &str) -> RegexCheck {
    // Mirror adblock-rust's compile_regex: unescape unrecognised escape sequences.
    let unescaped = pattern.replace("\\/", "/").replace("\\:", ":");
    let compiled = regex::bytes::RegexBuilder::new(&unescaped)
        .unicode(false)
        .build();
    match compiled {
        Ok(_) => RegexCheck {
            supported: true,
            features: Vec::new(),
        },
        Err(_) => {
            let mut features = unsupported_features(pattern);
            if features.is_empty() {
                features.push(OTHER);
            }
            RegexCheck {
                supported: false,
                features,
            }
        }
    }
}

/// Detect the syntax features the `regex` crate does not support: lookarounds
/// (`(?=`, `(?!`, `(?<=`, `(?<!`) and backreferences (`\1`-`\9`). Character classes and
/// escapes are tracked so literal occurrences (e.g. `[(?=)]`, `\\1`) are not flagged.
/// Named groups `(?<name>...)` are supported by both JS and the `regex` crate (since 1.9)
/// and are not lookbehinds, so they are correctly absent.
fn unsupported_features(pattern: &str) -> Vec<&'static str> {
    let mut features: Vec<&'static str> = Vec::new();
    // Walk by char, not byte, so multi-byte UTF-8 can't create a non-boundary slice.
    let chars: Vec<char> = pattern.chars().collect();
    let mut in_class = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                // Escaped char: skip it so e.g. `\\1` is not a backreference.
                if let Some(&next) = chars.get(i + 1) {
                    if !in_class && next.is_ascii_digit() && next != '0' {
                        push_once(&mut features, "backreference");
                    }
                }
                i += 2;
                continue;
            }
            '[' => in_class = true,
            ']' => in_class = false,
            '(' if !in_class => {
                let rest: &[char] = &chars[i..];
                if rest.starts_with(&['(', '?', '<', '=']) {
                    push_once(&mut features, "lookbehind");
                } else if rest.starts_with(&['(', '?', '<', '!']) {
                    push_once(&mut features, "negative lookbehind");
                } else if rest.starts_with(&['(', '?', '=']) {
                    push_once(&mut features, "lookahead");
                } else if rest.starts_with(&['(', '?', '!']) {
                    push_once(&mut features, "negative lookahead");
                }
            }
            _ => (),
        }
        i += 1;
    }
    features
}

fn push_once(features: &mut Vec<&'static str>, feature: &'static str) {
    if !features.contains(&feature) {
        features.push(feature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adblock::lists::{parse_filter, FilterFormat, ParseOptions, RuleTypes};
    use adblock::resources::PermissionMask;

    fn parse_opts() -> ParseOptions {
        ParseOptions {
            rule_types: RuleTypes::All,
            format: FilterFormat::Standard,
            permissions: PermissionMask::from_bits(0),
        }
    }

    fn check_rule(rule: &str) -> RegexCheck {
        let source = match parse_filter(rule, true, parse_opts()) {
            Ok(adblock::lists::ParsedFilter::Network(nf)) => regex_source(&nf),
            _ => panic!("rule should parse as a network filter: {rule}"),
        };
        check(&source.expect("complete-regex rule should yield a regex source"))
    }

    /// The lookahead rule from brave/adblock-rust#672.
    const RULE_672: &str = r#"/^https?:\/\/(?:[a-z]{2}\.)?[0-9a-z]{5,16}\.[a-z]{3,7}\/[a-z](?=[a-z]{0,25}[0-9A-Z])[0-9a-zA-Z]{3,26}\/\d{3,6}(?:[?&][_a-z0-9]+=[-0-9a-zA-Z]+)*$/$script,3p,redirect-rule=noop.js,match-case"#;
    /// A lookahead rule from brave/adblock-rust#729 (no match-case: adblock-rust
    /// lowercases the stored pattern, which must not affect detection).
    const RULE_729: &str = r#"/^https?:\/\/(?:[a-z]{2}\.)?[0-9a-z]{5,16}\.[a-z]{3,7}\/[a-z](?=[a-z]{0,25}[0-9A-Z])[0-9a-zA-Z]{3,26}\/\d{4,6}(?:\?[_a-z]=[-0-9a-z]+)?$/$script,3p"#;

    #[test]
    fn lookahead_rules_are_unsupported() {
        let check = check_rule(RULE_672);
        assert!(!check.supported);
        assert_eq!(check.features, vec!["lookahead"]);

        let check = check_rule(RULE_729);
        assert!(!check.supported);
        assert_eq!(check.features, vec!["lookahead"]);
    }

    #[test]
    fn plain_full_regex_is_supported() {
        let check = check_rule(r"/^https:\/\/f\.vimeocdn.*/$script,3p");
        assert!(check.supported);
        assert!(check.features.is_empty());
    }

    #[test]
    fn non_regex_rule_has_no_regex_source() {
        // Not a complete regex (no slashes): adblock-rust escapes the pattern itself,
        // so it can never fail to compile.
        let source = match parse_filter(r"||a.com^foo*bar^", true, parse_opts()) {
            Ok(adblock::lists::ParsedFilter::Network(nf)) => regex_source(&nf),
            _ => panic!("rule should parse"),
        };
        assert!(source.is_none());
    }

    #[test]
    fn feature_labels() {
        assert_eq!(unsupported_features("a(?=x)"), vec!["lookahead"]);
        assert_eq!(unsupported_features("a(?!x)"), vec!["negative lookahead"]);
        assert_eq!(unsupported_features("a(?<=x)"), vec!["lookbehind"]);
        assert_eq!(unsupported_features("a(?<!x)"), vec!["negative lookbehind"]);
        assert_eq!(unsupported_features(r"a(b)\1"), vec!["backreference"]);
        // multiple features, first-occurrence order, de-duplicated
        assert_eq!(
            unsupported_features(r"(?<=a)b(?=c)\1(?=d)"),
            vec!["lookbehind", "lookahead", "backreference"]
        );
        // literal occurrences inside character classes are not features
        assert!(unsupported_features("[a(?=b)]").is_empty());
        assert!(unsupported_features(r"[\1]").is_empty());
        // an escaped backslash is not a backreference; `(?<name>` is not a lookbehind
        assert_eq!(unsupported_features(r"a\\1(?=x)"), vec!["lookahead"]);
        assert!(unsupported_features("(?<name>a)b").is_empty());
    }

    #[test]
    fn compile_failure_without_known_feature_falls_back() {
        // Invalid for the regex crate (`a{2,1}` is a reversed repetition range) but with
        // no known lookaround/backreference syntax.
        let check = check("a{2,1}");
        assert!(!check.supported);
        assert_eq!(check.features, vec!["unsupported syntax"]);
    }

    #[test]
    fn valid_patterns_compile() {
        for pattern in [
            "",
            "(?:a|b)+",
            r"^https?://[a-z]+/\d{3}(?:\?q=[a-z]+)?$",
            "(?<name>a)b",
            r"a\/b",
        ] {
            let result = check(pattern);
            assert!(result.supported, "pattern should compile: {pattern}");
            assert!(result.features.is_empty());
        }
    }
}
