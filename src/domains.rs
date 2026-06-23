//! Decide whether a filter rule relates to a configured set of domains, and how:
//!   - `target`: the rule blocks a request to one of the domains.
//!   - `scope`:  the rule runs while browsing one of the domains (cosmetic / `$domain=`).
//!
//! Parsed rules are matched against their parse tree; rejected rules (no parse tree)
//! fall back to a role-aware text split that ignores incidental mentions (e.g. an
//! allowlisted `denyallow=` entry).

use std::collections::HashSet;

use adblock::filters::cosmetic::CosmeticFilter;
use adblock::filters::network::NetworkFilter;
use adblock::lists::ParsedFilter;
use adblock::utils::{fast_hash, Hash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Relation {
    Target,
    Scope,
}

/// Matches filter rules against a fixed set of domains.
///
/// Readable hostnames are matched by boundary-safe suffix, so `example.com` also covers
/// `sub.example.com`. Hashed scopes (`$domain=`, cosmetic) can only match exact strings
/// (hashes aren't reversible), so list the specific subdomains you need; entity labels
/// like `example` (from `example.com`) are derived to match `example.*##...`.
pub struct DomainMatcher {
    suffix_domains: Vec<String>,
    scope_hashes: HashSet<Hash>,
}

impl DomainMatcher {
    pub fn new<S: AsRef<str>>(domains: &[S]) -> Self {
        let mut suffix_domains = Vec::with_capacity(domains.len());
        let mut scope_hashes = HashSet::new();
        for d in domains {
            let d = d.as_ref().trim().trim_end_matches('.').to_ascii_lowercase();
            if d.is_empty() {
                continue;
            }
            scope_hashes.insert(fast_hash(&d));
            // entity label from a registrable (single-dot) domain
            if d.matches('.').count() == 1 {
                if let Some(label) = d.split('.').next() {
                    scope_hashes.insert(fast_hash(label));
                }
            }
            suffix_domains.push(d);
        }
        Self {
            suffix_domains,
            scope_hashes,
        }
    }

    /// `host == d` or ends with `.d`; avoids matching `notexample.com`.
    fn host_in_set(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.suffix_domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }

    /// Match a raw token like `example.com`, `sub.example.com`, or `example.*`.
    fn token_matches(&self, token: &str) -> bool {
        let token = token.trim().to_ascii_lowercase();
        let label = token.strip_suffix(".*").unwrap_or(&token);
        self.host_in_set(label) || self.scope_hashes.contains(&fast_hash(label))
    }

    fn any_scope_hash(&self, hashes: &Option<Vec<Hash>>) -> bool {
        hashes
            .as_ref()
            .map(|v| v.iter().any(|h| self.scope_hashes.contains(h)))
            .unwrap_or(false)
    }

    pub fn relations_parsed(&self, parsed: &ParsedFilter) -> Vec<Relation> {
        match parsed {
            ParsedFilter::Network(f) => self.relations_network(f),
            ParsedFilter::Cosmetic(f) => self.relations_cosmetic(f),
        }
    }

    fn relations_network(&self, f: &NetworkFilter) -> Vec<Relation> {
        let mut rels = Vec::new();
        if let Some(host) = &f.hostname {
            if self.host_in_set(host) {
                rels.push(Relation::Target);
            }
        }
        // `$domain=` include list (ignore the excludes in opt_not_domains)
        if self.any_scope_hash(&f.opt_domains) {
            rels.push(Relation::Scope);
        }
        rels
    }

    fn relations_cosmetic(&self, f: &CosmeticFilter) -> Vec<Relation> {
        // Excluded scope (`~example.com##...`) does not count as a match.
        if self.any_scope_hash(&f.not_hostnames) || self.any_scope_hash(&f.not_entities) {
            return Vec::new();
        }
        if self.any_scope_hash(&f.hostnames) || self.any_scope_hash(&f.entities) {
            vec![Relation::Scope]
        } else {
            Vec::new()
        }
    }

    /// Text-based fallback for rules with no parse tree.
    pub fn relations_raw(&self, rule: &str) -> Vec<Relation> {
        if let Some(sep) = cosmetic_separator(rule) {
            return self.relations_raw_cosmetic(&rule[..sep]);
        }
        self.relations_raw_network(rule)
    }

    fn relations_raw_cosmetic(&self, scope_text: &str) -> Vec<Relation> {
        let mut excluded = false;
        let mut included = false;
        for part in scope_text.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (neg, dom) = match part.strip_prefix('~') {
                Some(rest) => (true, rest),
                None => (false, part),
            };
            if self.token_matches(dom) {
                if neg {
                    excluded = true;
                } else {
                    included = true;
                }
            }
        }
        if included && !excluded {
            vec![Relation::Scope]
        } else {
            Vec::new()
        }
    }

    fn relations_raw_network(&self, rule: &str) -> Vec<Relation> {
        let (pattern, options) = split_network_options(rule);
        let mut rels = Vec::new();

        if let Some(host) = pattern_anchor_host(pattern) {
            if self.host_in_set(host) {
                rels.push(Relation::Target);
            }
        }

        // Only non-negated `domain=` counts; `denyallow=` and `domain=~...` are ignored
        // because those domains are exempted, not targeted.
        for opt in options.split(',') {
            let opt = opt.trim();
            if let Some(val) = opt.strip_prefix("domain=") {
                for dom in val.split('|') {
                    let dom = dom.trim();
                    if dom.starts_with('~') {
                        continue;
                    }
                    if self.token_matches(dom) {
                        rels.push(Relation::Scope);
                    }
                }
            }
        }
        rels.sort_by_key(|r| matches!(r, Relation::Scope));
        rels.dedup();
        rels
    }
}

/// Byte offset of the cosmetic separator (`##`, `#@#`, `#$#`, ...), if any.
fn cosmetic_separator(rule: &str) -> Option<usize> {
    let bytes = rule.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'#' {
            let rest = &rule[i..];
            for marker in [
                "##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#$?#", "#@$?#", "#%#", "#@%#",
            ] {
                if rest.starts_with(marker) {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Split a network rule into `(pattern, options)` on the first `$`.
fn split_network_options(rule: &str) -> (&str, &str) {
    match rule.find('$') {
        Some(idx) => (&rule[..idx], &rule[idx + 1..]),
        None => (rule, ""),
    }
}

/// Anchored hostname from a `||host...` pattern; `None` if not hostname-anchored.
fn pattern_anchor_host(pattern: &str) -> Option<&str> {
    let rest = pattern.strip_prefix("||")?;
    let end = rest.find(['^', '/', '*', '?', ':']).unwrap_or(rest.len());
    let host = &rest[..end];
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adblock::lists::{parse_filter, FilterFormat, ParseOptions, RuleTypes};
    use adblock::resources::PermissionMask;

    const YT: &[&str] = &[
        "youtube.com",
        "youtu.be",
        "youtube-nocookie.com",
        "ytimg.com",
        "googlevideo.com",
        "ggpht.com",
        "www.youtube.com",
        "m.youtube.com",
        "music.youtube.com",
        "i.ytimg.com",
    ];

    fn matcher() -> DomainMatcher {
        DomainMatcher::new(YT)
    }

    fn parse(rule: &str) -> ParsedFilter {
        parse_filter(
            rule,
            true,
            ParseOptions {
                rule_types: RuleTypes::All,
                format: FilterFormat::Standard,
                permissions: PermissionMask::from_bits(0),
            },
        )
        .unwrap_or_else(|e| panic!("expected {rule:?} to parse, got {e:?}"))
    }

    fn rels_parsed(rule: &str) -> Vec<Relation> {
        matcher().relations_parsed(&parse(rule))
    }

    fn rels_raw(rule: &str) -> Vec<Relation> {
        matcher().relations_raw(rule)
    }

    #[test]
    fn host_matching_is_boundary_safe() {
        let m = matcher();
        assert!(m.host_in_set("youtube.com"));
        assert!(m.host_in_set("www.youtube.com"));
        assert!(m.host_in_set("r3---sn-abc.googlevideo.com"));
        assert!(m.host_in_set("i.ytimg.com"));
        assert!(!m.host_in_set("notyoutube.com"));
        assert!(!m.host_in_set("youtube.com.evil.com"));
        assert!(!m.host_in_set("example.com"));
    }

    #[test]
    fn matcher_is_domain_agnostic() {
        let fb = DomainMatcher::new(&["facebook.com", "fbcdn.net"]);
        assert!(fb.host_in_set("static.fbcdn.net"));
        assert!(!fb.host_in_set("youtube.com"));
        assert_eq!(
            fb.relations_raw("||ads.example.com^$domain=facebook.com"),
            vec![Relation::Scope]
        );
    }

    #[test]
    fn network_hostname_anchor_is_target() {
        assert_eq!(
            rels_parsed("||www.youtube.com/watch^"),
            vec![Relation::Target]
        );
        assert_eq!(rels_parsed("||ads.youtube.com^"), vec![Relation::Target]);
        assert_eq!(rels_parsed("||r3.googlevideo.com^"), vec![Relation::Target]);
    }

    #[test]
    fn network_domain_option_is_scope_not_target() {
        assert_eq!(
            rels_parsed("||ads.example.com^$domain=youtube.com"),
            vec![Relation::Scope]
        );
    }

    #[test]
    fn non_matching_network_rule_has_no_relations() {
        assert!(rels_parsed("||ads.example.com^").is_empty());
        assert!(rels_parsed("||doubleclick.net^$domain=cnn.com").is_empty());
    }

    #[test]
    fn cosmetic_hostname_scope() {
        assert_eq!(
            rels_parsed("youtube.com##.ytp-ad-module"),
            vec![Relation::Scope]
        );
    }

    #[test]
    fn cosmetic_entity_scope() {
        assert_eq!(rels_parsed("youtube.*##.ad"), vec![Relation::Scope]);
    }

    #[test]
    fn cosmetic_excluded_domain_is_not_a_match() {
        assert!(rels_parsed("~youtube.com,~m.youtube.com##.ad").is_empty());
    }

    #[test]
    fn generic_cosmetic_rule_is_not_a_match() {
        assert!(rels_parsed("##.ad-banner").is_empty());
    }

    #[test]
    fn raw_replace_rule_targets_domain() {
        let rule = r#"||www.youtube.com/watch?$xhr,1p,replace=/"adPlacements"/"no_ads"/"#;
        assert!(parse_filter(rule, true, ParseOptions::default()).is_err());
        assert_eq!(rels_raw(rule), vec![Relation::Target]);
    }

    #[test]
    fn raw_denyallow_domain_is_not_a_match() {
        let rule = "*$frame,denyallow=facebook.com|google.com|youtube.com,domain=foxseotools.com";
        assert!(rels_raw(rule).is_empty());
    }

    #[test]
    fn raw_negated_domain_is_not_scope() {
        assert!(rels_raw("||ads.example.com^$domain=~youtube.com").is_empty());
    }

    #[test]
    fn raw_cosmetic_scope_and_exclusion() {
        assert_eq!(
            rels_raw("m.youtube.com,www.youtube.com##.ad"),
            vec![Relation::Scope]
        );
        assert!(rels_raw("~youtube.com##.ad").is_empty());
    }

    #[test]
    fn raw_network_domain_scope() {
        assert_eq!(
            rels_raw("||ads.example.com^$script,domain=youtube.com|other.com"),
            vec![Relation::Scope]
        );
    }

    #[test]
    fn cosmetic_separator_detection() {
        assert_eq!(cosmetic_separator("youtube.com##.ad"), Some(11));
        assert_eq!(cosmetic_separator("youtube.com#@#.ad"), Some(11));
        assert_eq!(cosmetic_separator("youtube.com#$#scriptlet"), Some(11));
        assert_eq!(cosmetic_separator("||youtube.com^$third-party"), None);
    }

    #[test]
    fn split_network_options_on_first_dollar() {
        assert_eq!(
            split_network_options("||a.com^$script,third-party"),
            ("||a.com^", "script,third-party")
        );
        assert_eq!(split_network_options("||a.com^"), ("||a.com^", ""));
    }

    #[test]
    fn pattern_anchor_host_extraction() {
        assert_eq!(
            pattern_anchor_host("||www.youtube.com/watch?"),
            Some("www.youtube.com")
        );
        assert_eq!(pattern_anchor_host("||youtube.com^"), Some("youtube.com"));
        assert_eq!(pattern_anchor_host("||youtube.com"), Some("youtube.com"));
        assert_eq!(pattern_anchor_host("*"), None);
        assert_eq!(pattern_anchor_host("/ads/banner"), None);
    }
}
