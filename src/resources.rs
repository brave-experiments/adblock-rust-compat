//! Whether a rule's scriptlet/redirect resource actually resolves. A rule can parse
//! yet do nothing if the resource is missing or needs a permission it wasn't granted.
//! Uses adblock-rust's own `ResourceStorage` with Brave's vendored resource set, so
//! `.js` suffixing, aliases, dependencies, and permissions match the engine.

use adblock::filters::cosmetic::CosmeticFilterMask;
use adblock::filters::network::NetworkFilterMask;
use adblock::lists::ParsedFilter;
use adblock::resources::{InMemoryResourceStorage, PermissionMask, Resource, ResourceStorage};

const BRAVE_RESOURCES_JSON: &str = include_str!("../data/brave-resources.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    /// Not a scriptlet or redirect rule.
    NotApplicable,
    Ok,
    RequiresPermission,
    Missing,
}

pub struct ResourceChecker {
    storage: ResourceStorage,
}

impl ResourceChecker {
    pub fn from_embedded() -> Self {
        let resources: Vec<Resource> = serde_json::from_str(BRAVE_RESOURCES_JSON)
            .expect("vendored brave-resources.json should deserialize into Vec<Resource>");
        Self {
            storage: ResourceStorage::from_backend(InMemoryResourceStorage::from_resources(
                resources,
            )),
        }
    }

    /// `rule` is the original text; `parsed` is its parse tree, used to tell scriptlet
    /// and redirect rules apart from rules that merely mention `+js(`/`redirect=`.
    pub fn check_rule(&self, parsed: &ParsedFilter, rule: &str) -> ResourceStatus {
        match parsed {
            ParsedFilter::Cosmetic(c) if c.mask.contains(CosmeticFilterMask::SCRIPT_INJECT) => {
                match scriptlet_body(rule) {
                    Some(body) => self.check_scriptlet(body),
                    None => ResourceStatus::NotApplicable,
                }
            }
            ParsedFilter::Network(n) if n.mask.contains(NetworkFilterMask::IS_REDIRECT) => {
                match n.modifier_option.as_deref() {
                    // strip any `:priority` suffix; resource names contain no colon
                    Some(value) => {
                        let name = value.split(':').next().unwrap_or(value);
                        if self.storage.get_redirect_resource(name).is_some() {
                            ResourceStatus::Ok
                        } else {
                            ResourceStatus::Missing
                        }
                    }
                    None => ResourceStatus::NotApplicable,
                }
            }
            _ => ResourceStatus::NotApplicable,
        }
    }

    fn check_scriptlet(&self, body: &str) -> ResourceStatus {
        // get_scriptlet_resources returns "" when it can't resolve the scriptlet.
        let resolves = |perm: u8| {
            !self
                .storage
                .get_scriptlet_resources([(body, PermissionMask::from_bits(perm))])
                .is_empty()
        };
        if resolves(0) {
            ResourceStatus::Ok
        } else if resolves(0xFF) {
            ResourceStatus::RequiresPermission
        } else {
            ResourceStatus::Missing
        }
    }
}

fn scriptlet_body(rule: &str) -> Option<&str> {
    let start = rule.find("+js(")? + "+js(".len();
    let end = rule.rfind(')')?;
    if end > start {
        Some(&rule[start..end])
    } else {
        Some("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adblock::lists::{parse_filter, FilterFormat, ParseOptions, RuleTypes};

    fn status(rule: &str) -> ResourceStatus {
        let parsed = parse_filter(
            rule,
            true,
            ParseOptions {
                rule_types: RuleTypes::All,
                format: FilterFormat::Standard,
                permissions: PermissionMask::from_bits(0),
            },
        )
        .unwrap_or_else(|e| panic!("expected {rule:?} to parse, got {e:?}"));
        ResourceChecker::from_embedded().check_rule(&parsed, rule)
    }

    #[test]
    fn embedded_resources_deserialize() {
        let _ = ResourceChecker::from_embedded();
    }

    #[test]
    fn known_scriptlet_resolves() {
        assert_eq!(
            status("youtube.com##+js(set, foo.bar, undefined)"),
            ResourceStatus::Ok
        );
        assert_eq!(
            status("youtube.com##+js(json-prune, adPlacements)"),
            ResourceStatus::Ok
        );
    }

    #[test]
    fn unknown_scriptlet_is_missing() {
        assert_eq!(
            status("youtube.com##+js(this-scriptlet-does-not-exist-xyz, 1)"),
            ResourceStatus::Missing
        );
    }

    #[test]
    fn known_redirect_resolves() {
        assert_eq!(
            status("||youtube.com/get_video$media,redirect=noopmp4-1s"),
            ResourceStatus::Ok
        );
    }

    #[test]
    fn unknown_redirect_is_missing() {
        assert_eq!(
            status("||x.com^$redirect=nonexistent-resource-xyz"),
            ResourceStatus::Missing
        );
    }

    #[test]
    fn plain_rules_are_not_applicable() {
        assert_eq!(status("||ads.youtube.com^"), ResourceStatus::NotApplicable);
        assert_eq!(
            status("youtube.com##.ytp-ad-module"),
            ResourceStatus::NotApplicable
        );
    }

    #[test]
    fn cosmetic_selector_mentioning_redirect_is_not_a_redirect_rule() {
        // The literal "redirect=" in a hide selector must not be treated as a redirect.
        assert_eq!(
            status(r#"youtube.com##a[href*="redirect="]"#),
            ResourceStatus::NotApplicable
        );
    }

    #[test]
    fn scriptlet_body_extraction() {
        assert_eq!(
            scriptlet_body("youtube.com##+js(set, a, 1)"),
            Some("set, a, 1")
        );
        assert_eq!(scriptlet_body("||ads.youtube.com^"), None);
    }
}
