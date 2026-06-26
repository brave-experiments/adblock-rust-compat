//! Extract the "type options" of a filter rule: a network rule's `$` modifiers
//! (script, third-party, domain, replace, ...), or a cosmetic rule's type(s)
//! (elemhide, scriptlet, style, remove, procedural, js, exception). The `style`/`remove`
//! actions cover both the uBO `:style()`/`:remove()` forms and the ABP `{css}`/`{remove:
//! true;}` forms (see brave/adblock-rust#415).
//!
//! Extraction is textual so it works on rules adblock-rust can't parse (e.g. `$replace`),
//! which is the whole point - you want to find those.

/// All option/type tokens for a rule (lowercased, de-duplicated, in order).
pub fn rule_options(rule: &str) -> Vec<String> {
    let rule = rule.trim();
    match cosmetic_types(rule) {
        Some(types) => types,
        None => network_options(rule),
    }
}

/// uBO procedural *matching* operators. A `##` rule using any of these is procedural even
/// though it doesn't use the `#?#` separator. `:has`/`:not` are excluded (native CSS), and
/// the `:style()`/`:remove()` *actions* are handled separately (they aren't matching ops).
const PROCEDURAL_OPS: &[&str] = &[
    ":has-text(",
    ":if(",
    ":if-not(",
    ":matches-attr(",
    ":matches-css(",
    ":matches-css-before(",
    ":matches-css-after(",
    ":matches-media(",
    ":matches-path(",
    ":min-text-length(",
    ":others(",
    ":upward(",
    ":watch-attr(",
    ":xpath(",
    ":remove-attr(",
    ":remove-class(",
    ":-abp-has(",
    ":-abp-contains(",
    ":-abp-properties(",
];

fn has_procedural_operator(body: &str) -> bool {
    PROCEDURAL_OPS.iter().any(|op| body.contains(op))
}

/// A `##selector { ... }` declaration block whose body is `remove: true` - the ABP
/// "Remove" syntax (see brave/adblock-rust#415), equivalent to `:remove()`.
fn is_remove_block(body: &str) -> bool {
    match (body.find('{'), body.rfind('}')) {
        (Some(open), Some(close)) if close > open => {
            let inner: String = body[open + 1..close]
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ';')
                .collect();
            inner.eq_ignore_ascii_case("remove:true")
        }
        _ => false,
    }
}

/// Cosmetic type tokens if `rule` is a cosmetic filter, else `None` (it's a network rule).
fn cosmetic_types(rule: &str) -> Option<Vec<String>> {
    let (idx, marker) = cosmetic_marker(rule)?;
    let body = &rule[idx + marker.len()..];
    let mut out: Vec<String> = Vec::new();

    let scriptlet = body.starts_with("+js(");
    let js = marker.contains('%');
    // Procedural if the `#?#` separator is used or a procedural matching operator appears.
    let procedural = marker.contains('?') || has_procedural_operator(body);
    let css_block = !scriptlet && body.contains('{');
    // Actions (brave/adblock-rust#415): `{remove: true;}`/`:remove()` => remove;
    // `{css}`/`:style()`/`#$#` => style (CSS injection). A CSS selector never has `{`.
    let remove = body.contains(":remove(") || (css_block && is_remove_block(body));
    let style = !remove && (marker.contains('$') || body.contains(":style(") || css_block);

    // Base kind: scriptlet/js, else the action (remove/style), else procedural, else hide.
    let base = if scriptlet {
        "scriptlet"
    } else if js {
        "js"
    } else if remove {
        "remove"
    } else if style {
        "style"
    } else if procedural {
        "procedural"
    } else {
        "elemhide"
    };
    out.push(base.to_string());
    // A style/remove rule can also use procedural matching (e.g. `#?#...:remove()`).
    if procedural && base != "procedural" && !scriptlet && !js {
        out.push("procedural".to_string());
    }
    if marker.contains('@') {
        out.push("exception".to_string());
    }
    Some(out)
}

/// Find the cosmetic separator and return `(offset, marker)`, longest marker first.
fn cosmetic_marker(rule: &str) -> Option<(usize, &'static str)> {
    const MARKERS: &[&str] = &[
        "#@$?#", "#@$#", "#@?#", "#@%#", "#$?#", "#@#", "#$#", "#?#", "#%#", "##",
    ];
    let bytes = rule.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' {
            let rest = &rule[i..];
            for m in MARKERS {
                if rest.starts_with(m) {
                    return Some((i, m));
                }
            }
        }
    }
    None
}

/// Network `$` option names: the token before `=`, leading `~` stripped, kept only if it
/// looks like an option name (so regex / replacement fragments containing commas, which
/// would otherwise split into junk tokens, are dropped).
fn network_options(rule: &str) -> Vec<String> {
    let Some(dollar) = rule.find('$') else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for tok in rule[dollar + 1..].split(',') {
        let tok = tok.trim().trim_start_matches('~');
        let name = tok
            .split('=')
            .next()
            .unwrap_or(tok)
            .trim()
            .to_ascii_lowercase();
        let looks_like_option =
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if looks_like_option && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_modifiers() {
        assert_eq!(
            rule_options("||a.com^$script,third-party"),
            vec!["script", "third-party"]
        );
        // `~` negation stripped; option name only
        assert_eq!(rule_options("||a.com^$~third-party"), vec!["third-party"]);
        // `domain=` value dropped, name kept
        assert_eq!(
            rule_options("||a.com^$script,domain=x.com|y.com"),
            vec!["script", "domain"]
        );
        // a comma inside replace=/.../ doesn't produce a junk option
        assert_eq!(
            rule_options(r#"||a.com^$xhr,replace=/"a","b"/"#),
            vec!["xhr", "replace"]
        );
        // no options
        assert!(rule_options("||ads.com^").is_empty());
    }

    #[test]
    fn cosmetic_kinds() {
        assert_eq!(rule_options("youtube.com##.ad"), vec!["elemhide"]);
        assert_eq!(
            rule_options("youtube.com##+js(set, a, 1)"),
            vec!["scriptlet"]
        );
        assert_eq!(
            rule_options("youtube.com#@#.ad"),
            vec!["elemhide", "exception"]
        );
        assert_eq!(rule_options("a.com#?#.x:has(.y)"), vec!["procedural"]);
        assert_eq!(rule_options("a.com#$#body { color: red }"), vec!["style"]);
        assert_eq!(rule_options("a.com#%#//scriptlet"), vec!["js"]);
    }

    #[test]
    fn procedural_operators_in_hash_rules() {
        // Modern procedural cosmetics use `##` plus an operator, not the `#?#` separator.
        assert_eq!(
            rule_options(r#"facebook.com##.ego_section:if(a[href^="/ad_campaign"])"#),
            vec!["procedural"]
        );
        assert_eq!(rule_options("a.com##.x:has-text(Ad)"), vec!["procedural"]);
        assert_eq!(rule_options("a.com##.x:upward(2)"), vec!["procedural"]);
        // exception + procedural
        assert_eq!(
            rule_options("a.com#@#.x:matches-css(display: none)"),
            vec!["procedural", "exception"]
        );
        // native :has()/:not() are not procedural on their own
        assert_eq!(rule_options("a.com##.x:has(.y)"), vec!["elemhide"]);
        assert_eq!(rule_options("a.com##.x:not(.y)"), vec!["elemhide"]);
        // a style rule that is also procedural
        assert_eq!(
            rule_options("a.com#$?#.x:upward(1) { display: none }"),
            vec!["style", "procedural"]
        );
    }

    #[test]
    fn style_injection_via_hash_block() {
        // `##selector { declarations }` is CSS injection, not element hiding.
        assert_eq!(
            rule_options("twitch.tv##.ad_lower-third {height:100% !important;}"),
            vec!["style"]
        );
        // exception form
        assert_eq!(
            rule_options("a.com#@#.x { display: none }"),
            vec!["style", "exception"]
        );
        // a scriptlet whose args contain braces is still a scriptlet, not style
        assert_eq!(rule_options("a.com##+js(set, x, {})"), vec!["scriptlet"]);
        // plain element hiding (no block) stays elemhide
        assert_eq!(rule_options("a.com##.ad"), vec!["elemhide"]);
    }

    // ABP inline-css / remove syntax and their uBO equivalents (brave/adblock-rust#415).
    #[test]
    fn style_and_remove_actions() {
        // remove: both the `:remove()` and the ABP `{remove: true;}` forms
        assert_eq!(rule_options("a.com##.x:remove()"), vec!["remove"]);
        assert_eq!(rule_options("a.com##.x {remove: true;}"), vec!["remove"]);
        // style: `:style()` and the ABP `{css}` form (not mis-tagged procedural)
        assert_eq!(
            rule_options("a.com##.x:style(background: #fff !important;)"),
            vec!["style"]
        );
        assert_eq!(rule_options("a.com##.x {background: #fff;}"), vec!["style"]);
        // procedural matching + a remove action together
        assert_eq!(
            rule_options("a.com#?#div:-abp-properties(width: 46px):remove()"),
            vec!["remove", "procedural"]
        );
        // :remove-attr() / :remove-class() are matching-ish ops, not the remove action
        assert_eq!(
            rule_options("a.com##.x:remove-attr(foo)"),
            vec!["procedural"]
        );
    }
}
