//! Windows security descriptors in their text form (SDDL): the descriptors
//! warren applies to its own files and control pipe, and a classifier for the
//! descriptors Windows reports.
//!
//! This module is plain string handling, safe and platform-neutral, so it is
//! unit-tested on every OS. `crate::sys::windows` only converts between
//! this text and the binary form the system calls take.

use std::fmt;

/// The descriptor for warren's private directories: owned by the user, a
/// protected DACL (nothing inherited from the parent) that grants full access
/// to the user and to LocalSystem only, inherited by new files and
/// subdirectories. The equivalent of mode 0700; Administrators are left out
/// on purpose (they can still take ownership, as root can on Unix).
pub fn private_dir(user_sid: &str) -> String {
    format!("O:{user_sid}D:PAI(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)")
}

/// The descriptor for warren's private files (the equivalent of mode 0600).
pub fn private_file(user_sid: &str) -> String {
    format!("O:{user_sid}D:PAI(A;;FA;;;{user_sid})(A;;FA;;;SY)")
}

/// The descriptor for the daemon's control pipe: only the user and
/// LocalSystem may connect or create instances, and network logons are
/// denied as a second line of defence (the pipe also rejects remote clients).
pub fn control_pipe(user_sid: &str) -> String {
    control_pipe_at_integrity(user_sid, "ME")
}

pub fn control_pipe_at_integrity(user_sid: &str, integrity_sid: &str) -> String {
    format!(
        "O:{user_sid}D:P(D;;FA;;;NU)(A;;FA;;;{user_sid})(A;;FA;;;SY)S:(ML;;NW;;;{integrity_sid})"
    )
}

/// Mandatory integrity SID or its SDDL alias. Unknown labels fail closed.
pub fn integrity_level(sid: &str) -> Option<u32> {
    match sid {
        "LW" => Some(4096),
        "ME" => Some(8192),
        "MP" => Some(8448),
        "HI" => Some(12288),
        "SI" => Some(16384),
        _ => sid.strip_prefix("S-1-16-")?.parse().ok(),
    }
}

/// The connected object must carry one explicit no-write-up label at medium
/// or above and at least the caller's integrity. Missing labels are rejected.
pub fn trusted_pipe_integrity(text: &str, caller_sid: &str) -> bool {
    let Some(caller) = integrity_level(caller_sid) else {
        return false;
    };
    let Ok(parts) = components(text) else {
        return false;
    };
    let labels: Vec<_> = parts.iter().filter(|(k, _)| *k == 'S').collect();
    if labels.len() != 1 {
        return false;
    }
    let Ok(Dacl::List { aces, .. }) = parse_dacl(labels[0].1) else {
        return false;
    };
    aces.len() == 1
        && aces[0].kind == "ML"
        && aces[0].flags.is_empty()
        && (aces[0].rights.contains("NW") || aces[0].rights == "0x1")
        && integrity_level(&aces[0].sid).is_some_and(|level| level >= caller.max(8192))
}

/// A security descriptor's owner and DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The owner as written (a SID string or an SDDL alias such as `BA`).
    pub owner: Option<String>,
    pub dacl: Option<Dacl>,
}

/// A discretionary access control list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dacl {
    /// A NULL DACL (`D:NO_ACCESS_CONTROL`): everyone has full access.
    Null,
    List {
        /// Protected from inheriting the parent's entries (`P`).
        protected: bool,
        aces: Vec<Ace>,
    },
}

/// One access control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// `A`, `D`, `OA`, `XA`, ...
    pub kind: String,
    /// Inheritance flags such as `OICI` or `ID`.
    pub flags: String,
    /// Access rights (`FA`, `0x1f01ff`, ...).
    pub rights: String,
    /// The trustee as written (a SID string or an SDDL alias).
    pub sid: String,
}

impl Ace {
    /// Deny entries never grant access. Every other type (allow, object
    /// allow, callback allow, and anything unknown) is treated as granting
    /// access, so an unfamiliar entry fails closed.
    pub fn is_deny(&self) -> bool {
        matches!(self.kind.as_str(), "D" | "OD" | "XD" | "ZD")
    }
}

/// A malformed SDDL string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed security descriptor: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Split `s` at depth 0 into the SDDL components `O:`, `G:`, `D:` and `S:`.
/// Parentheses nest (conditional and resource-attribute entries contain
/// parenthesized expressions) and double-quoted strings may contain any
/// character.
fn components(s: &str) -> Result<Vec<(char, &str)>, ParseError> {
    let b = s.as_bytes();
    let mut marks = Vec::new();
    let (mut depth, mut quoted) = (0usize, false);
    for i in 0..b.len() {
        let c = b[i];
        if quoted {
            if c == b'"' {
                quoted = false;
            }
            continue;
        }
        match c {
            b'"' if depth > 0 => quoted = true,
            b'(' => depth += 1,
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| ParseError("unbalanced parentheses".into()))?;
            }
            b':' if depth == 0 => {
                let key = i
                    .checked_sub(1)
                    .map(|k| b[k])
                    .filter(|k| matches!(k, b'O' | b'G' | b'D' | b'S'))
                    .ok_or_else(|| ParseError(format!("unexpected ':' at {i}")))?;
                marks.push((i - 1, key as char));
            }
            _ => {}
        }
    }
    if depth != 0 || quoted {
        return Err(ParseError("unbalanced parentheses".into()));
    }
    if marks.first().map(|m| m.0) != Some(0) {
        return Err(ParseError("no component at the start".into()));
    }
    let mut out = Vec::new();
    for (n, &(start, key)) in marks.iter().enumerate() {
        let end = marks.get(n + 1).map(|m| m.0).unwrap_or(s.len());
        out.push((key, &s[start + 2..end]));
    }
    Ok(out)
}

/// Split an ACE body (without its outer parentheses) at `;` on depth 0.
fn ace_fields(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut quoted, mut start) = (0usize, false, 0);
    for (i, c) in body.char_indices() {
        if quoted {
            if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => {
                out.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&body[start..]);
    out
}

fn parse_dacl(v: &str) -> Result<Dacl, ParseError> {
    let open = v.find('(').unwrap_or(v.len());
    let flags = &v[..open];
    if flags.contains("NO_ACCESS_CONTROL") {
        return Ok(Dacl::Null);
    }
    if !flags.chars().all(|c| matches!(c, 'P' | 'A' | 'I' | 'R')) {
        return Err(ParseError(format!("unknown DACL flags {flags:?}")));
    }
    let protected = flags.contains('P');
    let mut aces = Vec::new();
    let rest = &v[open..];
    let (mut depth, mut quoted, mut start) = (0usize, false, 0);
    for (i, c) in rest.char_indices() {
        if quoted {
            if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' if depth > 0 => quoted = true,
            '(' => {
                if depth == 0 {
                    start = i + 1;
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let f = ace_fields(&rest[start..i]);
                    if f.len() < 6 {
                        return Err(ParseError(format!("short entry {:?}", &rest[start..i])));
                    }
                    aces.push(Ace {
                        kind: f[0].to_string(),
                        flags: f[1].to_string(),
                        rights: f[2].to_string(),
                        sid: f[5].to_string(),
                    });
                }
            }
            c if depth == 0 && !c.is_whitespace() => {
                return Err(ParseError(format!("text outside an entry: {rest:?}")));
            }
            _ => {}
        }
    }
    Ok(Dacl::List { protected, aces })
}

/// Parse the owner and DACL of an SDDL string (the group and SACL, if any,
/// are ignored).
pub fn parse(s: &str) -> Result<Descriptor, ParseError> {
    let mut d = Descriptor {
        owner: None,
        dacl: None,
    };
    for (key, v) in components(s.trim())? {
        match key {
            'O' => d.owner = Some(v.to_string()),
            'D' => d.dacl = Some(parse_dacl(v)?),
            _ => {}
        }
    }
    Ok(d)
}

/// Well-known SDDL aliases and the SIDs they stand for (the ones that can
/// appear on a user's files).
const ALIASES: &[(&str, &str)] = &[
    ("AN", "S-1-5-7"),
    ("AU", "S-1-5-11"),
    ("BA", "S-1-5-32-544"),
    ("BG", "S-1-5-32-546"),
    ("BO", "S-1-5-32-551"),
    ("BU", "S-1-5-32-545"),
    ("CG", "S-1-3-1"),
    ("CO", "S-1-3-0"),
    ("IU", "S-1-5-4"),
    ("LS", "S-1-5-19"),
    ("NS", "S-1-5-20"),
    ("NU", "S-1-5-2"),
    ("OW", "S-1-3-4"),
    ("PS", "S-1-5-10"),
    ("PU", "S-1-5-32-547"),
    ("RC", "S-1-5-12"),
    ("RD", "S-1-5-32-555"),
    ("SO", "S-1-5-32-549"),
    ("SU", "S-1-5-6"),
    ("SY", "S-1-5-18"),
    ("WD", "S-1-1-0"),
    ("WR", "S-1-5-33"),
];

/// The SID an SDDL trustee stands for (aliases resolved, case normalized).
pub fn canonical_sid(t: &str) -> String {
    let t = t.trim();
    ALIASES
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(t))
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| t.to_ascii_uppercase())
}

/// LocalSystem.
pub const LOCAL_SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// CREATOR OWNER.
const CREATOR_OWNER: &str = "S-1-3-0";

/// True if trustee `t` (as written in SDDL) is the account `user_sid`. SDDL
/// writes the local machine's built-in Administrator and Guest accounts as
/// `LA` and `LG`.
pub fn is_account(t: &str, user_sid: &str) -> bool {
    let user = user_sid.to_ascii_uppercase();
    if canonical_sid(t) == user {
        return true;
    }
    user.starts_with("S-1-5-21-")
        && match t.trim() {
            "LA" => user.ends_with("-500"),
            "LG" => user.ends_with("-501"),
            _ => false,
        }
}

/// How private an object is, judged from its descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The owner is the user, LocalSystem or the process's default owner.
    pub owner_ok: bool,
    /// The owner as written.
    pub owner: Option<String>,
    /// The DACL is NULL (everyone has access) or missing.
    pub open_to_all: bool,
    /// The DACL is protected from inheritance.
    pub protected: bool,
    /// Trustees other than the user and LocalSystem that an allow entry
    /// names, as written, without duplicates.
    pub others: Vec<String>,
    /// True if every trustee in `others`, and a wrong owner, is one warren
    /// removes without a warning: the Administrators group (which can take
    /// ownership of anything anyway), CREATOR OWNER, or the process's own
    /// default owner.
    benign: bool,
}

impl Assessment {
    /// Only the user and LocalSystem have access, and the owner is one of
    /// them (or the account the process creates files as).
    pub fn is_private(&self) -> bool {
        self.owner_ok && !self.open_to_all && self.others.is_empty()
    }

    /// Someone other than the user, LocalSystem and the Administrators had
    /// access: worth a warning when warren tightens it.
    pub fn exposed(&self) -> bool {
        !self.is_private() && !self.benign
    }

    /// A short description for messages, such as `access for BU, WD`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.open_to_all {
            parts.push("no access control list, so everyone has access".to_string());
        }
        if !self.others.is_empty() {
            parts.push(format!("access for {}", self.others.join(", ")));
        }
        if !self.owner_ok {
            parts.push(format!(
                "owned by {}",
                self.owner.as_deref().unwrap_or("nobody")
            ));
        }
        if parts.is_empty() {
            "private".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// Classify `sddl` for the account `user_sid` whose files are created with
/// owner `default_owner` (the token's default owner: the user, or
/// BUILTIN\Administrators in an elevated process).
pub fn assess(sddl: &str, user_sid: &str, default_owner: &str) -> Result<Assessment, ParseError> {
    let d = parse(sddl)?;
    let default_owner = canonical_sid(default_owner);
    let benign_trustee = |t: &str| {
        let c = canonical_sid(t);
        c == ADMINISTRATORS || c == CREATOR_OWNER || c == default_owner
    };
    let owner_ok = d.owner.as_deref().is_some_and(|o| {
        is_account(o, user_sid)
            || canonical_sid(o) == LOCAL_SYSTEM
            || canonical_sid(o) == default_owner
    });
    let mut benign = owner_ok || d.owner.as_deref().is_some_and(benign_trustee);
    let (open_to_all, protected, aces) = match d.dacl {
        None | Some(Dacl::Null) => (true, false, Vec::new()),
        Some(Dacl::List { protected, aces }) => (false, protected, aces),
    };
    if open_to_all {
        benign = false;
    }
    let mut others: Vec<String> = Vec::new();
    for a in aces.iter().filter(|a| !a.is_deny()) {
        if is_account(&a.sid, user_sid) || canonical_sid(&a.sid) == LOCAL_SYSTEM {
            continue;
        }
        if !benign_trustee(&a.sid) {
            benign = false;
        }
        if !others.contains(&a.sid) {
            others.push(a.sid.clone());
        }
    }
    Ok(Assessment {
        owner_ok,
        owner: d.owner,
        open_to_all,
        protected,
        others,
        benign,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    #[test]
    fn pipe_integrity_requires_an_explicit_sufficient_label() {
        assert!(trusted_pipe_integrity("S:(ML;;NW;;;ME)", "S-1-16-8192"));
        assert!(trusted_pipe_integrity("S:(ML;;NW;;;HI)", "S-1-16-8192"));
        for bad in [
            "",
            "D:P(A;;FA;;;SY)",
            "S:(ML;;NW;;;LW)",
            "S:(ML;;NW;;;S-1-16-0)",
            "S:(ML;;NR;;;ME)",
            "S:(ML;IO;NW;;;ME)",
            "S:(ML;;NW;;;ME)(ML;;NW;;;LW)",
        ] {
            assert!(!trusted_pipe_integrity(bad, "S-1-16-8192"), "{bad}");
        }
        assert!(!trusted_pipe_integrity("S:(ML;;NW;;;ME)", "S-1-16-12288"));
        assert!(!trusted_pipe_integrity("S:(ML;;NW;;;HI)", "unknown"));
    }

    #[test]
    fn warren_descriptors_are_private() {
        for s in [private_dir(ME), private_file(ME), control_pipe(ME)] {
            let a = assess(&s, ME, ME).unwrap();
            assert!(a.is_private() && a.protected && !a.exposed(), "{s}: {a:?}");
        }
        let d = parse(&control_pipe(ME)).unwrap();
        let Some(Dacl::List { aces, .. }) = d.dacl else {
            panic!()
        };
        assert!(aces[0].is_deny() && aces[0].sid == "NU");
        assert_eq!(d.owner.as_deref(), Some(ME));
    }

    #[test]
    fn parses_what_windows_reports() {
        // A folder made in Explorer under the profile: inherited entries.
        let s = format!("O:{ME}D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;{ME})");
        let a = assess(&s, ME, ME).unwrap();
        assert!(!a.is_private() && !a.protected);
        assert_eq!(a.others, ["BA"]);
        assert!(!a.exposed(), "Administrators alone is not worth a warning");
        // The root of C: grants Users and Authenticated Users.
        let s = "O:BAD:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)\
                 (A;CIID;LC;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)";
        let a = assess(s, ME, ME).unwrap();
        assert!(a.exposed());
        assert_eq!(a.others, ["BA", "BU", "AU"]);
        assert!(!a.owner_ok);
        assert_eq!(a.describe(), "access for BA, BU, AU; owned by BA");
        // Elevated: files are created owned by Administrators.
        let s = format!("O:BAD:AI(A;ID;FA;;;{ME})(A;ID;FA;;;SY)");
        assert!(assess(&s, ME, "S-1-5-32-544").unwrap().is_private());
        assert!(!assess(&s, ME, ME).unwrap().is_private());
        // Group and SACL parts are ignored.
        let s = format!("O:{ME}G:{ME}D:P(A;;FA;;;{ME})S:(ML;;NW;;;LW)");
        assert!(assess(&s, ME, ME).unwrap().is_private());
    }

    #[test]
    fn null_and_deny_entries() {
        let a = assess(&format!("O:{ME}D:NO_ACCESS_CONTROL"), ME, ME).unwrap();
        assert!(!a.is_private() && a.exposed() && a.open_to_all);
        let a = assess(&format!("O:{ME}"), ME, ME).unwrap();
        assert!(!a.is_private(), "a missing DACL is not private");
        // Deny entries for others are fine.
        let s = format!("O:{ME}D:P(D;;FA;;;WD)(A;;FA;;;{ME})");
        assert!(assess(&s, ME, ME).unwrap().is_private());
        // An unknown entry type fails closed.
        let s = format!("O:{ME}D:P(ZZ;;FA;;;WD)(A;;FA;;;{ME})");
        assert!(assess(&s, ME, ME).unwrap().exposed());
    }

    #[test]
    fn callback_and_object_entries_parse() {
        let s = format!(
            "O:{ME}D:P(A;;FA;;;{ME})(XA;;FA;;;WD;(Member_of {{SID(BA)}} || @User.x == \"a)b;c\"))\
             (OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;AU)"
        );
        let d = parse(&s).unwrap();
        let Some(Dacl::List { aces, protected }) = d.dacl.clone() else {
            panic!()
        };
        assert!(protected);
        assert_eq!(aces.len(), 3);
        assert_eq!(aces[1].kind, "XA");
        assert_eq!(aces[1].sid, "WD");
        assert_eq!(aces[2].sid, "AU");
        let a = assess(&s, ME, ME).unwrap();
        assert_eq!(a.others, ["WD", "AU"]);
        assert!(a.exposed());
    }

    #[test]
    fn aliases_and_builtin_accounts() {
        assert_eq!(canonical_sid("sy"), LOCAL_SYSTEM);
        assert_eq!(canonical_sid("s-1-5-18"), LOCAL_SYSTEM);
        let admin = "S-1-5-21-1-2-3-500";
        let s = "O:LAD:P(A;;FA;;;LA)(A;;FA;;;SY)";
        assert!(assess(s, admin, admin).unwrap().is_private());
        assert!(!assess(s, ME, ME).unwrap().is_private());
    }

    #[test]
    fn malformed() {
        for bad in [
            "",
            "D:P(A;;FA;;;SY",
            "D:P(A;;FA)",
            "X:1",
            "D:P(A;;FA;;;SY))",
            "D:Q(A;;FA;;;SY)",
            "D:Pjunk(A;;FA;;;SY)",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
