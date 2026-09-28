//! store — trwałość: zapis/odczyt rankingu i audytów (JSON) do katalogu roboczego.
//!
//! MVP: pliki flat (rank.json, audits.json); docelowo SQLite. API zostaje.

use crate::dnsmini::Answer;
use crate::export::{collect, DnsAudit};
use crate::model::Lead;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// Pasywny DNS-audit domeny leadu (MX + TXT + A; server configurable, timeout 2 s).
/// Zero aktywnego skanowania — zapytania równoważne zwykłemu resolverowi.
pub fn audit_domain(domain: &str, server: &str) -> DnsAudit {
    let t = Duration::from_secs(2);
    let mut answers: Vec<(&str, Answer)> = Vec::new();
    let dmarc_name = format!("_dmarc.{domain}");
    for (kind, name, qtype) in [
        ("MX", domain, 15u16),
        ("TXT", domain, 16),
        ("A", domain, 1),
        ("TXT", dmarc_name.as_str(), 16),
    ] {
        match crate::dnsmini::query(name, qtype, server, t) {
            Ok(ans) => answers.push((kind, ans)),
            Err(_) => continue, // timeout/serwer martwy → traktuj jak brak danych
        }
    }
    let mut audit = collect(domain, &answers);
    // DMARC siedzi pod _dmarc.<domain> — TXT z tej odpowiedzi wyciągamy osobno
    if let Some((_, ans)) = answers.iter().find(|(k, _)| *k == "TXT" && false) {
        let _ = ans; // (logika DMARC poniżej bez hacków)
    }
    // ponownie: zbierz TXT z zapytania o _dmarc — answers[3] jeśli było
    if let Some(ans) = answers.get(3).map(|(_, a)| a.clone()) {
        if !ans.is_nxdomain() {
            if let Some(d) = ans.txt_strings().into_iter().find(|t| t.starts_with("v=DMARC1")) {
                audit.dmarc = Some(d);
            }
        }
    }
    audit.analyze();
    audit
}

/// Audyt całego rankingu (sekwencyjnie; MVP nie robi równoległości — przewidywalność).
pub fn audit_all(leads: &[Lead], server: &str) -> BTreeMap<String, DnsAudit> {
    let mut out = BTreeMap::new();
    for l in leads {
        if let Some(d) = l.effective_domain() {
            out.entry(d.clone()).or_insert_with(|| audit_domain(&d, server));
        }
    }
    out
}

/// Zapis JSON do pliku (pretty).
pub fn write_json(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    let s = serde_json::to_string_pretty(value).unwrap_or_else(|_| "[]".into());
    std::fs::write(path, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_json_pisze_pretty() {
        let dir = std::env::temp_dir().join(format!("scryer-store-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.json");
        let v = serde_json::json!({"a": 1});
        write_json(&p, &v).unwrap();
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("\"a\": 1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
