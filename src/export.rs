//! export — snapshot JSON i generatory briefów markdown per lead.
//!
//! Brief = gotowy szkic maila (personalizacja): hooki sektorowe + wyniki
//! pasywnego DNS-auditu domeny. Format odpowiedni do wklejenia w Brevo/edycję.

use crate::dnsmini::{Answer, Record};
use crate::model::Lead;
use serde::Serialize;

/// Wynik pasywnego audytu domeny (tylko publiczny DNS; zero aktywnego skanu).
#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsAudit {
    pub domain: String,
    pub has_mx: bool,
    pub mx: Vec<String>,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub a_records: Vec<String>,
    pub nxdomain: bool,
    /// Krótkie wnioski sprzedażowe („brak DMARC", „SPF zbyt łagodny"...).
    pub findings: Vec<String>,
}

impl DnsAudit {
    /// Interpretacja zebranych rekordów (reguły MVP, deterministyczne).
    pub fn analyze(&mut self) {
        if self.nxdomain {
            self.findings.push("domena nie istnieje (NXDOMAIN) — mail odbije".into());
            return;
        }
        if !self.has_mx {
            self.findings.push("brak MX — domena nie odbiera maila (kontakt inny kanał)".into());
        }
        match &self.spf {
            None => self.findings.push("brak SPF — spoofing nazwy domeny trywialny".into()),
            Some(spf) if spf.contains("+all") || spf.contains("?all") => {
                self.findings.push("SPF przepuszcza wszystko (+all/?all) — zerowa ochrona".into())
            }
            _ => {}
        }
        match &self.dmarc {
            None => self.findings.push("brak DMARC — brak raportowania i polityki spoofingu".into()),
            Some(d) if d.contains("p=none") => {
                self.findings.push("DMARC p=none — tylko monitoring, brak egzekwowania".into())
            }
            _ => {}
        }
        if self.findings.is_empty() {
            self.findings.push("higiena DNS poprawna (MX+SPF+DMARC) — lead technicznie dojrzały".into());
        }
    }

    /// Czy audit daje amunicję personalizacyjną (≥1 realne znalezisko)?
    pub fn is_attack_surface_signal(&self) -> bool {
        !self.nxdomain && self.findings.iter().any(|f| !f.contains("poprawna"))
    }
}

/// Zebranie rekordów z odpowiedzi DNS do DnsAudit (parser → struktura).
pub fn collect(domain: &str, answers: &[(&str, Answer)]) -> DnsAudit {
    let mut a = DnsAudit {
        domain: domain.to_string(),
        ..Default::default()
    };
    for (kind, ans) in answers {
        if ans.is_nxdomain() {
            a.nxdomain = true;
            continue;
        }
        match *kind {
            "MX" => {
                for r in &ans.records {
                    if let Record::Mx { pref, exchange } = r {
                        a.mx.push(format!("{pref} {exchange}"));
                        a.has_mx = true;
                    }
                }
            }
            "TXT" => {
                for t in ans.txt_strings() {
                    let tl = t.to_lowercase();
                    if tl.starts_with("v=spf1") {
                        a.spf = Some(t.clone());
                    }
                }
            }
            "A" => {
                for r in &ans.records {
                    if let Record::A(ip) = r {
                        a.a_records.push(ip.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    a
}

/// Zrzut JSON całego rankingu (snapshot do LOGU / analiz offline).
pub fn snapshot_json(leads: &[Lead], audits: &std::collections::BTreeMap<String, DnsAudit>) -> String {
    #[derive(Serialize)]
    struct Row<'a> {
        org: &'a str,
        email: &'a str,
        domain: Option<String>,
        score: u32,
        tier: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        dns_audit: Option<&'a DnsAudit>,
    }
    let rows: Vec<Row> = leads
        .iter()
        .map(|l| Row {
            org: &l.org,
            email: &l.email,
            domain: l.effective_domain(),
            score: l.score(),
            tier: l.tier(),
            dns_audit: l
                .effective_domain()
                .and_then(|d| audits.get(&d))
                .filter(|_| true),
        })
        .collect();
    serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".into())
}

/// Brief markdown per lead — szkic maila 1:1 (hook + personalizacja z audytu).
pub fn brief_markdown(l: &Lead, audit: Option<&DnsAudit>) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Brief — {}\n\n", l.org));
    out.push_str(&format!(
        "- **Do:** {} · sektor: {} · tier: {} (score {})\n",
        l.email,
        l.sector,
        l.tier(),
        l.score()
    ));
    if let Some(a) = audit {
        out.push_str(&format!(
            "- **DNS-audit ({}):** {}\n",
            a.domain,
            if a.findings.is_empty() { "brak danych".into() } else { a.findings.join("; ") }
        ));
    }
    out.push_str("\n## Szkic maila\n\n");
    out.push_str(&format!("Temat: Bezpieczeństwo IT {} — 2 rzeczy na wczoraj (KSC 3.10)\n\n", l.org));
    out.push_str("Dzień dobry,\n\n");
    let hook_line = if l
        .hooks
        .iter()
        .any(|h| matches!(h, crate::model::Hook::KscDeadline(_)))
    {
        "do 3.10 mija termin samorejestracji w Wykazie KSC — po tej dacie wąskie okno na uzupełnienie"
    } else {
        "środki techniczne NIS2/UKSC wchodzą 3.04.2027 — planowanie warto zacząć wcześniej"
    };
    out.push_str(&format!(
        "piszę, bo {hook_line}. W skrócie:\n\n"
    ));
    if let Some(a) = audit {
        for f in a.findings.iter().take(2) {
            if !f.contains("poprawna") {
                out.push_str(&format!("- w Waszej domenie ({}) widzę: {}\n", a.domain, f));
            }
        }
    }
    out.push_str("- sektor, w którym działacie, jest dziś celem nr 1 dla grup wymuszających\n\n");
    out.push_str(
        "Zajmujemy się detekcją i reagowaniem dla linuxowych środowisk (eBPF, air-gap). \
         Chętnie pokażę na 20 minutach, jak to wygląda na przykładzie sektora.\n\nPozdrawiam,\nHartwell Labs\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Sector;

    fn audit_fixture() -> DnsAudit {
        DnsAudit {
            domain: "zwik.example.pl".into(),
            has_mx: true,
            mx: vec!["10 mail.zwik.example.pl".into()],
            spf: None,
            dmarc: None,
            a_records: vec![],
            nxdomain: false,
            findings: vec![],
        }
    }

    #[test]
    fn analyze_flaguje_brak_spf_i_dmarc() {
        let mut a = audit_fixture();
        a.analyze();
        assert!(a.findings.iter().any(|f| f.contains("brak SPF")));
        assert!(a.findings.iter().any(|f| f.contains("brak DMARC")));
        assert!(a.is_attack_surface_signal());
    }

    #[test]
    fn analyze_higiena_ok_nie_jest_sygnalem() {
        let mut a = audit_fixture();
        a.spf = Some("v=spf1 mx -all".into());
        a.dmarc = Some("v=DMARC1; p=reject".into());
        a.analyze();
        assert!(!a.is_attack_surface_signal());
        assert!(a.findings[0].contains("poprawna"));
    }

    #[test]
    fn analyze_nxdomain_konczy_skan() {
        let mut a = audit_fixture();
        a.nxdomain = true;
        a.analyze();
        assert_eq!(a.findings.len(), 1);
        assert!(a.findings[0].contains("NXDOMAIN"));
    }

    #[test]
    fn collect_czyta_odpowiedzi() {
        let mx = Answer {
            rcode: 0,
            records: vec![Record::Mx { pref: 10, exchange: "mail.x.pl".into() }],
        };
        let txt = Answer {
            rcode: 0,
            records: vec![Record::Txt("v=spf1 mx ~all".into())],
        };
        let a = collect(
            "x.pl",
            &[("MX", mx), ("TXT", txt)],
        );
        assert!(a.has_mx);
        assert_eq!(a.mx, vec!["10 mail.x.pl"]);
        assert_eq!(a.spf.as_deref(), Some("v=spf1 mx ~all"));
    }

    #[test]
    fn brief_zawiera_hook_i_personalizacje() {
        let l = Lead {
            org: "ZWiK Test".into(),
            domain: "zwik.example.pl".into(),
            email: "a@b.pl".into(),
            sector: Sector::Water,
            voivodeship: String::new(),
            email_verified: false,
            hooks: vec![crate::model::Hook::KscDeadline(5)],
            source: "test".into(),
        };
        let mut a = audit_fixture();
        a.analyze();
        let md = brief_markdown(&l, Some(&a));
        assert!(md.contains("# Brief — ZWiK Test"));
        assert!(md.contains("brak SPF"));
        assert!(md.contains("KSC"));
    }

    #[test]
    fn snapshot_json_serializuje_audit() {
        let l = Lead {
            org: "X".into(),
            domain: "x.pl".into(),
            email: "a@x.pl".into(),
            sector: Sector::Other,
            voivodeship: String::new(),
            email_verified: false,
            hooks: vec![],
            source: "t".into(),
        };
        let mut audits = std::collections::BTreeMap::new();
        let mut a = audit_fixture();
        a.analyze();
        audits.insert("x.pl".to_string(), a);
        let json = snapshot_json(&[l], &audits);
        assert!(json.contains("\"dns_audit\""));
        assert!(json.contains("\"tier\""));
    }
}
