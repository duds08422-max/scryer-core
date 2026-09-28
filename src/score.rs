//! score — scoring, dedupe, ranking, walidacja, loader, manifest (ex-main.rs).
//!
//! Semantyka bez zmian względem MVP; dodany scoring DNS-audit (higiena domeny
//! jako sygnał sprzedażowy i personalizacja maili).

use crate::model::Lead;
use sha2::{Digest, Sha256};
use serde::Deserialize;use std::collections::{BTreeMap, HashSet};

/// Wynik przetworzenia wsadu.
#[derive(Debug, Default)]
pub struct PipelineReport {
    pub loaded: usize,
    pub deduped: usize,
    pub dropped_invalid: usize,
    pub hot: usize,
    pub warm: usize,
    pub cold: usize,
    pub total_score: u32,
}

/// Walidacja: email musi mieć '@' i domenę; org nie może być pusty (fail-early).
pub fn validate(l: &Lead) -> Result<(), String> {
    if l.org.trim().is_empty() {
        return Err(format!("{}: pusta nazwa organizacji", l.email));
    }
    let e = l.email.trim();
    let Some((_, dom)) = e.split_once('@') else {
        return Err(format!("{e}: email bez '@'"));
    };
    if dom.is_empty() || !dom.contains('.') {
        return Err(format!("{e}: email z bezużyteczną domeną"));
    }
    Ok(())
}

/// Dedupe po emailu (lowercase) — pierwszy wygrywa.
pub fn dedupe(leads: Vec<Lead>) -> (Vec<Lead>, usize) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(leads.len());
    let mut dropped = 0usize;
    for l in leads {
        if seen.insert(l.email.trim().to_lowercase()) {
            out.push(l);
        } else {
            dropped += 1;
        }
    }
    (out, dropped)
}

/// Ranking: score malejąco, remis → org alfabetycznie (stabilny output).
pub fn rank(mut leads: Vec<Lead>) -> Vec<Lead> {
    leads.sort_by(|a, b| {
        b.score()
            .cmp(&a.score())
            .then_with(|| a.org.to_lowercase().cmp(&b.org.to_lowercase()))
    });
    leads
}

/// Pełny pipeline: walidacja → dedupe → ranking.
pub fn run(leads: Vec<Lead>) -> (Vec<Lead>, PipelineReport) {
    let mut rep = PipelineReport {
        loaded: leads.len(),
        ..Default::default()
    };
    let valid: Vec<Lead> = leads
        .into_iter()
        .filter(|l| match validate(l) {
            Ok(()) => true,
            Err(_) => {
                rep.dropped_invalid += 1;
                false
            }
        })
        .collect();
    let (deduped, dups) = dedupe(valid);
    rep.deduped = deduped.len();
    rep.dropped_invalid += dups;
    let ranked = rank(deduped);
    for l in &ranked {
        rep.total_score += l.score();
        match l.tier() {
            "HOT" => rep.hot += 1,
            "WARM" => rep.warm += 1,
            _ => rep.cold += 1,
        }
    }
    (ranked, rep)
}

/// Eksport CSV pod Brevo: nagłówek + wiersze, escaping ';'.
pub fn export_csv(leads: &[Lead]) -> String {
    let mut out = String::from("EMAIL;ORG;SECTOR;VOIVODESHIP;SCORE;TIER;HOOKS;SOURCE\n");
    for l in leads {
        let hooks = l
            .hooks
            .iter()
            .map(|h| h.label())
            .collect::<Vec<_>>()
            .join(" | ");
        let esc = |s: &str| s.replace(';', ",").replace('\n', " ");
        out.push_str(&format!(
            "{};{};{};{};{};{};{};{}\n",
            esc(l.email.trim()),
            esc(&l.org),
            l.sector,
            esc(&l.voivodeship),
            l.score(),
            l.tier(),
            esc(&hooks),
            esc(&l.source),
        ));
    }
    out
}

/// Wczytanie wsadu JSON: albo [Lead], albo {"leads":[...]}.
pub fn load_json(raw: &str) -> Result<Vec<Lead>, serde_json::Error> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') {
        #[derive(Deserialize)]
        struct Wrapper {
            leads: Vec<Lead>,
        }
        Ok(serde_json::from_str::<Wrapper>(raw)?.leads)
    } else {
        serde_json::from_str(raw)
    }
}

/// Deterministyczny manifest audytowy (sha256 rankingu) — do LOGU PR7.
pub fn manifest_hash(leads: &[Lead]) -> String {
    let mut map: BTreeMap<String, u32> = BTreeMap::new();
    for l in leads {
        let mut h = Sha256::new();
        h.update(l.email.trim().to_lowercase().as_bytes());
        let id: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()[..16]
            .to_string();
        map.insert(id, l.score());
    }
    let mut h = Sha256::new();
    for (k, v) in &map {
        h.update(k.as_bytes());
        h.update(v.to_le_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hook, Sector};

    fn lead(org: &str, email: &str, sector: Sector, hooks: Vec<Hook>, verified: bool) -> Lead {
        Lead {
            org: org.into(),
            domain: String::new(),
            email: email.into(),
            sector,
            voivodeship: "zachodniopomorskie".into(),
            email_verified: verified,
            hooks,
            source: "test".into(),
        }
    }

    #[test]
    fn scoring_sektor_i_hooki() {
        let szpital = lead(
            "Szpital X",
            "a@x.pl",
            Sector::Health,
            vec![Hook::KscDeadline(3), Hook::CezRecommendation],
            true,
        );
        assert_eq!(szpital.score(), 20);
        assert_eq!(szpital.tier(), "HOT");
        let other = lead("Firma Y", "b@y.pl", Sector::Other, vec![], false);
        assert_eq!(other.score(), 3);
        assert_eq!(other.tier(), "COLD");
    }

    #[test]
    fn ksc_deadline_far_to_slabym_hookiem() {
        let soon = lead("A", "a@a.pl", Sector::Water, vec![Hook::KscDeadline(3)], false);
        let far = lead("A", "a@a.pl", Sector::Water, vec![Hook::KscDeadline(30)], false);
        assert_eq!(soon.score(), far.score() + 2);
    }

    #[test]
    fn dedupe_po_emailu_case_insensitive() {
        let a = lead("A", "Kontakt@Zwik.pl", Sector::Water, vec![], false);
        let b = lead("A (kop)", "kontakt@zwik.pl", Sector::Water, vec![], true);
        let (out, dropped) = dedupe(vec![a, b]);
        assert_eq!(out.len(), 1);
        assert_eq!(dropped, 1);
        assert!(!out[0].email_verified);
    }

    #[test]
    fn ranking_stabilny_przy_remisie() {
        let a = lead("Beta", "b@b.pl", Sector::Water, vec![], false);
        let b = lead("Alfa", "a@a.pl", Sector::Water, vec![], false);
        let (ranked, _) = run(vec![a, b]);
        assert_eq!(ranked[0].org, "Alfa");
    }

    #[test]
    fn walidacja_wyrzuca_smieci() {
        let bad = lead("", "no-at", Sector::Other, vec![], false);
        let (ranked, rep) = run(vec![bad]);
        assert_eq!(rep.dropped_invalid, 1);
        assert!(ranked.is_empty());
    }

    #[test]
    fn csv_escaping_i_naglowek() {
        let l = lead("ZWiK; Police", "a@a.pl", Sector::Water, vec![Hook::Nis2Window], false);
        let csv = export_csv(&[l]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "EMAIL;ORG;SECTOR;VOIVODESHIP;SCORE;TIER;HOOKS;SOURCE");
        assert!(lines[1].contains("ZWiK, Police"));
        assert!(lines[1].ends_with("WARM;NIS2: środki do 3.04.2027;test"));
    }

    #[test]
    fn manifest_hash_stabilny() {
        let l1 = lead("A", "a@a.pl", Sector::Water, vec![], false);
        let l2 = lead("B", "b@b.pl", Sector::Health, vec![], false);
        let m1 = manifest_hash(&[l1.clone(), l2.clone()]);
        let m2 = manifest_hash(&[l2, l1]);
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 64);
    }

    #[test]
    fn loader_json_dwoch_ksztaltow() {
        let flat = r#"[{"org":"X","email":"x@x.pl","sector":"wodociagi"}]"#;
        let wrapped = r#"{"leads":[{"org":"X","email":"x@x.pl","sector":"zwik"}]}"#;
        assert_eq!(load_json(flat).unwrap().len(), 1);
        assert_eq!(load_json(wrapped).unwrap().len(), 1);
        assert_eq!(load_json(flat).unwrap()[0].sector, Sector::Water);
    }
}
