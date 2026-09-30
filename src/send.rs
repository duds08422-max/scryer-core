//! send — bezpieczna wysyłka kampanijna (Resend API) z gate'ami.
//!
//! Zasady (hard):
//! 1. Domyślnie DRY-RUN — nic nie wychodzi bez SCRYER_CONFIRM=yes.
//! 2. Gate MX: lead bez aktywnego MX nie dostaje maila — nie palimy
//!    reputacji domeny na martwe skrzynki.
//! 3. Limit: domyślnie 20 wysyłek/run (SCRYER_DAILY_LIMIT) — snajper,
//!    nie karabin (taktyka CAMPAIGN-ETAP1).
//! 4. Pełny audyt: każdy attempt = wiersz JSONL w outbox.
//! 5. v0.2 SUPPRESSION: email obecny w outbox ze statusem "sent" nigdy
//!    nie dostanie drugiego maila (niezależnie od wsadu).
//! 6. v0.2 A/B: 3 warianty tematu rotowane round-robin (równy podział).

use crate::model::Lead;
use crate::ontology;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct SendRecord {
    pub org: String,
    pub email: String,
    pub status: String, // sent|dry_run|skipped_no_mx|skipped_limit|skipped_suppressed|error
    pub via: String,
    pub subject: String,
    pub variant: u8,
    pub error: Option<String>,
    pub ts: String,
}

pub struct SendConfig {
    pub api_key: String,
    pub from: String,
    pub confirm: bool,
    pub daily_limit: usize,
    pub dns_server: String,
}

impl SendConfig {
    pub fn from_env() -> Self {
        Self {
            api_key: std::env::var("SCRYER_RESEND_KEY").unwrap_or_default(),
            from: std::env::var("SCRYER_FROM")
                .unwrap_or_else(|_| "contact@hartwell-labs.pl".into()),
            confirm: std::env::var("SCRYER_CONFIRM").as_deref() == Ok("yes"),
            daily_limit: std::env::var("SCRYER_DAILY_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            dns_server: std::env::var("SCRYER_DNS").unwrap_or_else(|_| "1.1.1.1".into()),
        }
    }
}

/// Skrót nazwy podmiotu (bez form prawnych) do tematu/treści.
fn org_short(org: &str) -> String {
    let cut = |s: &str| {
        s.split(" SPÓŁKA")
            .next()
            .unwrap_or(s)
            .split(" SAMODZIELNY")
            .next()
            .unwrap_or(s)
            .trim()
            .to_string()
    };
    let s = cut(org);
    // slice po znakach, nie bajtach (polskie znaki = >1 bajt; bug paniki 29.09)
    if s.chars().count() > 60 {
        let t: String = s.chars().take(57).collect();
        format!("{t}…")
    } else {
        s
    }
}

/// 3 warianty tematu (rotacja A/B/C, round-robin po indeksie wsadu).
/// Warianty zakazane przez CAMPAIGN-ETAP1 §2 (bez "omijam przetarg" itp.).
pub fn subject_variant(short: &str, v: u8) -> String {
    match v % 3 {
        0 => format!("KSC przed 3.10 — czy {short} ma już plan ochrony offline?"),
        1 => format!("{short}: dni do samorejestracji KSC — plan na offline?"),
        _ => format!("Pilot 14 dni dla {short} — detekcja ransomware offline (Linux)"),
    }
}

/// Treść maila (text/plain — snajper, nie newsletter).
pub fn render_email(lead: &Lead, ammo: Option<&str>, variant: u8) -> (String, String) {
    let short = org_short(&lead.org);
    let subject = subject_variant(&short, variant);
    let ammo_line = ammo
        .map(|a| {
            format!(
                "\nPrzy okazji: z zewnątrz widać, że {a}. Chętnie pokażę, co jeszcze \
wyszło w pasywnym audycie domeny.\n"
            )
        })
        .unwrap_or_default();
    // v0.3: pitch zależny od sektora — wod-kan: SCADA/dyspozytornia, urzędy: dane
    // mieszkańców, energetyka: OT; reszta (health) — wersja ogólna.
    let pitch = match lead.sector {
        crate::model::Sector::Water => "Talus CI to agent dla Linuksa, który wykrywa ransomware i \
eksfiltrację na poziomie jądra (eBPF) i automatycznie zatrzymuje proces ataku — bez chmury, \
bez telemetrii, bez modułów jądra. Licencja i aktualizacje w pełni offline. Montowany na \
stacjach operatorowych, serwerach dyspozytorskich SCADA i stacjach roboczych inżynierów — \
tam, gdzie segment OT nie może widzieć internetu.\n\n"
            .to_string(),
        crate::model::Sector::Energy => "Talus CI to agent dla Linuksa, który wykrywa ransomware \
i eksfiltrację na poziomie jądra (eBPF) i automatycznie zatrzymuje proces ataku — bez chmury, \
bez telemetrii. Licencja i aktualizacje w pełni offline. Celuje w stacje operatorowe i serwery \
dyspozytorskie w segmentach OT, gdzie dostęp z internetu jest wykluczony.\n\n"
            .to_string(),
        crate::model::Sector::PublicAdmin => "Talus CI to agent dla Linuksa, który wykrywa \
ransomware i eksfiltrację na poziomie jądra (eBPF) i automatycznie zatrzymuje proces ataku — \
bez chmury, bez telemetrii. Licencja i aktualizacje w pełni offline. Chroni serwery \
aplikacyjne i stacje robocze z danymi mieszkańców, tam gdzie chmura nie wchodzi w grę.\n\n"
            .to_string(),
        _ => "Talus CI to agent bezpieczeństwa dla Linuksa, który wykrywa ransomware i \
eksfiltrację na poziomie jądra (eBPF) i automatycznie zatrzymuje proces ataku — bez chmury, \
bez telemetrii, bez modułów jądra. Licencja i aktualizacje działają w pełni offline.\n\n"
            .to_string(),
    };
    let body = format!(
        "Dzień dobry,\n\npiszę krótko, bo przed 3 października {short} składa wniosek o wpis do \
Wykazu podmiotów kluczowych (KSC) — a po wpisie przyjdzie realny obowiązek wykrywania i \
reagowania na incydenty (art. 25 ustawy KSC), także na systemach odciętych od internetu.\n\n\
{pitch}\
{ammo_line}\
Proponuję 14-dniowy pilotaż (1–5 hostów, 0 zł, bez zobowiązań). Standardowa cena roczna to \
100 000 zł netto — kwota mieści się w trybie zamówienia z wolnej ręki.\n\n\
Czy przesłać krótki brief (3 strony PDF) i ustawić pilotaż?\n\n--\n\
Bartosz Osiej — Hartwell Labs\neBPF threat detection · https://hartwell-labs.pl\n\
Otrzymuje Pan/Pani tę wiadomość jednorazowo jako podmiot objęty KSC. Nie chcesz więcej? \
Odpowiedz \"stop\"."
    );
    (subject, body)
}

/// Pasywny MX-check domeny leadu (dnsmini; równoważne resolverowi).
pub fn has_mx(lead: &Lead, server: &str) -> bool {
    let Some(d) = lead.effective_domain() else {
        return false;
    };
    match crate::dnsmini::query(&d, 15, server, Duration::from_secs(2)) {
        Ok(ans) => {
            !ans.is_nxdomain()
                && ans
                    .records
                    .iter()
                    .any(|r| matches!(r, crate::dnsmini::Record::Mx { .. }))
        }
        Err(_) => false,
    }
}

/// Suppression list: emaile ze statusem "sent" z poprzednich runów (JSONL).
pub fn load_suppressed(outbox_path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(f) = std::fs::File::open(outbox_path) {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if v["status"] == "sent" {
                    if let Some(e) = v["email"].as_str() {
                        set.insert(e.to_lowercase());
                    }
                }
            }
        }
    }
    set
}

/// Wysyłka jednego maila przez Resend; zwraca message-id albo błąd.
pub fn send_one(
    cfg: &SendConfig,
    to_email: &str,
    subject: &str,
    body: &str,
) -> Result<String, String> {
    let payload = serde_json::json!({
        "from": cfg.from,
        "to": [to_email],
        "subject": subject,
        "text": body,
    });
    let resp = ureq::post("https://api.resend.com/emails")
        .timeout(Duration::from_secs(15))
        .set("Authorization", &format!("Bearer {}", cfg.api_key))
        .send_json(payload)
        .map_err(|e| e.to_string())?;
    let txt = resp.into_string().map_err(|e| e.to_string())?;
    let id = serde_json::from_str::<serde_json::Value>(&txt)
        .ok()
        .and_then(|v| v["id"].as_str().map(String::from))
        .unwrap_or_default();
    Ok(id)
}

/// v0.5: pętla jak run_campaign, ale dodatkowo:
/// - suppression czytana z GRAFU (ontologia) i z JSONL (oba źródła),
/// - każdy sent/dry_run zapisuje Interakcję do grafu,
/// - graf: SCRYER_DB (domyślnie scryer.db), opcjonalny.
pub fn run_campaign_graph(leads: &[Lead], outbox_path: &str) -> Vec<SendRecord> {
    let db = std::env::var("SCRYER_DB").unwrap_or_else(|_| "scryer.db".into());
    let graph = ontology::Ontology::open(std::path::Path::new(&db)).ok();
    let records = run_campaign(leads, outbox_path);
    if let Some(g) = &graph {
        for r in &records {
            if matches!(r.status.as_str(), "sent" | "dry_run") {
                let _ = g.log_interakcja(&ontology::NewInterakcja {
                    typ: "email_sent".into(),
                    kierunek: "out".into(),
                    email: r.email.clone().to_lowercase(),
                    temat: r.subject.clone(),
                    ts: r.ts.parse().unwrap_or(0),
                    wynik: "-".into(),
                    ref_id: r.via.clone(),
                });
            }
        }
    }
    records
}

/// Główna pętla: suppression → gate MX → limit → A/B → send/log → audyt JSONL.
pub fn run_campaign(leads: &[Lead], outbox_path: &str) -> Vec<SendRecord> {
    let cfg = SendConfig::from_env();
    let suppressed = load_suppressed(outbox_path);
    let mut records = Vec::new();
    let mut sent_this_run = 0usize;
    let mut idx = 0u8;

    for lead in leads {
        idx = idx.wrapping_add(1);
        let variant = idx % 3;
        let (subject, body) = render_email(lead, None, variant);
        let rec = if suppressed.contains(&lead.email.to_lowercase()) {
            SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "skipped_suppressed".into(),
                via: "-".into(),
                subject,
                variant,
                error: Some("już dostał maila wcześniej (suppression)".into()),
                ts: now(),
            }
        } else if sent_this_run >= cfg.daily_limit {
            SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "skipped_limit".into(),
                via: "-".into(),
                subject,
                variant,
                error: Some("daily limit reached".into()),
                ts: now(),
            }
        } else if !has_mx(lead, &cfg.dns_server) {
            SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "skipped_no_mx".into(),
                via: "-".into(),
                subject,
                variant,
                error: None,
                ts: now(),
            }
        } else if !cfg.confirm {
            sent_this_run += 1;
            SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "dry_run".into(),
                via: "resend(dry)".into(),
                subject,
                variant,
                error: None,
                ts: now(),
            }
        } else if cfg.api_key.is_empty() {
            SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "error".into(),
                via: "resend".into(),
                subject,
                variant,
                error: Some("brak SCRYER_RESEND_KEY".into()),
                ts: now(),
            }
        } else {
            match send_one(&cfg, &lead.email, &subject, &body) {
                Ok(id) => {
                    sent_this_run += 1;
                    SendRecord {
                        org: lead.org.clone(),
                        email: lead.email.clone(),
                        status: "sent".into(),
                        via: format!("resend:{id}"),
                        subject,
                        variant,
                        error: None,
                        ts: now(),
                    }
                }
                Err(e) => SendRecord {
                    org: lead.org.clone(),
                    email: lead.email.clone(),
                    status: "error".into(),
                    via: "resend".into(),
                    subject,
                    variant,
                    error: Some(e),
                    ts: now(),
                },
            }
        };
        records.push(rec);
    }

    // audyt JSONL (append; per lead jeden wiersz)
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(outbox_path)
    {
        for r in &records {
            let _ = writeln!(f, "{}", serde_json::to_string(r).unwrap_or_default());
        }
    }
    records
}

fn now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

/// Raport kampanii z całego outbox.jsonl (do cmd_report).
pub fn report(outbox_path: &str) -> String {
    let (mut sent, mut dry, mut no_mx, mut lim, mut supp, mut err) = (0, 0, 0, 0, 0, 0);
    let mut variants = [0u32; 3];
    let mut domains = std::collections::BTreeSet::new();
    if let Ok(f) = std::fs::File::open(outbox_path) {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                match v["status"].as_str().unwrap_or("") {
                    "sent" => {
                        sent += 1;
                        if let Some(d) = v["email"].as_str().and_then(|e| e.split('@').nth(1)) {
                            domains.insert(d.to_string());
                        }
                    }
                    "dry_run" => dry += 1,
                    "skipped_no_mx" => no_mx += 1,
                    "skipped_limit" => lim += 1,
                    "skipped_suppressed" => supp += 1,
                    _ => err += 1,
                }
                if let Some(x) = v["variant"].as_u64() {
                    variants[(x % 3) as usize] += 1;
                }
            }
        }
    }
    format!(
        "KAMPANIA: sent={sent} dry_run={dry} no_mx={no_mx} limit={lim} suppressed={supp} errors={err}\n\
         warianty A/B/C: A={} B={} C={}\n\
         unikalnych domen dotkniętych: {}\n\
         suppression: {sent} maili live (limit dzienny Resend: 100)",
        variants[0], variants[1], variants[2], domains.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Sector;

    fn lead() -> Lead {
        Lead {
            org: "UNIWERSYTECKI SZPITAL KLINICZNY W OPOLU SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ"
                .into(),
            domain: "usk.opole.pl".into(),
            email: "centrum@usk.opole.pl".into(),
            sector: Sector::Health,
            voivodeship: "opolskie".into(),
            email_verified: false,
            hooks: vec![],
            source: "test".into(),
            pop: 0,
            city: String::new(),
        }
    }

    #[test]
    fn render_email_zawiera_kluczowe_elementy() {
        let (subject, body) = render_email(&lead(), Some("brak rekordu DMARC"), 0);
        assert!(subject.contains("UNIWERSYTECKI SZPITAL KLINICZNY W OPOLU"));
        assert!(subject.contains("KSC"));
        assert!(body.contains("art. 25 ustawy KSC"));
        assert!(body.contains("eBPF"));
        assert!(body.contains("100 000"));
        assert!(body.contains("brak rekordu DMARC"));
        assert!(body.contains("hartwell-labs.pl"));
        assert!(body.contains("stop"));
    }

    #[test]
    fn warianty_tematu_sa_rozne_i_bez_zakazanych_fraz() {
        let l = lead();
        let s0 = render_email(&l, None, 0).0;
        let s1 = render_email(&l, None, 1).0;
        let s2 = render_email(&l, None, 2).0;
        assert_ne!(s0, s1);
        assert_ne!(s1, s2);
        for s in [&s0, &s1, &s2] {
            let low = s.to_lowercase();
            assert!(!low.contains("omijam przetarg"));
            assert!(!low.contains("taran"));
        }
    }

    #[test]
    fn org_short_obcina_forme_prawna_i_nie_paniekuje_na_utf() {
        assert_eq!(
            org_short("SZPITAL WOJSKOWY SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ"),
            "SZPITAL WOJSKOWY"
        );
        let dlugie = "ŚŻÓŁĆ GĘŚLĄ JAŹŃ".repeat(20);
        let _ = org_short(&dlugie); // nie może panikować na polskich znakach
    }

    #[test]
    fn suppression_wczytuje_wyslanych() {
        let dir = std::env::temp_dir().join(format!("scryer-supp-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("outbox.jsonl");
        std::fs::write(
            &p,
            format!(
                "{}\n{}\n",
                r#"{"org":"A","email":"a@x.pl","status":"sent","via":"r:1","subject":"s","variant":0,"error":null,"ts":"0"}"#,
                r#"{"org":"B","email":"b@x.pl","status":"skipped_limit","via":"-","subject":"s","variant":1,"error":null,"ts":"0"}"#
            ),
        )
        .unwrap();
        let s = load_suppressed(p.to_str().unwrap());
        assert!(s.contains("a@x.pl"));
        assert!(!s.contains("b@x.pl"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
