//! send — bezpieczna wysyłka kampanijna (Resend API) z gate'ami.
//!
//! Zasady (hard):
//! 1. Domyślnie DRY-RUN — nic nie wychodzi bez SCRYER_CONFIRM=yes.
//! 2. Gate MX: lead bez aktywnego MX nie dostaje maila — nie palimy
//!    reputacji domeny na martwe skrzynki.
//! 3. Limit: domyślnie 20 wysyłek/run (SCRYER_DAILY_LIMIT) — snajper,
//!    nie karabin (taktyka CAMPAIGN-ETAP1).
//! 4. Pełny audyt: każdy attempt = wiersz JSONL w outbox.

use crate::model::Lead;
use serde::Serialize;
use std::io::Write;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct SendRecord {
    pub org: String,
    pub email: String,
    pub status: String, // "sent" | "dry_run" | "skipped_no_mx" | "skipped_limit" | "error"
    pub via: String,
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
            from: std::env::var("SCRYER_FROM").unwrap_or_else(|_| "contact@hartwell-labs.pl".into()),
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
    if s.len() > 60 { format!("{}…", &s[..57]) } else { s }
}

/// Treść maila (text/plain — snajper, nie newsletter).
pub fn render_email(lead: &Lead, ammo: Option<&str>) -> (String, String) {
    let short = org_short(&lead.org);
    let subject = format!("KSC przed 3.10 — czy {short} ma plan ochrony offline?");
    let ammo_line = ammo
        .map(|a| {
            format!(
                "\nPrzy okazji: z zewnątrz widać, że {a}. Chętnie pokażę, co jeszcze \
wyszło w pasywnym audycie domeny.\n"
            )
        })
        .unwrap_or_default();
    let body = format!(
        "Dzień dobry,\n\npiszę krótko, bo przed 3 października {short} składa wniosek o wpis do \
Wykazu podmiotów kluczowych (KSC) — a po wpisie przyjdzie realny obowiązek wykrywania i \
reagowania na incydenty (art. 25 ustawy KSC), także na systemach odciętych od internetu.\n\n\
Talus CI to agent bezpieczeństwa dla Linuksa, który wykrywa ransomware i eksfiltrację na \
poziomie jądra (eBPF) i automatycznie zatrzymuje proces ataku — bez chmury, bez telemetrii, \
bez modułów jądra. Licencja i aktualizacje działają w pełni offline.\n{ammo_line}\n\
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
        Ok(ans) => !ans.is_nxdomain()
            && ans.records.iter().any(|r| {
                matches!(r, crate::dnsmini::Record::Mx { .. })
            }),
        Err(_) => false,
    }
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

/// Główna pętla: leady (ranked) → gate MX → limit → send/log → audyt JSONL.
pub fn run_campaign(leads: &[Lead], outbox_path: &str) -> Vec<SendRecord> {
    let cfg = SendConfig::from_env();
    let mut records = Vec::new();
    let mut sent = 0usize;

    for lead in leads {
        if sent >= cfg.daily_limit {
            records.push(SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "skipped_limit".into(),
                via: "-".into(),
                error: Some("daily limit reached".into()),
                ts: now(),
            });
            continue;
        }
        if !has_mx(lead, &cfg.dns_server) {
            records.push(SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "skipped_no_mx".into(),
                via: "-".into(),
                error: None,
                ts: now(),
            });
            continue;
        }
        let (subject, body) = render_email(lead, None);
        let rec = if !cfg.confirm {
            sent += 1;
            SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "dry_run".into(),
                via: "resend(dry)".into(),
                error: None,
                ts: now(),
            }
        } else if cfg.api_key.is_empty() {
            SendRecord {
                org: lead.org.clone(),
                email: lead.email.clone(),
                status: "error".into(),
                via: "resend".into(),
                error: Some("brak SCRYER_RESEND_KEY".into()),
                ts: now(),
            }
        } else {
            match send_one(&cfg, &lead.email, &subject, &body) {
                Ok(id) => {
                    sent += 1;
                    SendRecord {
                        org: lead.org.clone(),
                        email: lead.email.clone(),
                        status: "sent".into(),
                        via: format!("resend:{id}"),
                        error: None,
                        ts: now(),
                    }
                }
                Err(e) => SendRecord {
                    org: lead.org.clone(),
                    email: lead.email.clone(),
                    status: "error".into(),
                    via: "resend".into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Sector;

    #[test]
    fn render_email_zawiera_kluczowe_elementy() {
        let lead = Lead {
            org: "UNIWERSYTECKI SZPITAL KLINICZNY W OPOLU SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ"
                .into(),
            domain: "usk.opole.pl".into(),
            email: "centrum@usk.opole.pl".into(),
            sector: Sector::Health,
            voivodeship: "opolskie".into(),
            email_verified: false,
            hooks: vec![],
            source: "test".into(),
        };
        let (subject, body) = render_email(&lead, Some("brak rekordu DMARC"));
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
    fn org_short_obcina_forme_prawna() {
        assert_eq!(
            org_short("SZPITAL WOJSKOWY SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ"),
            "SZPITAL WOJSKOWY"
        );
    }
}
