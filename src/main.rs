//! scryer-core — Hartwell Labs Lead Intelligence & External Attack Surface.
//!
//! Binarne CLI na bibliotece scryer_core (moduły: model/score/dnsmini/export/store).
//! Komendy:
//!   score    <leads.json>              — pipeline + CSV pod Brevo (SCRYER_OUT)
//!   briefs   <leads.json> <katalog>    — snapshot JSON + briefy .md per lead (z DNS-auditem)
//!   demo                               — generuje seed demo i odpala score (dla leniwych)

use scryer_core::model::Lead;
use scryer_core::{export, score, store};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("score") if args.len() >= 3 => cmd_score(&args[2]),
        Some("briefs") if args.len() >= 4 => cmd_briefs(&args[2], &args[3]),
        Some("demo") => cmd_demo(),
        _ => {
            eprintln!("użycie:");
            eprintln!("  scryer-core score <leads.json>              (SCRYER_OUT=plik.csv, SCRYER_DNS=serwer)");
            eprintln!("  scryer-core briefs <leads.json> <katalog>    (SCRYER_DNS=serwer)");
            eprintln!("  scryer-core demo");
            std::process::exit(2);
        }
    }
}

fn cmd_score(path: &str) {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("nie mogę czytać {path}: {e}"));
    let leads = score::load_json(&raw).unwrap_or_else(|e| panic!("JSON: {e}"));
    let (ranked, rep) = score::run(leads);
    println!("scryer: {}", rep.line());
    println!("manifest: {}", score::manifest_hash(&ranked));
    let csv = score::export_csv(&ranked);
    let out = std::env::var("SCRYER_OUT").unwrap_or_else(|_| "brevo-import.csv".into());
    std::fs::write(&out, csv).expect("zapis CSV");
    println!("CSV → {out}");
    for l in ranked.iter().take(10) {
        println!("  [{:>3}] {:4} {:24} {}", l.score(), l.tier(), l.org, l.email);
    }
}

fn cmd_briefs(path: &str, outdir: &str) {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("nie mogę czytać {path}: {e}"));
    let leads: Vec<Lead> = score::load_json(&raw).unwrap_or_else(|e| panic!("JSON: {e}"));
    let (ranked, rep) = score::run(leads);
    let server = std::env::var("SCRYER_DNS").unwrap_or_else(|_| "1.1.1.1".into());
    println!("scryer: {} | dns-audit via {server}...", rep.line());

    let audits = store::audit_all(&ranked, &server);
    let dir = Path::new(outdir);
    std::fs::create_dir_all(dir).expect("tworzenie katalogu");

    // snapshot JSON
    store::write_json(&dir.join("snapshot.json"), &export::snapshot_json(&ranked, &audits))
        .expect("zapis snapshot");
    // briefy .md per lead
    let mut n = 0;
    for l in &ranked {
        let audit = l.effective_domain().and_then(|d| audits.get(&d));
        let md = export::brief_markdown(l, audit);
        let slug = slugify(&l.org);
        std::fs::write(dir.join(format!("{slug}.md")), md).expect("zapis briefu");
        n += 1;
    }
    println!("briefs → {outdir}/ ({n} plików) + snapshot.json");
    // top-5 z amunicją
    for l in ranked.iter().take(5) {
        if let Some(d) = l.effective_domain() {
            if let Some(a) = audits.get(&d) {
                if a.is_attack_surface_signal() {
                    println!("  [AMUNICJA] {} ({}): {}", l.org, d, a.findings.join("; "));
                }
            }
        }
    }
}

fn cmd_demo() {
    println!("seed demo: seed/leads-demo.json → score");
    cmd_score("seed/leads-demo.json");
}

fn slugify(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
