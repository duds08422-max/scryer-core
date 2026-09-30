//! scryer-core — Hartwell Labs Lead Intelligence & External Attack Surface.
//!
//! Binarne CLI na bibliotece scryer_core (moduły: model/score/dnsmini/export/store).
//! Komendy:
//!   score    <leads.json>              — pipeline + CSV pod Brevo (SCRYER_OUT)
//!   briefs   <leads.json> <katalog>    — snapshot JSON + briefy .md per lead (z DNS-auditem)
//!   demo                               — generuje seed demo i odpala score (dla leniwych)

use scryer_core::model::Lead;
use scryer_core::{bzp, export, intel, ontology, query, score, send, server, store, viz};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("score") if args.len() >= 3 => cmd_score(&args[2]),
        Some("briefs") if args.len() >= 4 => cmd_briefs(&args[2], &args[3]),
        Some("send") if args.len() >= 3 => cmd_send(&args[2]),
        Some("tenders") if args.len() >= 3 => cmd_tenders(&args[2]),
        Some("import") if args.len() >= 3 => cmd_import(&args[2..]),
        Some("ask") if args.len() >= 3 => cmd_ask(&args[2]),
        Some("viz") => cmd_viz(),
        Some("serve") => cmd_serve(),
        Some("discover") if args.len() >= 3 => cmd_discover(&args[2]),
        Some("report") => println!("{}", send::report("outbox.jsonl")),
        Some("demo") => cmd_demo(),
        _ => {
            eprintln!("użycie:");
            eprintln!("  scryer-core score <leads.json>              (SCRYER_OUT=plik.csv, SCRYER_DNS=serwer)");
            eprintln!("  scryer-core briefs <leads.json> <katalog>    (SCRYER_DNS=serwer)");
            eprintln!("  scryer-core send <leads.json>                (DRY-RUN domyślnie; SCRYER_CONFIRM=yes = wyślij;");
            eprintln!("                  SCRYER_RESEND_KEY=klucz, SCRYER_FROM=adres, SCRYER_DAILY_LIMIT=20, SCRYER_OUTBOX=outbox.jsonl)");
            eprintln!("  scryer-core report                            (statystyki kampanii z outbox.jsonl)");
            eprintln!("  scryer-core tenders <bzp.json>                (scoring przetargow BZP pod Talus; SCRYER_OUT=csv)");
            eprintln!("  scryer-core import <seeds...>               (migracja seedów/outboxu do ontologii; SCRYER_DB=scryer.db)");
            eprintln!("  scryer-core ask <zapytanie>                 (NL-ai: 'wodociagi bez kontaktu' | dQuery: hot-nodmarc | bez-kontaktu-30d | stats)");
            eprintln!("  scryer-core viz                              (graf ontologii -> HTML; SCRYER_VIZ=out.html)");
            eprintln!("  scryer-core serve                            (zywa konsola + API; SCRYER_DB, SCRYER_HOST=127.0.0.1, SCRYER_PORT=8787)");
            eprintln!("  scryer-core discover <domena|email|fraza>    (OSINT: DNS+RDAP+crt.sh+WWW+search → ontologia; SCRYER_DNS, SCRYER_SEARCH_KEY)");
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

fn db_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("SCRYER_DB").unwrap_or_else(|_| "scryer.db".into()))
}

fn cmd_import(paths: &[String]) {
    let o = ontology::Ontology::open(&db_path()).expect("otwarcie ontologii");
    let mut total = 0usize;
    for p in paths {
        let raw = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("nie mogę czytać {p}: {e}"));
        match o.import_leads_json(&raw) {
            Ok(n) => {
                println!("  {p}: {n} leadów → ontologia");
                total += n;
            }
            Err(e) => eprintln!("  {p}: BŁĄD {e}"),
        }
    }
    // migracja outboxu → interakcje (suppression w grafie)
    let mut n_int = 0usize;
    if let Ok(raw) = std::fs::read_to_string("outbox.jsonl") {
        for line in raw.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v["status"] == "sent" {
                    let _ = o.log_interakcja(&ontology::NewInterakcja {
                        typ: "email_sent".into(),
                        kierunek: "out".into(),
                        email: v["email"].as_str().unwrap_or("").to_lowercase(),
                        temat: v["subject"].as_str().unwrap_or("").into(),
                        ts: v["ts"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
                        wynik: "-".into(),
                        ref_id: v["via"].as_str().unwrap_or("").into(),
                    });
                    n_int += 1;
                }
            }
        }
    }
    println!("import: {total} podmiotów/kontaktów, {n_int} interakcji → {}", db_path().display());
}

fn cmd_ask(q: &str) {
    let o = ontology::Ontology::open(&db_path()).expect("otwarcie ontologii");
    if q != "hot-nodmarc" && q != "bez-kontaktu-30d" && q != "stats" {
        // spróbuj NL (intel); jak zrozumie — wykona; jak nie — dQuery
        let plan = intel::plan(q);
        if !plan.preds.is_empty() || plan.target == intel::Target::External {
            println!("AI: {}", plan.said);
            match intel::execute(&o, &plan) {
                Ok(out) => {
                    if out["mode"] == "external" {
                        let eq = out["q"].as_str().unwrap_or("");
                        let nq = scryer_core::discovery::normalize(eq);
                        let rep = scryer_core::discovery::discover(&nq);
                        let dom = rep["domain"].as_str().unwrap_or("");
                        if !dom.is_empty() {
                            persist_report(&o, &rep);
                        }
                        println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
                    } else {
                        println!("wyników: {}", out["count"]);
                        if let Some(items) = out["items"].as_array() {
                            for it in items.iter().take(30) {
                                println!("  {}", item_line(it));
                            }
                        }
                    }
                }
                Err(e) => eprintln!("błąd: {e}"),
            }
            return;
        }
        match query::parse(q) {
            Ok(parsed) => {
                let rows = query::run(&o, &parsed).unwrap_or_else(|e| panic!("{e}"));
                println!("wyników: {}", rows.len());
                for r in rows {
                    println!("  {r}");
                }
            }
            Err(e) => eprintln!("błąd zapytania: {e}"),
        }
        return;
    }
    match q {
        "hot-nodmarc" => {
            let rows = o.hot_bez_dmarc().expect("zapytanie");
            println!("HOT podmioty z brakiem DMARC ({}):", rows.len());
            for (org, dom) in rows.iter().take(30) {
                println!("  {org} — {dom}");
            }
        }
        "bez-kontaktu-30d" => {
            let rows = o.bez_kontaktu_od(30).expect("zapytanie");
            println!("adresy bez kontaktu 30 dni ({}):", rows.len());
            for e in rows.iter().take(30) {
                println!("  {e}");
            }
        }
        "stats" => {
            for t in ["podmiot", "domena", "osoba", "przetarg", "interakcja"] {
                let n: i64 = o
                    .count_table(t)
                    .unwrap_or_else(|e| panic!("{e}"));
                println!("  {t}: {n}");
            }
        }
        other => {
            eprintln!("nieznane zapytanie: {other}. Dostępne: hot-nodmarc | bez-kontaktu-30d | stats");
            std::process::exit(2);
        }
    }
}

fn persist_report(o: &ontology::Ontology, rep: &serde_json::Value) {
    // identyczna logika persistu jak w server::persist_discovery (CLI skrót)
    let dom = rep["domain"].as_str().unwrap_or("");
    if dom.is_empty() {
        return;
    }
    let dns = &rep["dns"];
    let pid = o.podmiot_id_by_domena(dom);
    let has_mail = dns["has_mail"].as_bool().unwrap_or(false);
    let _ = match pid {
        Some(p) => o.upsert_domena(dom, has_mail, p),
        None => o.upsert_domena_free(dom, has_mail),
    };
    o.set_domena_mail(
        dom,
        dns["spf"].as_array().and_then(|a| a[0].as_str()),
        dns["dmarc"].as_array().and_then(|a| a[0].as_str()),
    );
    o.log_audyt("cli-ai", "recon", dom);
}

/// jednolinijkowy wydruk podmiotu/interakcji z JSON wyniku AI
fn item_line(it: &serde_json::Value) -> String {
    if let Some(nazwa) = it["nazwa"].as_str() {
        format!(
            "[{:>3}] {:36} {:14} {:16} pop={}",
            it["score"].as_i64().unwrap_or(0),
            nazwa,
            it["sektor"].as_str().unwrap_or("-"),
            it["miasto"].as_str().unwrap_or("-"),
            it["pop"].as_i64().unwrap_or(0),
        )
    } else if let Some(email) = it["email"].as_str() {
        format!("  ✉ {} — {}", email, it["temat"].as_str().unwrap_or(""))
    } else if let Some(tytul) = it["tytul"].as_str() {
        format!("  [{}] {} — {}", it["score"].as_i64().unwrap_or(0), tytul, it["org"].as_str().unwrap_or(""))
    } else {
        it.to_string()
    }
}

fn cmd_discover(q: &str) {
    use scryer_core::discovery;
    let query = discovery::normalize(q);
    println!("discovery: {} (kind: {:?})", query.phrase, query.kind);
    let rep = discovery::discover(&query);

    // zapis do ontologii
    let o = ontology::Ontology::open(&db_path()).expect("otwarcie ontologii");
    let dom = rep["domain"].as_str().unwrap_or("");
    if !dom.is_empty() {
        let dns = &rep["dns"];
        let pid = o.podmiot_id_by_domena(dom);
        let has_mail = dns["has_mail"].as_bool().unwrap_or(false);
        let _ = match pid {
            Some(p) => o.upsert_domena(dom, has_mail, p),
            None => o.upsert_domena_free(dom, has_mail),
        };
        o.set_domena_mail(
            dom,
            dns["spf"].as_array().and_then(|a| a[0].as_str()),
            dns["dmarc"].as_array().and_then(|a| a[0].as_str()),
        );
        o.log_audyt("cli", "discover", dom);
    }

    println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
}

fn cmd_serve() {
    let db = db_path();
    // pusta baza jest OK — OSINT-first zbuduje ją z internetu (schemat tworzy
    // Ontology::open); stary wymóg "najpierw import" nie obowiązuje
    if let Some(dir) = db.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            let _ = std::fs::create_dir_all(dir);
        }
    }
    let host = std::env::var("SCRYER_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("SCRYER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(server::serve(db, &host, port)) {
        eprintln!("serve: {e}");
        std::process::exit(1);
    }
}

fn cmd_viz() {
    let o = ontology::Ontology::open(&db_path()).expect("otwarcie ontologii");
    let out = std::env::var("SCRYER_VIZ").unwrap_or_else(|_| "ontology.html".into());
    match viz::export_html(&o, &out) {
        Ok(n) => println!("viz: {n} podmiotów → {out} (otwórz w przeglądarce)"),
        Err(e) => eprintln!("viz błąd: {e}"),
    }
}

fn cmd_tenders(path: &str) {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("nie mogę czytać {path}: {e}"));
    let tenders = bzp::load(&raw).unwrap_or_else(|e| panic!("JSON: {e}"));
    let mut rows: Vec<(u32, &bzp::Tender, Vec<String>)> = tenders
        .iter()
        .map(|t| {
            let m = bzp::score(t);
            (m.score, t, m.reasons)
        })
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.title.cmp(&b.1.title)));
    println!("scryer: {} ogłoszeń → dopasowanie pod Talus", rows.len());
    let out = std::env::var("SCRYER_OUT").unwrap_or_else(|_| "tenders-ranked.csv".into());
    let mut csv = String::from("SCORE;TIER;TITLE;ORG;DEADLINE;URL;REASONS\n");
    let mut shown = 0;
    for (sc, t, reasons) in &rows {
        let tier = bzp::tier(&bzp::Match { score: *sc, reasons: Vec::new() });
        if *sc >= 8 {
            println!("  [{:>2} {}] {} — {}", sc, tier, t.org, t.title);
            println!("        deadline: {} | {}", t.deadline, t.url);
            shown += 1;
        }
        let esc = |s: &str| s.replace(';', ",").replace('\n', " ");
        csv.push_str(&format!(
            "{};{};{};{};{};{};{}\n",
            sc,
            tier,
            esc(&t.title),
            esc(&t.org),
            esc(&t.deadline),
            esc(&t.url),
            esc(&reasons.join(" | ")),
        ));
    }
    std::fs::write(&out, csv).expect("zapis CSV");
    println!("pasujących (>=8): {shown} | CSV → {out}");
}

fn cmd_send(path: &str) {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("nie mogę czytać {path}: {e}"));
    let leads: Vec<Lead> = score::load_json(&raw).unwrap_or_else(|e| panic!("JSON: {e}"));
    let (ranked, rep) = score::run(leads);
    println!("scryer: {} — kampania (top {})", rep.line(), ranked.len());
    let outbox = std::env::var("SCRYER_OUTBOX").unwrap_or_else(|_| "outbox.jsonl".into());
    let records = send::run_campaign_graph(&ranked, &outbox);
    let (mut sent, mut dry, mut skip_mx, mut skip_lim, mut err) = (0, 0, 0, 0, 0);
    for r in &records {
        match r.status.as_str() {
            "sent" => sent += 1,
            "dry_run" => dry += 1,
            "skipped_no_mx" => skip_mx += 1,
            "skipped_limit" => skip_lim += 1,
            _ => err += 1,
        }
    }
    println!("sent={sent} dry_run={dry} skipped_no_mx={skip_mx} skipped_limit={skip_lim} skipped_suppressed={} errors={err}",
        records.iter().filter(|r| r.status == "skipped_suppressed").count());
    println!("audyt → {outbox}");
    if dry > 0 {
        println!("⚠ DRY-RUN: nic nie wyszło. Aby wysłać naprawdę: SCRYER_CONFIRM=yes");
    }
    for r in records.iter().take(10) {
        println!("  [{:14}] {:40} {}", r.status, r.email, r.via);
    }
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
