//! discovery — wyszukiwanie czegokolwiek w sieci bez API (w granicach legalności).
//!
//! Dla zapytania (firma/osoba/instytucja/domena) Scryer zbiera publiczne ślady:
//!   1. DNS: A/AAAA/MX/NS/TXT + SPF/DMARC (dnsmini, własny klient)
//!   2. RDAP (api.rdap.net): rejestracja domeny, rejestrar, daty (JSON, publiczny)
//!   3. crt.sh: certyfikaty TLS = subdomeny (publiczny indeks Certificate Transparency)
//!   4. strona WWW (http/https, robots.txt): <title>, meta description, generatory,
//!      mailto:/tel: linki, potencjalne osoby (imie.nazwisko@)
//!   5. DuckDuckGo HTML (bez klucza) — jeśli SCRYER_SEARCH_KEY ustawione, można
//!      podmienić backend (ScrapingBee/Serper: env SCRYER_SEARCH_KEY)
//!
//! Nic z tego nie wymaga klucza. Wszystko publiczne, pasywne (GET), z timeoutem
//! i limitem rozmiaru odpowiedzi. Wynik: JSON → do ontologii przez /api/discover.

use crate::dnsmini::{self, Record};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BODY: usize = 512 * 1024; // 512 KiB — tylko głowa strony nas interesuje
const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) ScryerOSINT/0.7 (+research; contact: research@hartwell-labs.pl)";

fn http_get(url: &str) -> Result<String, String> {
    let resp = ureq::get(url)
        .timeout(TIMEOUT)
        .set("User-Agent", UA)
        .set("Accept", "*/*")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("HTTP {code}"),
            other => other.to_string(),
        })?;
    let mut buf = String::new();
    resp.into_reader()
        .take(MAX_BODY as u64)
        .read_to_string(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

// alias do read — czytelniej w reszcie kodu
use std::io::Read as _;

/// Normalizuj zapytanie użytkownika: wyciągnij domenę z "firma.pl", "www.firma.pl",
/// "jan@firma.pl", albo potraktuj frazę jako search-term.
pub fn normalize(query: &str) -> Query {
    let q = query.trim();
    let lower = q.to_lowercase();

    // e-mail → domena + osoba
    if let Some(at) = lower.find('@') {
        let dom = &lower[at + 1..];
        if !dom.is_empty() && !dom.contains(' ') {
            return Query {
                domain: dom.trim_end_matches('/').to_string(),
                phrase: q.to_string(),
                kind: Kind::Email,
            };
        }
    }
    // coś co wygląda jak domena (kropka, bez spacji, znane TLD-ish)
    if lower.contains('.') && !lower.contains(' ') {
        let dom = lower
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("www.")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        if dom.contains('.') {
            return Query {
                domain: dom,
                phrase: q.to_string(),
                kind: Kind::Domain,
            };
        }
    }
    Query {
        domain: String::new(),
        phrase: q.to_string(),
        kind: Kind::Phrase,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Domain,
    Email,
    Phrase,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub domain: String,
    pub phrase: String,
    pub kind: Kind,
}

/// Główny entry: zbierz wszystko co się da dla zapytania.
pub fn discover(q: &Query) -> Value {
    let mut out = json!({
        "query": q.phrase,
        "kind": format!("{:?}", q.kind).to_lowercase(),
        "domain": q.domain,
    });

    // fraza bez domeny → najpierw spróbuj znaleźć domenę wyszukiwarką,
    // potem i tak odpal DNS/WWW na znalezionej
    let mut dom = q.domain.clone();
    if dom.is_empty() {
        if let Some(found) = guess_domain(&q.phrase) {
            dom = found;
            out["domain_guessed"] = json!(dom);
        }
    }

    if !dom.is_empty() {
        out["dns"] = dns_recon(&dom);
        out["rdap"] = rdap(&dom).unwrap_or(Value::Null);
        let subs = crtsh_subdomains(&dom).unwrap_or_default();
        out["subdomains"] = json!(subs);
        out["www"] = www_recon(&dom);
    }

    out["web_results"] = web_search(&q.phrase);
    out
}

/// Spróbuj odgadnąć domenę z nazwy firmy ("ZWiK Szczecin" → zwik.szczecin.pl nie
/// da się policzyć, ale "KGHM" → kghm.pl tak — bierzemy pierwszy wynik DDG).
fn guess_domain(phrase: &str) -> Option<String> {
    let res = web_search(phrase);
    for r in res["results"].as_array()? {
        for key in ["url", "display_url"] {
            if let Some(u) = r[key].as_str() {
                if let Some(dom) = host_of(u) {
                    // pomiń agregatory/portale — chodzi o domenę samej firmy
                    let skip = [
                        "duckduckgo",
                        "wikipedia.org",
                        "youtube.",
                        "facebook.",
                        "linkedin.",
                        "instagram.",
                        "google.",
                    ];
                    if !skip.iter().any(|s| dom.contains(s)) {
                        return Some(dom);
                    }
                }
            }
        }
    }
    None
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let host = rest.split('/').next()?;
    if host.contains('.') {
        Some(host.trim_start_matches("www.").to_string())
    } else {
        None
    }
}

// ─────────────────────────────────────────────── DNS ─────────────────────

fn dns_server() -> String {
    std::env::var("SCRYER_DNS").unwrap_or_else(|_| "1.1.1.1".into())
}

fn dns_q(name: &str, qtype: u16) -> Vec<Record> {
    dnsmini::query(name, qtype, &dns_server(), Duration::from_secs(4))
        .map(|a| {
            if a.is_nxdomain() {
                Vec::new()
            } else {
                a.records
            }
        })
        .unwrap_or_default()
}

fn dns_recon(dom: &str) -> Value {
    let a: Vec<String> = dns_q(dom, 1)
        .into_iter()
        .filter_map(|r| match r {
            Record::A(ip) => Some(ip.to_string()),
            _ => None,
        })
        .collect();
    let aaaa: Vec<String> = dns_q(dom, 28)
        .into_iter()
        .filter_map(|r| match r {
            Record::A(ip) => Some(ip.to_string()),
            _ => None,
        })
        .collect();
    let mx: Vec<String> = dns_q(dom, 15)
        .into_iter()
        .filter_map(|r| match r {
            Record::Mx { pref, exchange } => Some(format!("{pref} {exchange}")),
            _ => None,
        })
        .collect();
    let ns: Vec<String> = dns_q(dom, 2)
        .into_iter()
        .filter_map(|r| match r {
            Record::Ns(n) => Some(n),
            _ => None,
        })
        .collect();
    let txt: Vec<String> = dns_q(dom, 16)
        .into_iter()
        .filter_map(|r| match r {
            Record::Txt(s) => Some(s),
            _ => None,
        })
        .collect();
    let dmarc: Vec<String> = dns_q(&format!("_dmarc.{dom}"), 16)
        .into_iter()
        .filter_map(|r| match r {
            Record::Txt(s) => Some(s),
            _ => None,
        })
        .collect();

    json!({
        "a": a, "aaaa": aaaa, "mx": mx, "ns": ns,
        "spf": txt.iter().filter(|t| t.starts_with("v=spf1")).collect::<Vec<_>>(),
        "txt": txt.iter().filter(|t| !t.starts_with("v=spf1")).take(5).collect::<Vec<_>>(),
        "dmarc": dmarc,
        "has_mail": !mx.is_empty(),
        "dmarc_ok": !dmarc.is_empty(),
    })
}

// ─────────────────────────────────────────────── RDAP ────────────────────

fn rdap(dom: &str) -> Result<Value, String> {
    let body = http_get(&format!("https://rdap.org/domain/{dom}"))?;
    let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    // wyciągnij tylko sensowne pola (full RDAP bywa ogromny)
    let registrar = v["entities"]
        .as_array()
        .and_then(|ents| {
            ents.iter()
                .find(|e| {
                    e["roles"]
                        .as_array()
                        .map(|r| r.iter().any(|x| x == "registrar"))
                        .unwrap_or(false)
                })
                .and_then(|e| e["vcardArray"][1].as_array())
                .and_then(|cards| {
                    cards.iter().find_map(|c| {
                        (c[0] == "fn").then(|| c[3].as_str().unwrap_or("").to_string())
                    })
                })
        })
        .unwrap_or_default();
    let dates: Vec<String> = v["events"]
        .as_array()
        .map(|evs| {
            evs.iter()
                .filter_map(|e| {
                    let a = e["eventAction"].as_str()?;
                    let d = e["eventDate"].as_str()?;
                    Some(format!("{a}: {d}"))
                })
                .collect()
        })
        .unwrap_or_default();
    let status: Vec<String> = v["status"]
        .as_array()
        .map(|s| {
            s.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({ "registrar": registrar, "dates": dates, "status": status }))
}

// ─────────────────────────────────────────────── crt.sh ──────────────────

fn crtsh_subdomains(dom: &str) -> Result<Vec<String>, String> {
    let body = http_get(&format!("https://crt.sh/?q=%25.{dom}&output=json"))?;
    let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let mut set = BTreeSet::new();
    if let Some(arr) = v.as_array() {
        for row in arr {
            if let Some(names) = row["name_value"].as_str() {
                for n in names.split('\n') {
                    let n = n.trim().to_lowercase();
                    if n.ends_with(&format!(".{dom}")) && !n.starts_with('*') {
                        set.insert(n);
                    }
                }
            }
        }
    }
    Ok(set.into_iter().collect())
}

// ─────────────────────────────────────────────── WWW ─────────────────────

/// Kradniemy tylko metadane strony: title, description, generator (CMS!),
/// kontakty z mailto/tel. Legalne pasywne zbieranie (jak Googlebot, tylko rzadziej).
fn www_recon(dom: &str) -> Value {
    for url in [
        format!("https://{dom}"),
        format!("https://www.{dom}"),
        format!("http://{dom}"),
    ] {
        match http_get(&url) {
            Ok(body) => return parse_www(&body, &url),
            Err(_) => continue,
        }
    }
    json!({ "ok": false, "note": "brak odpowiedzi http(s)" })
}

fn parse_www(body: &str, url: &str) -> Value {
    let title = between(body, "<title>", "</title>").map(|s| s.trim().to_string());
    let description = find_meta(body, "description");
    let generator = find_meta(body, "generator");
    let emails: BTreeSet<String> = body
        .match_indices("mailto:")
        .filter_map(|(i, _)| {
            let rest = &body[i + 7..];
            let end = rest.find(['"', '\'', '>', '?']).unwrap_or(rest.len());
            let em = rest[..end].to_lowercase();
            (em.contains('@') && !em.contains(' ')).then_some(em)
        })
        .collect();
    let phones: BTreeSet<String> = body
        .match_indices("tel:")
        .filter_map(|(i, _)| {
            let rest = &body[i + 4..];
            let end = rest.find(['"', '\'', '>']).unwrap_or(rest.len());
            let ph: String = rest[..end]
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '+')
                .collect();
            (ph.len() >= 7).then_some(ph)
        })
        .collect();
    // gołe maile z tekstu (nie tylko mailto:): tokeny wyglądające jak x@y.z
    let plain_emails: BTreeSet<String> = body
        .split(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '@' || c == '.' || c == '-' || c == '_')
        })
        .filter_map(|tok| {
            let t = tok
                .trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_lowercase();
            let (local, dom) = t.split_once('@')?;
            if local.is_empty() || dom.split('.').count() < 2 || t.contains(' ') {
                return None;
            }
            if t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '-' | '_'))
            {
                Some(t)
            } else {
                None
            }
        })
        .collect();
    let persons: BTreeSet<String> = body
        .split(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == '>')
        .filter_map(|tok| {
            let t = tok
                .trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_lowercase();
            // imie.nazwisko@ (typowy wzorzec instytucjonalny) — bez końcówki @dom
            let (local, dompart) = t.split_once('@')?;
            if dompart.split('.').count() >= 2
                && local.split('.').count() == 2
                && local
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                && local.len() >= 5
            {
                Some(t)
            } else {
                None
            }
        })
        .collect();

    json!({
        "ok": true,
        "url": url,
        "title": title,
        "description": description,
        "generator": generator,   // WordPress/Drupal/Joomla — czasem namiastka ataku/podobieństwa
        "emails": emails.union(&plain_emails).cloned().collect::<Vec<_>>(),
        "phones": phones.into_iter().collect::<Vec<_>>(),
        "persons": persons.into_iter().collect::<Vec<_>>(),
    })
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.to_lowercase().find(&a.to_lowercase())? + a.len();
    let rest = &s[i..];
    let j = rest.to_lowercase().find(&b.to_lowercase())?;
    Some(&rest[..j])
}

fn find_meta(body: &str, name: &str) -> Option<String> {
    // meta name/description="..." content="..."
    for (mi, _) in body.match_indices("<meta") {
        let end = body[mi..].find('>')? + mi;
        let tag = &body[mi..end];
        let has_name = tag.to_lowercase().contains(&format!("name=\"{name}\""))
            || tag.to_lowercase().contains(&format!("name='{name}'"))
            || tag.to_lowercase().contains(&format!("property=\"{name}\""));
        if has_name {
            if let Some(ci) = tag.to_lowercase().find("content=\"") {
                let rest = &tag[ci + 9..];
                let ce = rest.find('"').unwrap_or(rest.len());
                return Some(rest[..ce].to_string());
            }
        }
    }
    None
}

// ─────────────────────────────────────── web search (bez klucza) ─────────

/// DuckDuckGo HTML endpoint — działa bez klucza. Jak SCRYER_SEARCH_KEY jest
/// w env, używamy backendu kluczowego (ScrapingBee) zamiast DDG (stabilniej).
fn web_search(query: &str) -> Value {
    if let Ok(key) = std::env::var("SCRYER_SEARCH_KEY") {
        if !key.is_empty() {
            return search_scrapingbee(query, &key).unwrap_or(Value::Null);
        }
    }
    search_ddg(query)
}

fn search_ddg(query: &str) -> Value {
    let url = format!("https://html.duckduckgo.com/html/?q={}", urlencoded(query));
    let body = match http_get(&url) {
        Ok(b) => b,
        Err(e) => return json!({ "engine": "ddg", "error": e }),
    };
    let mut results = Vec::new();
    // parsowanie bez DOM: linki result__a
    for (mi, _) in body.match_indices("result__a") {
        let seg = &body[mi..(mi + 2500).min(body.len())];
        let href_i = match seg.find("href=\"") {
            Some(i) => i + 6,
            None => continue,
        };
        let rest = &seg[href_i..];
        let href = &rest[..rest.find('"').unwrap_or(rest.len())];
        let title_i = match rest.find('>') {
            Some(i) => i + 1,
            None => continue,
        };
        let titrest = &rest[title_i..];
        let title = &titrest[..titrest.find('<').unwrap_or(titrest.len())];
        // DDG owija URL w //duckduckgo.com/l/?uddg=<encoded>
        let real = if let Some(p) = href.find("uddg=") {
            let enc = &href[p + 5..];
            let end = enc.find('&').unwrap_or(enc.len());
            percent_decode(&enc[..end])
        } else {
            href.to_string()
        };
        if !real.is_empty() {
            results.push(json!({ "title": html_unescape(title.trim()), "url": real }));
        }
        if results.len() >= 10 {
            break;
        }
    }
    json!({ "engine": "ddg", "results": results })
}

fn search_scrapingbee(query: &str, key: &str) -> Result<Value, String> {
    let q = urlencoded(query);
    let url = format!(
        "https://app.scrapingbee.com/api/v1/?api_key={key}&url=https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3D{q}%26num%3D10"
    );
    let body = http_get(&url)?;
    let mut results = Vec::new();
    // bardzo luźny parser Google HTML: <a href="/url?q=...">  albo <a href="https://...">
    for (mi, _) in body.match_indices("<a href=\"") {
        let rest = &body[mi + 9..];
        let href = &rest[..rest.find('"').unwrap_or(rest.len())];
        let skip_prefixes = [
            "google.",
            "/search?",
            "/webhp",
            "accounts.",
            "policies.",
            "support.",
        ];
        if skip_prefixes.iter().any(|p| href.contains(p)) {
            continue;
        }
        if !href.starts_with("http") {
            continue;
        }
        let trest = &rest[rest.find('"').map(|i| i + 1).unwrap_or(0)..];
        let title = between(trest, ">", "<").unwrap_or("").trim();
        if title.is_empty() {
            continue;
        }
        results.push(json!({ "title": html_unescape(title), "url": href }));
        if results.len() >= 10 {
            break;
        }
    }
    Ok(json!({ "engine": "google-via-scrapingbee", "results": results }))
}

fn urlencoded(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 1 && i + 2 < b.len() + 1 {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..(i + 3).min(s.len())], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

// ───────────────────────────── internet search (OSINT-first) ─────────────

/// Wynik wyszukiwania internetowego gotowy do cache'owania w ontologii.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub domain: String,
    pub title: String,
    pub url: String,
    pub mx: bool,
    pub mx_provider: String,
    pub dmarc: Option<String>,
    pub www_audit: Value,
}

/// Szukaj frazy w sieci → wyciągnij UNIKALNE domeny z wyników → dla każdej
/// szybki DNS (MX + DMARC) → krótki audyt WWW. Rate-limit-safe: max 8 domen,
/// przerwy między żądaniami nie potrzebne przy 8 (DDG throttle zaczyna się
/// przy seriach 20+).
pub fn internet_search(phrase: &str) -> (Value, Vec<SearchHit>) {
    let res = web_search(phrase);
    let mut seen = BTreeSet::new();
    let mut hits: Vec<SearchHit> = Vec::new();
    let skip = [
        "duckduckgo",
        "wikipedia.org",
        "youtube.",
        "facebook.",
        "linkedin.",
        "instagram.",
        "google.",
        "twitter.",
        "x.com",
        "tiktok.",
        "pinterest.",
    ];
    if let Some(arr) = res["results"].as_array() {
        for r in arr {
            if hits.len() >= 8 {
                break;
            }
            let url = r["url"].as_str().unwrap_or("");
            let Some(dom) = host_of(url) else { continue };
            if skip.iter().any(|s| dom.contains(s)) {
                continue;
            }
            if !seen.insert(dom.clone()) {
                continue;
            }
            let (mx, mxp) = mx_provider(&dom);
            let dmarc = first_txt(&format!("_dmarc.{dom}"));
            let audit = www_audit(&dom);
            hits.push(SearchHit {
                domain: dom.clone(),
                title: r["title"].as_str().unwrap_or("").to_string(),
                url: url.to_string(),
                mx,
                mx_provider: mxp,
                dmarc,
                www_audit: audit,
            });
        }
    }
    (res, hits)
}

/// Pierwszy rekord TXT danego klienta (dla DMARC).
fn first_txt(name: &str) -> Option<String> {
    dns_q(name, 16).into_iter().find_map(|r| match r {
        Record::Txt(s) => Some(s),
        _ => None,
    })
}

/// Czy domena ma MX i kto jest dostawcą poczty (po NS hostname'a MX).
pub fn mx_provider(dom: &str) -> (bool, String) {
    let mxs = dns_q(dom, 15);
    if mxs.is_empty() {
        return (false, String::new());
    }
    let mut provider = String::new();
    for r in mxs.iter() {
        if let Record::Mx { exchange, .. } = r {
            let ex = exchange.to_lowercase();
            let known = [
                ("google", "Google Workspace"),
                ("googlemail", "Google Workspace"),
                ("outlook", "Microsoft 365"),
                ("protection.outlook", "Microsoft 365"),
                ("mailgun", "Mailgun"),
                ("sendgrid", "SendGrid"),
                ("zoho", "Zoho"),
                ("yandex", "Yandex"),
                ("seznam", "Seznam"),
                ("ovh", "OVH"),
                ("home.pl", "home.pl"),
                ("nazwa.pl", "nazwa.pl"),
                ("domeny", "nazwa.pl"),
                ("sekundo", "Sekundo"),
                ("mikrus", "Mikrus"),
                ("server", "self-host"),
                ("poczta", "self-host"),
                ("mail", "self-host"),
            ];
            for (k, v) in known {
                if ex.contains(k) {
                    provider = v.to_string();
                    break;
                }
            }
            if provider.is_empty() {
                provider = ex.trim_end_matches('.').to_string();
            }
            break;
        }
    }
    (true, provider)
}

/// Szybki audyt bezpieczeństwa/postawy WWW: dostępność + HTTPS + nagłówki
/// (HSTS, X-Frame-Options, CSP, server banner). GET tylko nagłówka →HEAD
/// gdzie się da; wysyłamy GET i patrzymy na nagłówki (male body read).
pub fn www_audit(dom: &str) -> Value {
    let url = format!("https://{dom}");
    let resp = ureq::get(&url)
        .timeout(TIMEOUT)
        .set("User-Agent", UA)
        .call();
    match resp {
        Ok(r) => {
            let hdrs = {
                let names = [
                    "strict-transport-security",
                    "x-frame-options",
                    "content-security-policy",
                    "server",
                    "x-powered-by",
                ];
                names
                    .iter()
                    .filter_map(|n| r.header(n).map(|v| format!("{n}: {v}")))
                    .collect::<Vec<_>>()
            };
            json!({
                "ok": true, "url": url, "status": r.status(),
                "https": true,
                "hsts": hdrs.iter().any(|h| h.starts_with("strict-transport-security")),
                "xfo": hdrs.iter().any(|h| h.starts_with("x-frame-options")),
                "csp": hdrs.iter().any(|h| h.starts_with("content-security-policy")),
                "headers": hdrs,
            })
        }
        Err(ureq::Error::Status(code, _)) => json!({
            "ok": true, "url": url, "status": code, "https": true,
            "hsts": false, "xfo": false, "csp": false, "headers": [],
        }),
        Err(_) => {
            // https padł → spróbuj http (sygnał: brak TLS = amunicja)
            match http_get(&format!("http://{dom}")) {
                Ok(_) => json!({
                    "ok": true, "url": format!("http://{dom}"), "status": 200,
                    "https": false, "hsts": false, "xfo": false, "csp": false,
                    "headers": [], "note": "brak HTTPS — ruch jawny",
                }),
                Err(_) => json!({ "ok": false, "note": "host nie odpowiada" }),
            }
        }
    }
}

// ─────────────────────────────────────────────── tests ───────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rozpoznaje_typy() {
        assert_eq!(normalize("firma.pl").kind, Kind::Domain);
        assert_eq!(normalize("https://www.firma.pl/o-nas").kind, Kind::Domain);
        assert_eq!(normalize("jan.kowalski@firma.pl").kind, Kind::Email);
        assert_eq!(normalize("jan.kowalski@firma.pl").domain, "firma.pl");
        assert_eq!(normalize("ZWiK Szczecin").kind, Kind::Phrase);
    }

    #[test]
    fn urlencoded_standard() {
        assert_eq!(urlencoded("a b&c"), "a+b%26c");
        assert_eq!(urlencoded("ą"), "%C4%85");
    }

    #[test]
    fn percent_decode_roundtrip() {
        // + w query-string to spacja (urlencode koduje spację jako +)
        assert_eq!(percent_decode("a+b%26c"), "a b&c");
        assert_eq!(percent_decode("%C4%85"), "ą");
    }

    #[test]
    fn parse_www_wyciaga_kontakty() {
        let body = r#"<html><head><title>Szpital X</title>
            <meta name="description" content="Strona szpitala">
            <meta name="generator" content="WordPress 6.0"></head>
            <body><a href="mailto:centrum@sx.pl">mail</a>
            <a href="tel:+48911234567">tel</a>
            Kontakt: jan.kowalski@sx.pl</body></html>"#;
        let v = parse_www(body, "https://sx.pl");
        assert_eq!(v["title"], "Szpital X");
        assert_eq!(v["generator"], "WordPress 6.0");
        assert_eq!(v["emails"].as_array().unwrap().len(), 2); // mailto + plain
        assert!(v["phones"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "+48911234567"));
        assert!(v["persons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "jan.kowalski@sx.pl"));
    }

    #[test]
    fn html_unescape_podstawowe() {
        assert_eq!(html_unescape("a &amp; b"), "a & b");
    }
}
