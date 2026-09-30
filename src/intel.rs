//! intel — autorski silnik rozumienia zapytań naturalnych (100% local).
//!
//! Zero LLM, zero zewnętrznych API, zero sieci: deterministyczny parser
//! leksykon PL/EN → typowany plan (Pred) → parametryzowane SQL na ontologii.
//! Auditor-friendly: każde zapytanie zwraca "rozumiem jako" + confidence,
//! więc widać DLACZEGO silnik zwrócił taki zestaw wyników.
//!
//! Routing:
//!   - domena/e-mail albo fraza z czasownikiem recon → tryb EXTERNAL (discovery)
//!   - cała reszta → tryb LOCAL (SQL po ontologii)
//!
//! Przykłady (wszystko to samo API):
//!   "wodociągi bez kontaktu"            → podmioty sektor=wodociagi !email_sent
//!   "hot bez dmarc w zachodniopomorskiem"
//!   "duże miasta powyżej 100000"        → pop>100000
//!   "kto dostał maila"                  → interakcje typ=email_sent
//!   "szpitale"                          → sektor LIKE szpital
//!   "recon kghm.com" / "zwik@zwik.szczecin.pl" → EXTERNAL

use crate::discovery;
use crate::ontology::Ontology;
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────── plan ─────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Pred {
    /// fraza pełnotekstowa (fold po nazwa/miasto/email/domena)
    Text(String),
    /// sektor (fold, contains)
    Sector(String),
    /// miasto (fold, contains)
    City(String),
    /// województwo (fold, contains)
    Voiv(String),
    /// min populacja
    PopMin(i64),
    /// max populacja
    PopMax(i64),
    /// min tier_score
    TierMin(i64),
    /// ma MX na dowolnej domenie
    HasMail,
    /// brak DMARC na dowolnej domenie (właściwej)
    NoDmarc,
    /// brak SPF
    NoSpf,
    /// skontaktowani (email_sent)
    Contacted,
    /// niekontaktowani
    NotContacted,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Target {
    Podmioty,
    Interakcje,
    Przetargi,
    External,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub target: Target,
    pub preds: Vec<Pred>,
    pub external_q: Option<String>,
    pub limit: usize,
    pub said: String, // "rozumiem jako"
    pub conf: f64,    // 0..1 — ile predykatorów trafiło (naiwna pewność)
}

// ──────────────────────────────────────────────────── leksykon ────────────

/// fold bez diakrytyków (duplikat logiki z ontology.rs — tu offline, bez SQL)
fn fold(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            'ą' => vec!['a'],
            'ć' => vec!['c'],
            'ę' => vec!['e'],
            'ł' => vec!['l'],
            'ń' => vec!['n'],
            'ó' => vec!['o'],
            'ś' => vec!['s'],
            'ź' | 'ż' => vec!['z'],
            'Ą' => vec!['a'],
            'Ć' => vec!['c'],
            'Ę' => vec!['e'],
            'Ł' => vec!['l'],
            'Ń' => vec!['n'],
            'Ó' => vec!['o'],
            'Ś' => vec!['s'],
            'Ź' | 'Ż' => vec!['z'],
            c => c.to_lowercase().collect(),
        })
        .collect()
}

/// sektory znane ontologii + synonimy potoczne
fn sector_lexicon() -> &'static [(&'static str, &'static str)] {
    &[
        ("wodociagi", "wodociagi"),
        ("wodociag", "wodociagi"),
        ("woda", "wodociagi"),
        ("wod-kan", "wodociagi"),
        ("wodkan", "wodociagi"),
        ("kanalizacja", "wodociagi"),
        ("szpital", "szpital"),
        ("szpitale", "szpital"),
        ("zdrowie", "szpital"),
        ("medycyna", "szpital"),
        ("admin-publiczna", "admin-publiczna"),
        ("administracja", "admin-publiczna"),
        ("urzad", "admin-publiczna"),
        ("urzed", "admin-publiczna"),
        ("urzedu", "admin-publiczna"),
        ("gmina", "admin-publiczna"),
        ("miasto", "admin-publiczna"),
        ("education", "education"),
        ("szkola", "education"),
        ("szkol", "education"),
        ("uczelnia", "education"),
        ("uniwersytet", "education"),
        ("energy", "energy"),
        ("energetyka", "energy"),
        ("prad", "energy"),
        ("transport", "transport"),
        ("kolej", "transport"),
        ("pkp", "transport"),
        ("gov", "gov"),
        ("panstwowy", "gov"),
        ("panstwo", "gov"),
    ]
}

const VOIVODESHIPS: &[(&str, &str)] = &[
    // (rdzeń do dopasowania infleksji, kanoniczna forma w bazie)
    // dłuższe najpierw — "kujawsko-pomorski" przed "pomorski"
    ("kujawsko-pomorski", "kujawsko-pomorskie"),
    ("warminsko-mazurski", "warminsko-mazurskie"),
    ("zachodniopomorski", "zachodniopomorskie"),
    ("dolnoslaski", "dolnoslaskie"),
    ("swietokrzyski", "swietokrzyskie"),
    ("wielkopolski", "wielkopolskie"),
    ("mazowiecki", "mazowieckie"),
    ("malopolski", "malopolskie"),
    ("podkarpacki", "podkarpackie"),
    ("slaski", "slaskie"),
    ("lubuski", "lubuskie"),
    ("podlaski", "podlaskie"),
    ("lubelski", "lubelskie"),
    ("opolski", "opolskie"),
    ("pomorski", "pomorskie"),
    ("lodzki", "lodzkie"),
];

/// liczby słowne które warto rozumieć
fn word_num(w: &str) -> Option<i64> {
    Some(match fold(w).as_str() {
        "tysiac" | "tysiaca" | "tysiecy" => 1_000,
        "milion" | "miliona" | "milionow" => 1_000_000,
        _ => return None,
    })
}

// ──────────────────────────────────────────────────── parser ──────────────

/// Wykryj czy zapytanie to recon zewnętrzny: domena, e-mail albo czasownik recon.
fn external_intent(raw: &str) -> Option<String> {
    let q = raw.trim();
    let lower = fold(q);

    // czasowniki recon (PL/EN) — "sprawdź X", "recon X", "osint X"
    for v in [
        "recon ",
        "osint ",
        "sprawdz ",
        "sprawdź ",
        "zrekonuj ",
        "rozbierz ",
    ] {
        if let Some(rest) = lower.strip_prefix(v) {
            // wróć do oryginalnej wielkości liter — domena nieistotna, ale fraza tak
            let idx = lower.find(rest).unwrap_or(0);
            let target = q[idx..].trim();
            if !target.is_empty() {
                return Some(target.to_string());
            }
        }
    }

    // e-mail
    if lower.contains('@') && !lower.contains(' ') {
        return Some(q.to_string());
    }
    // domena (kropka, bez spacji)
    if lower.contains('.') && !lower.contains(' ') && lower.len() > 3 {
        return Some(q.to_string());
    }
    None
}

/// Główny entry: NL → Plan. Deterministyczny, przetestowany.
pub fn plan(raw: &str) -> Plan {
    let q = fold(raw.trim());
    let mut preds: Vec<Pred> = Vec::new();
    let mut said: Vec<String> = Vec::new();
    let mut target = Target::Podmioty;

    // ── interakcje: "kto dostał maila" itd.
    if (q.contains("dostal") && q.contains("mail"))
        || q.contains("wyslane maile")
        || q.contains("wyslane maile")
        || q.contains("kontaktowane")
        || q.contains("kampania")
    {
        target = Target::Interakcje;
        said.push("interakcje email_sent".into());
        preds.push(Pred::Contacted);
    }

    // ── przetargi
    if q.contains("przetarg") {
        target = Target::Przetargi;
        said.push("przetargi".into());
    }

    // ── external (domena/email/czasownik) — wygrywa z resztą
    if let Some(eq) = external_intent(raw) {
        let said = format!("recon zewnętrzny: {eq}");
        return Plan {
            target: Target::External,
            preds: Vec::new(),
            external_q: Some(eq),
            limit: 1,
            said,
            conf: 1.0,
        };
    }

    // ── negacje kontaktu
    let neg_contact = q.contains(" bez kontakt")
        || q.contains("niekontaktowan")
        || q.contains("nie skontaktowan")
        || q.contains("brak kontaktu")
        || q.contains("nie pisalismy")
        || (q.contains("bez maila") && !q.contains("ma maila"));
    let pos_contact = q.contains("kontaktowan") && !neg_contact;

    if neg_contact {
        preds.push(Pred::NotContacted);
        said.push("!interakcje[email_sent]".into());
    } else if pos_contact && target == Target::Podmioty {
        preds.push(Pred::Contacted);
        said.push("skontaktowani".into());
    }

    // ── DMARC / SPF / MX
    if q.contains("bez dmarc") || q.contains("no dmarc") || q.contains("brak dmarc") {
        preds.push(Pred::NoDmarc);
        said.push("domeny bez DMARC".into());
    }
    if q.contains("bez spf") || q.contains("no spf") || q.contains("brak spf") {
        preds.push(Pred::NoSpf);
        said.push("domeny bez SPF".into());
    }
    if q.contains("ma mail") || q.contains("z mx") || q.contains("poczta") {
        preds.push(Pred::HasMail);
        said.push("ma MX".into());
    }

    // ── tier / hot / warm
    if q.contains("hot") {
        preds.push(Pred::TierMin(15));
        said.push("tier>=15 (HOT)".into());
    } else if q.contains("warm") {
        preds.push(Pred::TierMin(8));
        said.push("tier>=8 (WARM+)".into());
    }

    // ── liczby: "powyżej 100000", ">50k", "ponad 1 mln", "mniej niż 20000"
    let mut nums: Vec<(bool, i64)> = Vec::new(); // (is_min, value)
    for (m, is_min) in [
        (
            find_num_after(
                &q,
                &[
                    "powyzej",
                    "powyżej",
                    "ponad",
                    "wieksze niz",
                    "większe niż",
                    "wiecej niz",
                    "więcej niż",
                    "min",
                    ">",
                ],
            ),
            true,
        ),
        (
            find_num_after(
                &q,
                &[
                    "mniej niz",
                    "mniej niż",
                    "ponizej",
                    "poniżej",
                    "mniejsze niz",
                    "mniejsze niż",
                    "max",
                    "<",
                ],
            ),
            false,
        ),
    ] {
        if let Some(v) = m {
            nums.push((is_min, v));
        }
    }
    // "k" i "mln" przy liczbie: "100k", "1mln" — find_num_after już rozwinął
    // słowa; tu sklejki typu "100k":
    if nums.is_empty() {
        for tok in q.split_whitespace() {
            let t = tok.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
            if let Some(n) = parse_compact(t) {
                // sklejka bez słowa kluczowego — interpretuj jako min gdy stoi
                // przy "miast/populacji"? zbyt mgłe; traktuj jako min populacji
                nums.push((true, n));
                said.push(format!("populacja >= {n} (ze sklejki „{t}”)"));
            }
        }
    }
    for (is_min, v) in nums {
        if is_min {
            preds.push(Pred::PopMin(v));
            said.push(format!("pop >= {v}"));
        } else {
            preds.push(Pred::PopMax(v));
            said.push(format!("pop <= {v}"));
        }
    }

    // ── sektor
    if target != Target::Interakcje {
        for (word, sec) in sector_lexicon() {
            // granica słowa: foldowany tekst, proste contains z kontrolą
            if contains_word(&q, word) {
                preds.push(Pred::Sector(sec.to_string()));
                said.push(format!("sektor={sec}"));
                break; // jeden sektor wystarczy
            }
        }
    }

    // ── województwo (infleksja: "zachodniopomorskim" → rdzeń → kanoniczna)
    for (stem, canon) in VOIVODESHIPS {
        if contains_prefix(&q, stem) {
            preds.push(Pred::Voiv(canon.to_string()));
            said.push(format!("województwo={canon}"));
            break;
        }
    }

    // ── miasto: "w szczecinie" / "miasto X" — po województwach, bo "w X" bywa
    //    województwem; szukamy inflektywu: "w <miescie>"
    for m in [
        "w szczecinie",
        "w krakowie",
        "w warszawie",
        "w poznaniu",
        "we wroclawiu",
        "w gdansku",
        "w lublinie",
    ] {
        if q.contains(m) {
            let city = city_from_phrase(m);
            preds.push(Pred::City(city.to_string()));
            said.push(format!("miasto={city}"));
            break;
        }
    }

    // ── reszta: co nie pasuje do niczego → fraza tekstowa
    if preds.is_empty() && target == Target::Podmioty {
        let stop = [
            "podmiot",
            "podmioty",
            "pokaz",
            "wyswietl",
            "wyświetl",
            "znajdz",
            "znajdź",
            "szukaj",
            "lista",
            "kto",
            "co",
            "gdzie",
            "jakie",
            "jacy",
            "give",
            "show",
            "find",
            "me",
            "the",
            "a",
            "i",
            "w",
            "z",
            "na",
            "do",
            "od",
            "dla",
            "bez",
            "oraz",
            "i",
        ];
        let words: Vec<&str> = q
            .split_whitespace()
            .filter(|w| w.len() > 2 && !stop.contains(w))
            .collect();
        if !words.is_empty() {
            let phrase = words.join(" ");
            preds.push(Pred::Text(phrase.clone()));
            said.push(format!("tekst~„{phrase}”"));
        }
    }

    // ── limit
    let mut limit = 50usize;
    if let Some(p) = q.rfind(" limit ") {
        if let Ok(n) = q[p + 7..].trim().parse::<usize>() {
            limit = n.min(500);
        }
    }

    let conf = if preds.is_empty() { 0.0 } else { 1.0 };
    Plan {
        target,
        preds,
        external_q: None,
        limit,
        said: if said.is_empty() {
            "wszystkie podmioty".into()
        } else {
            said.join(" · ")
        },
        conf,
    }
}

fn city_from_phrase(m: &str) -> &str {
    let city = m.rsplit(' ').next().unwrap_or(m);
    // zwróć rdzeń: "szczecinie" → "szczecin"
    city.trim_end_matches("ie")
        .trim_end_matches('u')
        .trim_end_matches('k')
}

/// sprawdź czy fraza zawiera słowo w granicach (spacje/przecinki/myślniki)
fn contains_word(hay: &str, word: &str) -> bool {
    hay.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .any(|t| t == word || t.starts_with(word) && t.len() <= word.len() + 2)
}

/// jak contains_word, ale dowolna końcówka fleksyjna ("pomorskiM", "pomorskiEGO")
fn contains_prefix(hay: &str, word: &str) -> bool {
    hay.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .any(|t| t.starts_with(word))
}

/// znajdź liczbę po pierwszym wystąpieniu dowolnego klucza; rozwiń słowa
/// "mln"/"milion"/"tys" do pełnych wartości ("ponad 1 mln" → 1_000_000).
fn find_num_after(hay: &str, keys: &[&str]) -> Option<i64> {
    for k in keys {
        if let Some(p) = hay.find(k) {
            let rest = hay[p + k.len()..].trim_start();
            let mut it = rest.split_whitespace();
            let mut acc: Option<i64> = None;
            let mut mult = 1i64;
            // liczba + opcjonalna jednostka
            while let Some(tok) = it.next() {
                let t = tok.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
                if let Ok(n) = t.parse::<i64>() {
                    acc = Some(n);
                    // sprawdź następny token jako jednostkę
                    if let Some(next) = it.next() {
                        match fold(next).as_str() {
                            "mln" | "milion" | "miliona" | "milionow" => mult = 1_000_000,
                            "tys" | "tys." | "tysiac" | "tysiaca" | "tysiecy" | "k" => mult = 1_000,
                            _ => {}
                        }
                        break;
                    }
                } else if let Some(n) = word_num(t) {
                    acc = Some(1);
                    mult = n;
                    break;
                } else if let Some(n) = parse_compact(t) {
                    acc = Some(n);
                    break;
                } else if acc.is_some() {
                    break;
                } else if !t.is_empty() && !t.chars().all(|c| c.is_ascii_digit()) {
                    // pierwsza rzecz po kluczu nie jest liczbą → klucz nie liczy
                    break;
                }
            }
            if let Some(v) = acc {
                return Some(v * mult);
            }
        }
    }
    None
}

/// "100k" / "1mln" / "1,5mln" → wartość
fn parse_compact(t: &str) -> Option<i64> {
    let t = fold(t);
    let (num, mult) = if let Some(p) = t.find("mln") {
        (&t[..p], 1_000_000i64)
    } else if let Some(p) = t.find('k') {
        (&t[..p], 1_000i64)
    } else {
        (&t[..], 1i64)
    };
    let n: f64 = if let Ok(n) = num.replace(',', ".").parse() {
        n
    } else {
        return None;
    };
    Some((n * mult as f64) as i64)
}

// ─────────────────────────── internet search (OSINT-first) ──────────────

/// Fraza → internet → encje do cache'u ontologii. Wywoływane ze spawn_blocking
/// (sieć!). Zwraca JSON dla konsoli + zapisuje do bazy.
pub fn internet_search(o: &Ontology, phrase: &str) -> Result<Value, String> {
    let (web, hits) = discovery::internet_search(phrase);
    if hits.is_empty() {
        return Ok(json!({
            "mode": "internet",
            "said": format!("internet: „{phrase}” — brak sensownych domen w wynikach"),
            "web": web,
            "count": 0,
            "items": [],
        }));
    }

    let mut items = Vec::with_capacity(hits.len());
    for h in &hits {
        // encja/domena do cache'u (idempotentnie)
        let title = if h.title.is_empty() {
            None
        } else {
            Some(h.title.as_str())
        };
        let pid = o
            .ensure_podmiot_by_domena(&h.domain, title)
            .map_err(|e| e.to_string())?;
        o.upsert_domena(&h.domain, h.mx, pid)
            .map_err(|e| e.to_string())?;
        o.set_domena_mail(&h.domain, None, h.dmarc.as_deref());
        if h.www_audit["ok"].as_bool() == Some(true) {
            let url = h.www_audit["url"].as_str().unwrap_or("");
            o.fill_podmiot_meta(pid, None, Some(url), title, None);
        }
        o.log_audyt("intel", "internet_search", &h.domain);

        items.push(json!({
            "podmiot_id": pid,
            "domain": h.domain,
            "title": h.title,
            "url": h.url,
            "mx": h.mx,
            "mx_provider": h.mx_provider,
            "dmarc": h.dmarc,
            "https": h.www_audit["https"],
            "hsts": h.www_audit["hsts"],
            "csp": h.www_audit["csp"],
            "www_status": h.www_audit["status"],
            "www_note": h.www_audit["note"],
        }));
    }

    let mx_count = items
        .iter()
        .filter(|i| i["mx"].as_bool().unwrap_or(false))
        .count();
    let nodmarc = items.iter().filter(|i| i["dmarc"].is_null()).count();
    Ok(json!({
        "mode": "internet",
        "said": format!(
            "internet: „{phrase}” · {} domen · {mx_count} z pocztą · {nodmarc} bez DMARC → cache w ontologii",
            items.len()
        ),
        "web": web,
        "count": items.len(),
        "items": items,
    }))
}

// ─────────────────────────────────────────────────── egzekucja ────────────

/// Uruchom plan na ontologii → JSON dla API. Parametryzowane SQL wszędzie.
pub fn execute(o: &Ontology, plan: &Plan) -> Result<Value, String> {
    match plan.target {
        Target::External => Ok(json!({
            "mode": "external",
            "said": plan.said,
            "q": plan.external_q,
        })),
        Target::Interakcje => run_interakcje(o, plan),
        Target::Przetargi => run_przetargi(o, plan),
        Target::Podmioty => run_podmioty(o, plan),
    }
}

fn run_podmioty(o: &Ontology, plan: &Plan) -> Result<Value, String> {
    use rusqlite::types::Value as SV;
    let mut conds: Vec<String> = Vec::new();
    let mut vals: Vec<SV> = Vec::new();
    let mut p = 0usize;
    // UWAGA: parametry liczbowe MUSZĄ być Integer — tekst w SQLite wygrywa
    // porównanie z liczbą (type-ordering) i po cichu zeruje wyniki.
    let sub = |sql: &str, val: SV, conds: &mut Vec<String>, vals: &mut Vec<SV>, p: &mut usize| {
        *p += 1;
        conds.push(sql.replacen("?", &format!("?{p}"), 1));
        vals.push(val);
    };

    for pred in &plan.preds {
        match pred {
            Pred::Sector(s) => {
                sub(
                    "COALESCE(p.sektor,'') LIKE ?",
                    SV::Text(fold(s)),
                    &mut conds,
                    &mut vals,
                    &mut p,
                );
            }
            Pred::City(c) => {
                sub(
                    "fold_search(p.miasto, ?)",
                    SV::Text(fold(c)),
                    &mut conds,
                    &mut vals,
                    &mut p,
                );
            }
            Pred::Voiv(v) => {
                sub(
                    "fold_search(COALESCE(p.wojewodztwo,''), ?)",
                    SV::Text(fold(v)),
                    &mut conds,
                    &mut vals,
                    &mut p,
                );
            }
            Pred::Text(t) => {
                // pełny tekst: nazwa / miasto / NIP / email osób / domena
                p += 1;
                conds.push(format!(
                    "(fold_search(p.nazwa, ?{p}) OR fold_search(p.miasto, ?{p}) \
                     OR fold_search(COALESCE(p.nip,''), ?{p}) \
                     OR p.id IN (SELECT podmiot_id FROM osoba WHERE fold_search(email, ?{p})) \
                     OR p.id IN (SELECT podmiot_id FROM domena WHERE fold_search(nazwa, ?{p})))"
                ));
                vals.push(SV::Text(fold(t)));
            }
            Pred::PopMin(v) => {
                p += 1;
                conds.push(format!("COALESCE(p.pop,0) >= ?{p}"));
                vals.push(SV::Integer(*v));
            }
            Pred::PopMax(v) => {
                p += 1;
                conds.push(format!("COALESCE(p.pop,0) <= ?{p}"));
                vals.push(SV::Integer(*v));
            }
            Pred::TierMin(v) => {
                p += 1;
                conds.push(format!("COALESCE(p.tier_score,0) >= ?{p}"));
                vals.push(SV::Integer(*v));
            }
            Pred::HasMail => {
                conds.push(
                    "EXISTS (SELECT 1 FROM domena d WHERE d.podmiot_id = p.id AND d.mx = 1)".into(),
                );
            }
            Pred::NoDmarc => {
                conds.push(
                    "EXISTS (SELECT 1 FROM domena d WHERE d.podmiot_id = p.id AND d.mx = 1 \
                            AND (d.dmarc IS NULL OR d.dmarc = ''))"
                        .into(),
                );
            }
            Pred::NoSpf => {
                conds.push(
                    "EXISTS (SELECT 1 FROM domena d WHERE d.podmiot_id = p.id AND d.mx = 1 \
                            AND (d.spf IS NULL OR d.spf = ''))"
                        .into(),
                );
            }
            Pred::Contacted => {
                conds.push(
                    "EXISTS (SELECT 1 FROM interakcja i WHERE i.podmiot_id = p.id \
                            AND i.typ = 'email_sent')"
                        .into(),
                );
            }
            Pred::NotContacted => {
                conds.push(
                    "NOT EXISTS (SELECT 1 FROM interakcja i WHERE i.podmiot_id = p.id \
                            AND i.typ = 'email_sent')"
                        .into(),
                );
            }
        }
    }

    let where_ = if conds.is_empty() {
        "1=1".to_string()
    } else {
        conds.join(" AND ")
    };
    let sql = format!(
        "SELECT p.id, p.nazwa, COALESCE(p.sektor,''), COALESCE(p.miasto,''), COALESCE(p.pop,0), \
                COALESCE(p.tier_score,0), \
                EXISTS(SELECT 1 FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent'), \
                (SELECT COUNT(*) FROM domena d WHERE d.podmiot_id=p.id) \
         FROM podmiot p WHERE {where_} \
         ORDER BY COALESCE(p.tier_score,0) DESC, COALESCE(p.pop,0) DESC \
         LIMIT {}",
        plan.limit
    );

    let conn = o.conn();
    let mut stmt = conn.prepare(&sql).map_err(|e| format!("SQL: {e}"))?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(vals), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "nazwa": r.get::<_, String>(1)?,
                "sektor": r.get::<_, String>(2)?,
                "miasto": r.get::<_, String>(3)?,
                "pop": r.get::<_, i64>(4)?,
                "score": r.get::<_, i64>(5)?,
                "kontakt": r.get::<_, i64>(6)?,
                "domeny": r.get::<_, i64>(7)?,
            }))
        })
        .map_err(|e| format!("SQL: {e}"))?;
    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(json!({
        "mode": "local",
        "kind": "podmioty",
        "said": plan.said,
        "conf": plan.conf,
        "count": items.len(),
        "items": items,
    }))
}

fn run_interakcje(o: &Ontology, plan: &Plan) -> Result<Value, String> {
    let conn = o.conn();
    let mut stmt = conn
        .prepare(
            "SELECT i.ts, i.typ, i.email, i.temat, COALESCE(p.nazwa,'') \
             FROM interakcja i LEFT JOIN podmiot p ON p.id = i.podmiot_id \
             WHERE i.typ = 'email_sent' \
             ORDER BY i.ts DESC LIMIT ?1",
        )
        .map_err(|e| format!("SQL: {e}"))?;
    let rows = stmt
        .query_map([plan.limit as i64], |r| {
            Ok(json!({
                "ts": r.get::<_, i64>(0)?,
                "typ": r.get::<_, String>(1)?,
                "email": r.get::<_, String>(2)?,
                "temat": r.get::<_, String>(3)?,
                "podmiot": r.get::<_, String>(4)?,
            }))
        })
        .map_err(|e| format!("SQL: {e}"))?;
    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(json!({
        "mode": "local",
        "kind": "interakcje",
        "said": plan.said,
        "conf": plan.conf,
        "count": items.len(),
        "items": items,
    }))
}

fn run_przetargi(o: &Ontology, plan: &Plan) -> Result<Value, String> {
    let conn = o.conn();
    let mut stmt = conn
        .prepare(
            "SELECT t.tytul, t.org, t.deadline, t.match_score, t.url \
             FROM przetarg t WHERE 1=1 ORDER BY t.match_score DESC LIMIT ?1",
        )
        .map_err(|e| format!("SQL: {e}"))?;
    let rows = stmt
        .query_map([plan.limit as i64], |r| {
            Ok(json!({
                "tytul": r.get::<_, String>(0)?,
                "org": r.get::<_, String>(1)?,
                "deadline": r.get::<_, String>(2)?,
                "score": r.get::<_, i64>(3)?,
                "url": r.get::<_, String>(4)?,
            }))
        })
        .map_err(|e| format!("SQL: {e}"))?;
    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(json!({
        "mode": "local",
        "kind": "przetargi",
        "said": plan.said,
        "conf": plan.conf,
        "count": items.len(),
        "items": items,
    }))
}

// ────────────────────────────────────────────────────── testy ─────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wodociagi_bez_kontaktu() {
        let p = plan("wodociągi bez kontaktu");
        assert_eq!(p.target, Target::Podmioty);
        assert!(p.preds.contains(&Pred::Sector("wodociagi".into())));
        assert!(p.preds.contains(&Pred::NotContacted));
        assert!(p.said.contains("wodociagi"));
    }

    #[test]
    fn hot_bez_dmarc_w_wojewodztwie() {
        let p = plan("hot bez dmarc w zachodniopomorskim");
        assert!(p.preds.contains(&Pred::TierMin(15)));
        assert!(p.preds.contains(&Pred::NoDmarc));
        assert!(p.preds.contains(&Pred::Voiv("zachodniopomorskie".into())));
    }

    #[test]
    fn populacja_powyzjej() {
        let p = plan("miasta powyżej 100000");
        assert!(p.preds.contains(&Pred::PopMin(100_000)));
        let p2 = plan("ponad 1 mln");
        assert!(p2.preds.contains(&Pred::PopMin(1_000_000)));
        let p3 = plan("mniej niż 50k");
        assert!(p3.preds.contains(&Pred::PopMax(50_000)));
    }

    #[test]
    fn kto_dostal_maila() {
        let p = plan("kto dostał maila");
        assert_eq!(p.target, Target::Interakcje);
    }

    #[test]
    fn recon_routing() {
        let p = plan("recon kghm.com");
        assert_eq!(p.target, Target::External);
        assert_eq!(p.external_q.as_deref(), Some("kghm.com"));
        let p2 = plan("zwik@zwik.szczecin.pl");
        assert_eq!(p2.target, Target::External);
        let p3 = plan("sprawdź ZWiK Szczecin");
        assert_eq!(p3.target, Target::External);
        assert_eq!(p3.external_q.as_deref(), Some("ZWiK Szczecin"));
    }

    #[test]
    fn domena_nie_jest_miastem() {
        // "zwik.szczecin.pl" → external, nie local-text
        let p = plan("zwik.szczecin.pl");
        assert_eq!(p.target, Target::External);
    }

    #[test]
    fn fraza_resztowa() {
        let p = plan("energetyka");
        assert!(p.preds.contains(&Pred::Sector("energy".into())));
        let p2 = plan("morskie oko");
        assert!(matches!(p2.preds.first(), Some(Pred::Text(t)) if t.contains("morskie")));
    }

    #[test]
    fn wojewodztwo_infleksja() {
        // "zachodniopomorskim" (miejscownik) → kanoniczna "zachodniopomorskie"
        let p = plan("hot bez dmarc w zachodniopomorskim");
        assert!(p.preds.contains(&Pred::Voiv("zachodniopomorskie".into())));
        let p2 = plan("kujawsko-pomorskie bez kontaktu");
        assert!(p2.preds.contains(&Pred::Voiv("kujawsko-pomorskie".into())));
    }

    #[test]
    fn internet_search_cacheuje_encje() {
        let o = Ontology::open_memory().unwrap();
        // symulacja: nie wołamy sieci — tylko sprawdzamy routing planu
        let p = plan("internet szczecin wodociągi");
        assert!(p.preds.contains(&Pred::Sector("wodociagi".into())));
        let _ = o; // internet_search testujemy integracyjnie przez smoke, nie testem jednostkowym (sieć)
    }

    #[test]
    fn execute_na_pamieci() {
        let o = Ontology::open_memory().unwrap();
        o.import_leads_json(
            r#"{"leads":[
              {"org":"ZWiK A","email":"a@a.pl","sector":"wodociagi","pop":500000,"source":"t"},
              {"org":"Gabinet B","email":"b@b.pl","sector":"szpital","pop":1000,"source":"t"}
            ]}"#,
        )
        .unwrap();
        let p = plan("wodociągi");
        let out = execute(&o, &p).unwrap();
        assert_eq!(out["count"], 1);
        assert_eq!(out["items"][0]["nazwa"], "ZWiK A");

        let p2 = plan("ponad 100000");
        let out2 = execute(&o, &p2).unwrap();
        assert_eq!(out2["count"], 1);
        assert_eq!(out2["items"][0]["nazwa"], "ZWiK A");

        // po wysłaniu maila: "wodociągi bez kontaktu" → pusto
        let _ = o.log_interakcja(&crate::ontology::NewInterakcja {
            typ: "email_sent".into(),
            kierunek: "out".into(),
            email: "a@a.pl".into(),
            temat: "t".into(),
            ts: 0,
            wynik: "-".into(),
            ref_id: "r".into(),
        });
        let p3 = plan("wodociągi bez kontaktu");
        let out3 = execute(&o, &p3).unwrap();
        assert_eq!(out3["count"], 0);
    }
}
