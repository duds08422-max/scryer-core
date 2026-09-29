//! server — `scryer-core serve`: żywe API + konsola na ontologii.
//!
//! Wszystko na żywym SQLite: wyszukiwanie, filtry, profil podmiotu,
//! zapytania (query::parse/run), przetargi, statystyki, wektory ataku.
//! Bind domyślnie na 127.0.0.1 — wystawienie na świat to świadoma decyzja
//! operatora (SCRYER_HOST=0.0.0.0).

use crate::ontology::Ontology;
use crate::query;
use axum::{
    extract::{Path as AxPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// Ścieżka DB dla spawn_blocking (discovery otwiera własne połączenie).
static DB_PATH: OnceLock<PathBuf> = OnceLock::new();

pub struct AppState {
    /// rusqlite Connection nie jest Sync — trzymamy za Mutexem.
    pub onto: Mutex<Ontology>,
}

type S = Arc<AppState>;

/// Zgodny format błędu JSON zamiast panik w handlerach.
struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult = Result<Json<Value>, AppError>;

fn err500<E: std::fmt::Display>(e: E) -> AppError {
    AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn err400<E: std::fmt::Display>(e: E) -> AppError {
    AppError(StatusCode::BAD_REQUEST, e.to_string())
}

fn lock_onto(s: &S) -> MutexGuard<'_, Ontology> {
    // zatruty mutex (panik w środku sekcji) nie może położyć całej konsoli
    s.onto.lock().unwrap_or_else(|p| p.into_inner())
}

pub async fn serve(db: PathBuf, host: &str, port: u16) -> Result<(), String> {
    let onto = Ontology::open(&db).map_err(|e| e.to_string())?;
    onto.register_sql_functions();
    let _ = DB_PATH.set(db.clone());
    let state = Arc::new(AppState { onto: Mutex::new(onto) });

    let app = Router::new()
        .route("/", get(index))
        .route("/assets/vis-network.min.js", get(asset_vis_js))
        .route("/api/stats", get(api_stats))
        .route("/api/podmioty", get(api_podmioty))
        .route("/api/podmiot/:id", get(api_podmiot))
        .route("/api/query", post(api_query))
        .route("/api/tenders", get(api_tenders))
        .route("/api/graph", get(api_graph))
        .route("/api/discover", post(api_discover))
        .route("/api/attack-surface", get(api_attack_surface))
        .with_state(state);

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    println!("scryer-core serve: http://{addr}  (db: {})", db.display());
    println!("  endpointy: /api/stats /api/podmioty /api/podmiot/:id /api/query /api/tenders /api/graph /api/attack-surface");
    axum::serve(listener, app).await.map_err(|e| e.to_string())
}

async fn index() -> Html<&'static str> {
    Html(CONSOLE_HTML)
}

/// vis-network vendored w binarce — konsola działa bez internetu (air-gap OK).
async fn asset_vis_js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        ASSET_VIS_JS,
    )
}

// ---------------------------------------------------------------- stats ---

async fn api_stats(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();
    let cnt = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };

    let contacted: i64 = cnt(
        "SELECT COUNT(DISTINCT podmiot_id) FROM interakcja
         WHERE typ='email_sent' AND podmiot_id IS NOT NULL",
    );
    let nodmarc: i64 = cnt(
        "SELECT COUNT(*) FROM domena WHERE mx=1 AND (dmarc IS NULL OR dmarc='')",
    );
    let hot: i64 = cnt("SELECT COUNT(*) FROM podmiot WHERE tier_score >= 15");
    let warm: i64 = cnt("SELECT COUNT(*) FROM podmiot WHERE tier_score >= 8 AND tier_score < 15");

    // rozkład sektorów (do selecta filtrów w konsoli)
    let mut st = c
        .prepare("SELECT COALESCE(sektor,''), COUNT(*) FROM podmiot GROUP BY sektor ORDER BY COUNT(*) DESC")
        .map_err(err500)?;
    let sektors: Vec<Value> = st
        .query_map([], |r| {
            Ok(json!({ "sektor": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)? }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({
        "podmioty": cnt("SELECT COUNT(*) FROM podmiot"),
        "domeny": cnt("SELECT COUNT(*) FROM domena"),
        "osoby": cnt("SELECT COUNT(*) FROM osoba"),
        "przetargi": cnt("SELECT COUNT(*) FROM przetarg"),
        "interakcje": cnt("SELECT COUNT(*) FROM interakcja"),
        "skontaktowani": contacted,
        "bez_dmarc": nodmarc,
        "hot": hot,
        "warm": warm,
        "sektors": sektors,
    })))
}

// ------------------------------------------------------------- podmioty ---

#[derive(Deserialize)]
struct PodmiotyQ {
    #[serde(default)]
    q: String,
    #[serde(default)]
    sektor: String,
    #[serde(default)]
    kontakt: String, // all|yes|no
    #[serde(default)]
    sort: String, // score|pop|nazwa
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}
fn default_limit() -> i64 {
    100
}

async fn api_podmioty(State(s): State<S>, Query(q): Query<PodmiotyQ>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();

    let mut sql = String::from(
        "SELECT p.id, p.nazwa, p.nip, p.sektor, p.wojewodztwo, p.miasto, p.pop,
                p.tier_score,
                (SELECT COUNT(*) FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent') AS maile,
                (SELECT GROUP_CONCAT(d.nazwa) FROM domena d WHERE d.podmiot_id=p.id) AS domeny
         FROM podmiot p WHERE 1=1",
    );
    let mut vals: Vec<String> = Vec::new();
    let mut n = |v: &str| -> usize {
        vals.push(v.to_string());
        vals.len()
    };

    if !q.q.is_empty() {
        let needle = q.q.trim();
        sql.push_str(&format!(
            " AND (fold_search(p.nazwa, ?{n}) OR fold_search(p.miasto, ?{n}) OR fold_search(p.nip, ?{n})
                 OR p.id IN (SELECT podmiot_id FROM osoba WHERE fold_search(email, ?{n}))
                 OR p.id IN (SELECT podmiot_id FROM domena WHERE fold_search(nazwa, ?{n})))",
            n = n(needle)
        ));
    }
    if !q.sektor.is_empty() {
        sql.push_str(&format!(" AND p.sektor = ?{}", n(&q.sektor)));
    }
    if q.kontakt == "yes" {
        sql.push_str(" AND EXISTS (SELECT 1 FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent')");
    } else if q.kontakt == "no" {
        sql.push_str(" AND NOT EXISTS (SELECT 1 FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent')");
    }

    sql.push_str(match q.sort.as_str() {
        "pop" => " ORDER BY p.pop DESC, p.tier_score DESC",
        "nazwa" => " ORDER BY p.nazwa",
        "maile" => " ORDER BY maile DESC, p.tier_score DESC",
        _ => " ORDER BY p.tier_score DESC, p.pop DESC",
    });

    let total: i64 = {
        // szybki licznik bez LIMIT/OFFSET do paginacji
        let count_sql = format!("SELECT COUNT(*) FROM ({sql})");
        c.query_row(&count_sql, rusqlite::params_from_iter(vals.iter()), |r| r.get(0))
            .unwrap_or(0)
    };

    let limit = q.limit.clamp(1, 1000);
    let offset = q.offset.max(0);
    sql.push_str(&format!(" LIMIT {limit} OFFSET {offset}"));

    let mut stmt = c.prepare(&sql).map_err(err500)?;
    let pv: Vec<&str> = vals.iter().map(|s| s.as_str()).collect();
    let rows = stmt
        .query_map(rusqlite::params_from_iter(pv), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "nazwa": r.get::<_, String>(1)?,
                "nip": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                "sektor": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                "wojewodztwo": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                "miasto": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                "pop": r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                "tier_score": r.get::<_, Option<i64>>(7)?.unwrap_or(0),
                "maile": r.get::<_, i64>(8)?,
                "domeny": r.get::<_, Option<String>>(9)?.unwrap_or_default(),
            }))
        })
        .map_err(err500)?;
    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!({
        "count": items.len(),
        "total": total,
        "offset": offset,
        "items": items,
    })))
}

// ------------------------------------------------------- profil podmiotu ---

async fn api_podmiot(State(s): State<S>, AxPath(id): AxPath<i64>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();

    let pod = c
        .query_row(
            "SELECT id, nazwa, nip, sektor, wojewodztwo, miasto, pop, ksc_status, tier_score, COALESCE(zrodla,'')
             FROM podmiot WHERE id=?1",
            rusqlite::params![id],
            |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "nazwa": r.get::<_, String>(1)?,
                    "nip": r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    "sektor": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    "wojewodztwo": r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    "miasto": r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    "pop": r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                    "ksc_status": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                    "tier_score": r.get::<_, Option<i64>>(8)?.unwrap_or(0),
                    "zrodla": r.get::<_, String>(9)?,
                }))
            },
        )
        .map_err(|_| AppError(StatusCode::NOT_FOUND, format!("podmiot {id}: brak")))?;

    let doms: Vec<Value> = {
        let mut st = c
            .prepare("SELECT nazwa, mx, COALESCE(spf,''), COALESCE(dmarc,'') FROM domena WHERE podmiot_id=?1 ORDER BY nazwa")
            .map_err(err500)?;
        let rows = st.query_map(rusqlite::params![id], |r| {
            Ok(json!({
                "nazwa": r.get::<_, String>(0)?,
                "mx": r.get::<_, i64>(1)?,
                "spf": r.get::<_, String>(2)?,
                "dmarc": r.get::<_, String>(3)?,
            }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();
        rows
    };

    let osoby: Vec<Value> = {
        let mut st = c
            .prepare("SELECT email, COALESCE(rola,''), COALESCE(telefon,'') FROM osoba WHERE podmiot_id=?1 ORDER BY email")
            .map_err(err500)?;
        let rows = st.query_map(rusqlite::params![id], |r| {
            Ok(json!({
                "email": r.get::<_, String>(0)?,
                "rola": r.get::<_, String>(1)?,
                "telefon": r.get::<_, String>(2)?,
            }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();
        rows
    };

    let inter: Vec<Value> = {
        let mut st = c
            .prepare(
                "SELECT typ, COALESCE(kierunek,'-'), COALESCE(email,''), COALESCE(temat,''), ts,
                        COALESCE(wynik,'-'), COALESCE(ref_id,'')
                 FROM interakcja WHERE podmiot_id=?1 ORDER BY ts DESC LIMIT 200",
            )
            .map_err(err500)?;
        let rows = st.query_map(rusqlite::params![id], |r| {
            Ok(json!({
                "typ": r.get::<_, String>(0)?,
                "kierunek": r.get::<_, String>(1)?,
                "email": r.get::<_, String>(2)?,
                "temat": r.get::<_, String>(3)?,
                "ts": r.get::<_, i64>(4)?,
                "wynik": r.get::<_, String>(5)?,
                "ref": r.get::<_, String>(6)?,
            }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();
        rows
    };

    Ok(Json(json!({ "podmiot": pod, "domeny": doms, "osoby": osoby, "interakcje": inter })))
}

// ---------------------------------------------------------------- query ---

#[derive(Deserialize)]
struct QueryBody {
    q: String,
}

async fn api_query(State(s): State<S>, Json(body): Json<QueryBody>) -> ApiResult {
    let onto = lock_onto(&s);
    let parsed = query::parse(&body.q).map_err(err400)?;
    let rows = query::run(&onto, &parsed).map_err(err400)?;
    Ok(Json(json!({ "count": rows.len(), "rows": rows })))
}

// -------------------------------------------------------------- tenders ---

async fn api_tenders(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();
    let mut st = c
        .prepare(
            "SELECT tytul, COALESCE(org,''), COALESCE(url,''), COALESCE(deadline,''),
                    COALESCE(cpv,''), match_score, COALESCE(status,'nowy')
             FROM przetarg ORDER BY match_score DESC, deadline LIMIT 500",
        )
        .map_err(err500)?;
    let rows = st
        .query_map([], |r| {
            Ok(json!({
                "tytul": r.get::<_, String>(0)?,
                "org": r.get::<_, String>(1)?,
                "url": r.get::<_, String>(2)?,
                "deadline": r.get::<_, String>(3)?,
                "cpv": r.get::<_, String>(4)?,
                "match_score": r.get::<_, i64>(5)?,
                "status": r.get::<_, String>(6)?,
            }))
        })
        .map_err(err500)?;
    let items: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!({ "count": items.len(), "items": items })))
}

// ---------------------------------------------------------------- graph ---

async fn api_graph(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let c = onto.conn();

    let pods: Vec<Value> = {
        let mut sp = c
            .prepare(
                "SELECT p.id, p.nazwa, COALESCE(p.sektor,''), COALESCE(p.miasto,''), p.pop, p.tier_score,
                        EXISTS(SELECT 1 FROM interakcja i WHERE i.podmiot_id=p.id AND i.typ='email_sent')
                 FROM podmiot p",
            )
            .map_err(err500)?;
        let rows = sp.query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "nazwa": r.get::<_, String>(1)?,
                "sektor": r.get::<_, String>(2)?,
                "miasto": r.get::<_, String>(3)?,
                "pop": r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                "score": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                "kontakt": r.get::<_, i64>(6)?,
            }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();
        rows
    };

    let doms: Vec<Value> = {
        let mut sd = c
            .prepare("SELECT id, nazwa, mx, COALESCE(dmarc,''), podmiot_id FROM domena")
            .map_err(err500)?;
        let rows = sd.query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "nazwa": r.get::<_, String>(1)?,
                "mx": r.get::<_, i64>(2)?,
                "dmarc": r.get::<_, String>(3)?,
                "podmiot_id": r.get::<_, i64>(4)?,
            }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();
        rows
    };

    let osoby: Vec<Value> = {
        let mut so = c
            .prepare("SELECT id, email, podmiot_id FROM osoba")
            .map_err(err500)?;
        let rows = so.query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "email": r.get::<_, String>(1)?,
                "podmiot_id": r.get::<_, i64>(2)?,
            }))
        })
        .map_err(err500)?
        .filter_map(|r| r.ok())
        .collect();
        rows
    };

    // którzy kontenci dostali maila (do podświetlenia węzłów/osób)
    let emailed: Vec<String> = {
        let mut se = c
            .prepare("SELECT DISTINCT email FROM interakcja WHERE typ='email_sent' AND email IS NOT NULL")
            .map_err(err500)?;
        let rows = se.query_map([], |r| r.get::<_, String>(0))
            .map_err(err500)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    Ok(Json(json!({ "podmioty": pods, "domeny": doms, "osoby": osoby, "emailed": emailed })))
}

// ------------------------------------------------------- attack surface ---

async fn api_attack_surface(State(s): State<S>) -> ApiResult {
    let onto = lock_onto(&s);
    let rows = onto.hot_bez_dmarc().map_err(err500)?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(nazwa, domena)| json!({ "nazwa": nazwa, "domena": domena }))
        .collect();
    Ok(Json(json!({ "count": items.len(), "items": items })))
}

// ------------------------------------------------------------- discover ---

#[derive(Deserialize)]
struct DiscoverBody {
    q: String,
}

async fn api_discover(
    State(s): State<S>,
    Json(body): Json<DiscoverBody>,
) -> ApiResult {
    use crate::discovery;

    let q = discovery::normalize(&body.q);
    if q.domain.is_empty() && q.phrase.is_empty() {
        return Err(AppError(StatusCode::BAD_REQUEST, "puste zapytanie".into()));
    }

    let db = DB_PATH
        .get()
        .cloned()
        .ok_or_else(|| AppError(StatusCode::INTERNAL_SERVER_ERROR, "brak ścieżki DB".into()))?;

    // sieciowe wołania poza async-ctx: osobne połączenie + spawn_blocking;
    // serwer ma Mutex na głównym conn — discovery pisze przez własny handle
    let res = tokio::task::spawn_blocking(move || {
        let onto = crate::ontology::Ontology::open(&db).map_err(|e| e.to_string())?;
        onto.register_sql_functions();
        let report = discovery::discover(&q);
        persist_discovery(&onto, &report);
        Ok::<_, String>(report)
    })
    .await
    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    lock_onto(&s).log_audyt("console", "discover", &format!("{} → {}", body.q, res["domain"].as_str().unwrap_or("-")));

    Ok(Json(res))
}

/// Zapis wyników discovery do ontologii (idempotentny).
fn persist_discovery(onto: &crate::ontology::Ontology, rep: &Value) {
    let dom = rep["domain"].as_str().unwrap_or("");
    if dom.is_empty() {
        return;
    }
    let dns = &rep["dns"];
    let has_mail = dns["has_mail"].as_bool().unwrap_or(false);
    let first = |k: &str| -> Option<&str> {
        dns[k].as_array().and_then(|a| a.first()).and_then(|x| x.as_str())
    };
    let spf = first("spf");
    let dmarc = first("dmarc");
    let pid = onto.podmiot_id_by_domena(dom);

    let dom_id = match pid {
        Some(p) => onto.upsert_domena(dom, has_mail, p).unwrap_or(0),
        None => onto.upsert_domena_free(dom, has_mail).unwrap_or(0),
    };
    let _ = dom_id;
    onto.set_domena_mail(dom, spf, dmarc);

    let www = &rep["www"];
    if www["ok"].as_bool().unwrap_or(false) {
        let title = www["title"].as_str().unwrap_or("");
        let url = www["url"].as_str().unwrap_or("");
        let desc = www["description"].as_str().unwrap_or("");
        let phones = www["phones"].as_array().and_then(|a| a.first()).and_then(|x| x.as_str());
        if let Some(p) = pid {
            onto.fill_podmiot_meta(
                p,
                None,
                Some(url),
                Some(if desc.is_empty() { title } else { desc }),
                phones,
            );
        }
        // osoby z www tylko gdy znamy ownera (FK na podmiot_id)
        if let Some(persons) = www["persons"].as_array() {
            if let Some(p) = pid {
                for em in persons.iter().filter_map(|x| x.as_str()) {
                    let _ = onto.upsert_osoba_email(em, "web", p);
                }
            }
        }
        if let Some(emails) = www["emails"].as_array() {
            if let Some(p) = pid {
                for em in emails.iter().filter_map(|x| x.as_str()) {
                    let _ = onto.upsert_osoba_email(em, "web", p);
                }
            }
        }
    }

    // subdomeny z crt.sh → domeny w grafie (bez MX-checku — to by długo trwało)
    if let Some(subs) = rep["subdomains"].as_array() {
        for sd in subs.iter().filter_map(|x| x.as_str()).take(30) {
            if sd != dom {
                let _ = match pid {
                    Some(p) => onto.upsert_domena(sd, false, p),
                    None => onto.upsert_domena_free(sd, false),
                };
            }
        }
    }

    onto.log_audyt("discovery", "recon", dom);
}

// -------------------------------------------------------------- konsola ---

const CONSOLE_HTML: &str = include_str!("console.html");
const ASSET_VIS_JS: &str = include_str!("assets/vis-network.min.js");
