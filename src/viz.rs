//! viz — eksport ontologii do interaktywnego grafu HTML (vis-network).
//!
//! Jeden plik HTML = ontologia do klikania: podmioty (kolor = sektor,
//! rozmiar = populacja, obramowanie = skontaktowani), domeny jako krawędzie
//! do hubów, hot leady wyróżnione. Offline-friendly (jeden plik; vis-network
//! z CDN — przy air-gap: SCRYER_VIZ_INLINE=1 docelowo embeduje JS).

use crate::ontology::Ontology;

use std::io::Write;

fn esc_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

const SECTOR_COLOR: &[(&str, &str)] = &[
    ("szpital", "#e5484d"),
    ("wodociagi", "#3b82f6"),
    ("energetyka", "#f59e0b"),
    ("admin-publiczna", "#22c55e"),
    ("medtech", "#a855f7"),
];

fn color_for(sektor: &str) -> &'static str {
    for (k, c) in SECTOR_COLOR {
        if sektor == *k {
            return c;
        }
    }
    "#8b93a7"
}

pub fn export_html(o: &Ontology, path: &str) -> Result<usize, String> {
    let conn = o.conn();

    // podmioty + liczba interakcji (skontaktowani)
    let mut stmt = conn
        .prepare(
            "SELECT p.id, p.nazwa, p.sektor, p.miasto, p.pop, p.tier_score,
                    (SELECT COUNT(*) FROM interakcja i WHERE i.podmiot_id = p.id AND i.typ='email_sent')
             FROM podmiot p ORDER BY p.pop DESC, p.tier_score DESC",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let podmioty: Vec<_> = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;

    // domeny → podmiot
    let mut stmt2 = conn
        .prepare("SELECT d.nazwa, d.podmiot_id, d.mx, COALESCE(d.dmarc,'') FROM domena d")
        .map_err(|e| e.to_string())?;
    let domeny = stmt2
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;

    let mut nodes = String::new();
    for (id, nazwa, sektor, miasto, pop, tier, kontakty) in &podmioty {
        let size = (8.0 + (*pop as f64).sqrt() / 18.0).min(38.0);
        let color = color_for(sektor);
        let border = if *kontakty > 0 { "#ffffff" } else { "#4f46e5" };
        let border_w = if *kontakty > 0 { 3 } else { 0 };
        let label = if nazwa.chars().count() > 34 {
            let t: String = nazwa.chars().take(32).collect();
            format!("{t}…")
        } else {
            nazwa.clone()
        };
        let label_j = format!("\"{}\"", esc_json(&label));
        let title_j = format!(
            "\"{}\\n{} | {} | pop={} | score={} | maili={}\"",
            esc_json(nazwa),
            esc_json(sektor),
            esc_json(miasto),
            pop,
            tier,
            kontakty
        );
        let group_j = format!("\"{}\"", esc_json(sektor));
        nodes.push_str(&format!(
            "{{id: {}, label: {label_j}, title: {title_j}, group: {group_j}, value: {size:.1}, shape: \"dot\", ",
            id
        ));
        nodes.push_str(&format!(
            "color: {{background: \"{}\", border: \"{}\", borderWidth: {}}},}},\n",
            color, border, border_w
        ));
    }

    let mut edges = String::new();
    for (nazwa, pid, _mx, dmarc) in &domeny {
        let color = if dmarc.is_empty() {
            "#e5484d"
        } else {
            "#64748b"
        };
        edges.push_str(&format!(
            "{{from: {}, to: {}, color: {{color: \"{}\"}}}},\n",
            pid + 100000,
            100000
                + domeny
                    .iter()
                    .position(|d| d.0 == *nazwa)
                    .map(|i| i as i64 + 1)
                    .unwrap_or(0),
            color
        ));
    }
    // domeny jako węzły (małe kwadraty)
    let mut dom_nodes = String::new();
    for (nazwa, _pid, mx, dmarc) in &domeny {
        let col = if *mx == 0 {
            "#334155"
        } else if dmarc.is_empty() {
            "#e5484d"
        } else {
            "#64748b"
        };
        let label_j = format!("\"{}\"", esc_json(nazwa));
        dom_nodes.push_str(&format!(
            "{{id: {}, label: {label_j}, shape: \"box\", size: 6, color: {{background: \"#0f1420\", border: \"{col}\"}}, font: {{size: 9, color: \"#8b93a7\"}}}},\n",
            100000 + domeny.iter().position(|d| &d.0 == nazwa).map(|i| i as i64 + 1).unwrap_or(0)
        ));
    }

    let html = format!(
        r#"<!doctype html>
<html lang="pl"><head><meta charset="utf-8">
<title>Scryer Ontology — Hartwell Labs</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
body{{margin:0;background:#0a0e14;color:#e8ebf4;font-family:system-ui,sans-serif}}
#m{{width:100vw;height:100vh}}
#l{{position:fixed;top:10px;left:12px;background:rgba(10,14,20,.85);padding:10px 14px;border:1px solid #1e2635;border-radius:8px;font-size:12px}}
#l b{{color:#fff}}
</style></head><body>
<div id="l"><b>SCRYER ONTOLOGY</b> — {np} podmiotów, {nd} domen<br>
<span style="color:#e5484d">■</span> zdrowie <span style="color:#3b82f6">■</span> wod-kan
<span style="color:#f59e0b">■</span> energetyka <span style="color:#22c55e">■</span> admin
<span style="color:#8b93a7">■</span> inne<br>
<span style="color:#4f46e5">◉</span> niekontaktowani · <span style="color:#fff">◉</span> skontaktowani</div>
<div id="m"></div>
<script>
var nodes = new vis.DataSet([{nodes}{dom_nodes}]);
var edges = new vis.DataSet([{edges}]);
var c = document.getElementById("m");
var net = new vis.Network(c, {{nodes: nodes, edges: edges}}, {{
  physics: {{solver: "barnesHut", barnesHut: {{gravitationalConstant: -8000, springLength: 90}}}},
  interaction: {{hover: true, navigationButtons: true}}
}});
</script></body></html>"#,
        np = podmioty.len(),
        nd = domeny.len(),
        nodes = nodes,
        dom_nodes = dom_nodes,
        edges = edges,
    );

    let mut f = std::fs::File::create(path).map_err(|e| e.to_string())?;
    f.write_all(html.as_bytes()).map_err(|e| e.to_string())?;
    Ok(podmioty.len())
}
