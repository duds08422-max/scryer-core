//! graphx — analityka grafu powiązań (link analysis; komponent: Palantir Graph).
//!
//! Czysty, deterministyczny, testowalny: operuje na liście krawędzi (węzły
//! jako identyfikatory "p:1" / "d:3" / "o:2"), zero sieci, zero LLM.
//! Buduje komponenty spójności, mosty (Tarjan low-link, O(V+E)), najkrótsze
//! ścieżki i wspólnych sąsiadów — odpowiedzi na pytania „co z czym jest
//! powiązane", „co się rozpadnie jak zniknie X", „jak A łączy się z B".
//!
//! Semantyka: graf nieskierowany, krawędzie proste (dedup par). Wszystkie
//! wyniki są deterministyczne (stabilna kolejność = powtarzalny audyt).

use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet, VecDeque};

pub type NodeId = String;
pub type Edge = (NodeId, NodeId);

/// Graf powiązań jako lista węzłów + prostych krawędzi.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkGraph {
    pub nodes: Vec<NodeId>,
    pub edges: Vec<Edge>,
}

fn canonical(a: NodeId, b: NodeId) -> Edge {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

impl LinkGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, id: impl Into<NodeId>) {
        let id = id.into();
        if !self.nodes.contains(&id) {
            self.nodes.push(id);
        }
    }

    /// Dodaje krawędź (tworzy węzły po drodze); duplikaty par są ignorowane.
    pub fn add_edge(&mut self, a: impl Into<NodeId>, b: impl Into<NodeId>) {
        let a = a.into();
        let b = b.into();
        if a == b {
            return; // bez pętli własnych
        }
        self.add_node(a.clone());
        self.add_node(b.clone());
        let e = canonical(a, b);
        if !self.edges.contains(&e) {
            self.edges.push(e);
        }
    }

    /// Sąsiedzi jako indeksy węzłów, posortowani rosnąco (determinizm).
    fn adj_map(&self) -> BTreeMap<usize, Vec<usize>> {
        let idx: BTreeMap<&str, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i))
            .collect();
        let mut adj: BTreeMap<usize, Vec<usize>> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, _)| (i, Vec::new()))
            .collect();
        for (a, b) in &self.edges {
            let ia = idx[a.as_str()];
            let ib = idx[b.as_str()];
            adj.entry(ia).or_default().push(ib);
            adj.entry(ib).or_default().push(ia);
        }
        for v in adj.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        adj
    }

    fn idx_of(&self, id: &str) -> Option<usize> {
        self.nodes.iter().position(|n| n == id)
    }

    /// Stopień węzła (0 dla nieznanych).
    pub fn degree(&self, id: &str) -> usize {
        self.edges
            .iter()
            .filter(|(a, b)| a == id || b == id)
            .count()
    }

    /// Komponenty spójności; posortowane stabilnie (rozmiar ↓, potem pierwszy węzeł).
    pub fn components(&self) -> Vec<Vec<NodeId>> {
        let adj = self.adj_map();
        let n = self.nodes.len();
        let mut seen = vec![false; n];
        let mut out: Vec<Vec<NodeId>> = Vec::new();
        for root in 0..n {
            if seen[root] {
                continue;
            }
            let mut comp = Vec::new();
            let mut q = VecDeque::from([root]);
            seen[root] = true;
            while let Some(v) = q.pop_front() {
                comp.push(self.nodes[v].clone());
                for &w in &adj[&v] {
                    if !seen[w] {
                        seen[w] = true;
                        q.push_back(w);
                    }
                }
            }
            comp.sort();
            out.push(comp);
        }
        out.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));
        out
    }

    /// Mosty = krawędzie, których usunięcie zwiększa liczbę komponentów
    /// (Tarjan low-link, iteracyjnie; wynik kanoniczny i posortowany).
    pub fn bridges(&self) -> Vec<Edge> {
        let n = self.nodes.len();
        let adj = self.adj_map();
        let mut disc = vec![u32::MAX; n];
        let mut low = vec![u32::MAX; n];
        let mut out: Vec<Edge> = Vec::new();
        let mut timer: u32 = 0;
        // stos: (węzeł, parent, następny sąsiad do odwiedzenia)
        let mut stack: Vec<(usize, usize, usize)> = Vec::new();
        for root in 0..n {
            if disc[root] != u32::MAX {
                continue;
            }
            disc[root] = timer;
            low[root] = timer;
            timer += 1;
            stack.push((root, usize::MAX, 0));
            while let Some(top) = stack.last_mut() {
                let (v, parent, idx) = *top;
                let neighbors = &adj[&v];
                if idx < neighbors.len() {
                    top.2 += 1;
                    let w = neighbors[idx];
                    if w == parent {
                        continue;
                    }
                    if disc[w] == u32::MAX {
                        disc[w] = timer;
                        low[w] = timer;
                        timer += 1;
                        stack.push((w, v, 0));
                    } else {
                        low[v] = low[v].min(disc[w]);
                    }
                } else {
                    stack.pop();
                    if let Some(ptop) = stack.last_mut() {
                        let p = ptop.0;
                        low[p] = low[p].min(low[v]);
                        if low[v] > disc[p] {
                            out.push(canonical(self.nodes[p].clone(), self.nodes[v].clone()));
                        }
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Najkrótsza ścieżka (BFS); None = brak połączenia.
    pub fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<NodeId>> {
        if from == to {
            return self.idx_of(from).map(|_| vec![from.to_string()]);
        }
        let adj = self.adj_map();
        let s = self.idx_of(from)?;
        let t = self.idx_of(to)?;
        let mut parent: BTreeMap<usize, usize> = BTreeMap::new();
        let mut seen: HashSet<usize> = [s].into();
        let mut q = VecDeque::from([s]);
        while let Some(v) = q.pop_front() {
            for &w in &adj[&v] {
                if seen.insert(w) {
                    parent.insert(w, v);
                    if w == t {
                        let mut path = vec![t];
                        let mut cur = t;
                        while let Some(&p) = parent.get(&cur) {
                            path.push(p);
                            cur = p;
                        }
                        path.reverse();
                        return Some(path.into_iter().map(|i| self.nodes[i].clone()).collect());
                    }
                    q.push_back(w);
                }
            }
        }
        None
    }

    /// Wspólni sąsiedzia­ni dwóch węzłów (posortowani wg kolejności w grafie).
    pub fn common_neighbors(&self, a: &str, b: &str) -> Vec<NodeId> {
        let (Some(ia), Some(ib)) = (self.idx_of(a), self.idx_of(b)) else {
            return Vec::new();
        };
        let adj = self.adj_map();
        let sa: HashSet<usize> = adj[&ia].iter().copied().collect();
        adj[&ib]
            .iter()
            .filter(|w| sa.contains(w))
            .map(|&w| self.nodes[w].clone())
            .collect()
    }

    /// Podsumowanie dla UI/raportu: skala, spójność, kruchość.
    pub fn stats(&self) -> Value {
        let n = self.nodes.len();
        let e = self.edges.len();
        let comps = self.components();
        let largest = comps.first().map(Vec::len).unwrap_or(0);
        let orphan = self.nodes.iter().filter(|id| self.degree(id) == 0).count();
        let hubs = self.nodes.iter().filter(|n| n.starts_with("i:")).count();
        let density = if n > 1 {
            (2.0 * e as f64) / (n as f64 * (n as f64 - 1.0))
        } else {
            0.0
        };
        json!({
            "nodes": n,
            "edges": e,
            "components": comps.len(),
            "largest_component": largest,
            "bridges": self.bridges().len(),
            "orphan_nodes": orphan,
            "infra_hubs": hubs,
            "density": (density * 10_000.0).round() / 10_000.0,
        })
    }
}

impl Default for LinkGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Hub-y wspólnej infrastruktury: wskaźnik (ip/mx/ns) obserwowany dla domen
/// ≥2 różnych podmiotów → ukryta relacja ("ci dwi grają z tym samym dostawcą").
/// Deterministyczny: sort po (typ, wartość); domeny posortowane rosnąco.
pub fn infra_hubs(c: &Connection) -> rusqlite::Result<Vec<(String, String, Vec<i64>)>> {
    let mut st = c.prepare(
        "SELECT w.typ, w.wartosc, w.domena_id, d.podmiot_id
         FROM wskaznik w JOIN domena d ON d.id = w.domena_id
         ORDER BY w.typ, w.wartosc, w.domena_id",
    )?;
    let rows: Vec<(String, String, i64, i64)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .filter_map(|r| r.ok())
        .collect();
    let mut groups: BTreeMap<(String, String), Vec<(i64, i64)>> = BTreeMap::new();
    for (typ, wart, dom, pod) in rows {
        groups.entry((typ, wart)).or_default().push((dom, pod));
    }
    let mut out = Vec::new();
    for ((typ, wart), doms) in groups {
        let mut pods: Vec<i64> = doms.iter().map(|(_, p)| *p).collect();
        pods.sort_unstable();
        pods.dedup();
        if pods.len() >= 2 {
            let ids: Vec<i64> = doms.into_iter().map(|(d, _)| d).collect();
            out.push((typ, wart, ids));
        }
    }
    Ok(out)
}

/// Buduje graf powiązań z ontologii: podmiot↔domena, podmiot↔osoba
/// + hub-y wspólnej infrastruktury (domena↔wskaźnik).
///
/// Deterministyczny (ORDER BY id); węzły "p:{id}", "d:{id}", "o:{id}", "i:{typ}:{wart}".
pub fn link_graph(c: &Connection) -> rusqlite::Result<LinkGraph> {
    let mut g = LinkGraph::new();
    let mut sd = c.prepare("SELECT id, podmiot_id FROM domena ORDER BY id")?;
    let doms: Vec<(i64, i64)> = sd
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    for (d, p) in doms {
        g.add_edge(format!("p:{p}"), format!("d:{d}"));
    }
    let mut so = c.prepare("SELECT id, podmiot_id FROM osoba ORDER BY id")?;
    let osob: Vec<(i64, i64)> = so
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    for (o, p) in osob {
        g.add_edge(format!("p:{p}"), format!("o:{o}"));
    }
    // podmioty bez żadnych krawędzi też wchodzą (widoczność "samotnych")
    let mut sp = c.prepare("SELECT id FROM podmiot ORDER BY id")?;
    let pods: Vec<i64> = sp
        .query_map([], |r| r.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    for p in pods {
        g.add_node(format!("p:{p}"));
    }
    // hub-y wspólnej infrastruktury: domena ↔ "i:{typ}:{wartość}"
    for (typ, wart, dom_ids) in infra_hubs(c)? {
        let hub = format!("i:{typ}:{wart}");
        for d in dom_ids {
            g.add_edge(hub.clone(), format!("d:{d}"));
        }
    }
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain3() -> LinkGraph {
        let mut g = LinkGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "c");
        g
    }

    #[test]
    fn path_chain_components_and_bridges() {
        let g = chain3();
        assert_eq!(g.components().len(), 1);
        assert_eq!(g.bridges().len(), 2, "w łańcuchu każda krawędź to most");
        let p = g.shortest_path("a", "c").unwrap();
        assert_eq!(p, vec!["a", "b", "c"]);
    }

    #[test]
    fn cycle_has_no_bridges() {
        let mut g = LinkGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "c");
        g.add_edge("c", "a");
        assert!(g.bridges().is_empty());
        assert_eq!(g.shortest_path("a", "c").unwrap().len(), 2);
    }

    #[test]
    fn components_isolation_and_orphan() {
        let mut g = chain3();
        g.add_edge("x", "y");
        g.add_node("lonely");
        let comps = g.components();
        assert_eq!(comps.len(), 3, "łańcuch + para + samotny");
        assert_eq!(comps[0].len(), 3);
        assert_eq!(g.stats()["orphan_nodes"], 1);
    }

    #[test]
    fn hub_is_articulation_and_common_neighbor() {
        let mut g = LinkGraph::new();
        g.add_edge("a", "hub");
        g.add_edge("c", "hub");
        g.add_edge("d", "hub");
        assert_eq!(g.bridges().len(), 3, "hub trzyma wszystko = same mosty");
        assert_eq!(g.common_neighbors("a", "c"), vec!["hub"]);
        assert!(g.shortest_path("a", "d").unwrap().len() == 3);
    }

    #[test]
    fn edges_dedup_and_no_self_loops() {
        let mut g = LinkGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "a");
        g.add_edge("a", "a");
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.degree("a"), 1);
    }

    #[test]
    fn unreachable_path_is_none() {
        let mut g = chain3();
        g.add_edge("x", "y");
        assert!(g.shortest_path("a", "x").is_none());
    }

    #[test]
    fn link_graph_from_ontology_memory() {
        let onto = crate::ontology::Ontology::open_memory().expect("db");
        let c = onto.conn();
        c.execute(
            "INSERT INTO podmiot (nazwa) VALUES ('ZWK Szczecin'), ('Samotna Gmina')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO domena (nazwa, podmiot_id) VALUES ('zwik.szczecin.pl', 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO osoba (email, podmiot_id) VALUES ('biuro@zwik.szczecin.pl', 1)",
            [],
        )
        .unwrap();
        let g = link_graph(c).unwrap();
        assert_eq!(g.nodes.len(), 4, "2 podmioty + domena + osoba");
        assert_eq!(g.edges.len(), 2);
        let comps = g.components();
        assert_eq!(comps.len(), 2, "ZWK spójny, Samotna Gmina osobno");
        assert_eq!(g.stats()["orphan_nodes"], 1);
        let p = g.shortest_path("d:1", "o:1").unwrap();
        assert_eq!(p, vec!["d:1", "p:1", "o:1"]);
    }

    #[test]
    fn shared_infra_creates_hub_and_merges_components() {
        let onto = crate::ontology::Ontology::open_memory().expect("db");
        let c = onto.conn();
        c.execute(
            "INSERT INTO podmiot (nazwa) VALUES ('Gmina A'), ('Gmina B'), ('Osobna C')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO domena (nazwa, podmiot_id) VALUES ('a.pl', 1), ('b.pl', 2), ('c.pl', 3)",
            [],
        )
        .unwrap();
        // A i B dzielą MX; C ma własny — hub łączy komponenty A i B
        onto.upsert_wskaznik("mx", "mail.wspolny.pl", 1);
        onto.upsert_wskaznik("mx", "mail.wspolny.pl", 2);
        onto.upsert_wskaznik("mx", "mail.c.pl", 3);
        let g = link_graph(c).unwrap();
        assert_eq!(g.stats()["infra_hubs"], 1);
        // ścieżka a.pl → hub → b.pl istnieje mimo braku bezpośredniej relacji
        let p = g.shortest_path("d:1", "d:2").unwrap();
        assert_eq!(p, vec!["d:1", "i:mx:mail.wspolny.pl", "d:2"]);
        // C pozostaje odizolowane
        assert!(g.shortest_path("d:1", "d:3").is_none());
    }
}
