# Recon Center — Expansion Plan

> Public roadmap working draft for future Recon Center expansion.
> Each section lists the current state, UX/layout opportunities, and candidate features.
> Complexity tiers remain: **T1** (small), **T2** (medium), **T3** (large).

---

## Tab 1 — SURFACE (Attack Surface)

### Estado Atual
- KPI row: TOTAL / WITH HASH / PMKID / EAPOL
- Hash type breakdown bar (PMKID only / Both / EAPOL only) com legenda
- Pipeline de kill-chain com 6 stages (barras horizontais com contagem)
- Stage details: top 5 networks por stage com badges PMKID/EAPOL
- Click em network → selectTarget() → Target Details no right panel

### Melhorias de Layout

| # | Melhoria | Tier | Descrição |
|---|----------|------|-----------|
| S-L1 | Stage pipeline interativa | T1 | Click em um stage filtra a lista de networks abaixo só para aquele stage. Highlight visual no stage selecionado. Click novamente remove filtro. |
| S-L2 | Expandir "N more" inline | T1 | O "+N more" vira um botão que expande a lista completa sem reload, lazy render. |
| S-L3 | Network search/filter | T1 | Input de busca rápida acima do pipeline que filtra networks por SSID/MAC em tempo real (client-side). |
| S-L4 | Mini sparkline por stage | T2 | Ao lado de cada stage count, um micro sparkline mostrando a evolução do count ao longo das últimas sessões (requer snapshot history — ver S-F3). |
| S-L5 | Kill-chain flow diagram | T2 | Substituir barras horizontais por um diagrama tipo funnel/sankey mostrando o fluxo de networks entre stages. Visual mais impactante para entender a progressão. |

### Novas Features

| # | Feature | Tier | Descrição |
|---|---------|------|-----------|
| S-F1 | Quick Attack launcher | T2 | Botão "ATTACK" no network chip que abre um popup rápido com opções: Hashcat, Aircrack, PMK, WPS (baseado no que o target suporta). Atalho direto sem sair da aba. |
| S-F2 | Stage transition log | T2 | Backend trackeia quando cada network muda de stage (discovered→captured, captured→hash_ready etc.). Endpoint novo: `GET /api/recon/kill-chain/transitions`. Frontend mostra timeline de progressão no right panel do target. |
| S-F3 | Kill-chain snapshots | T2 | Backend salva snapshot dos stage counts periodicamente (a cada refresh). Endpoint: `GET /api/recon/kill-chain/history`. Alimenta sparklines (S-L4) e permite ver evolução temporal da attack surface. |
| S-F4 | Bulk operations | T2 | Checkboxes nos network chips. Ações em batch: "Add to Targets", "Start Batch Crack", "Export selection". Toolbar contextual aparece quando ≥1 selecionado. |
| S-F5 | Recommended next targets | T1 | Seção no topo: "RECOMMENDED TARGETS" — top 3-5 networks ranqueados pelo attack_score + readiness que ainda não foram atacados. Usa dados já existentes da vuln matrix. |

---

## Tab 2 — INTEL (Target Intel)

### Estado Atual
- KPI row: TARGETS count
- Threat analysis (lazy-load): deauth/disassoc KPIs + top 15 BSSIDs table
- Vulnerability matrix table: SSID / ENC / STAGE / SCORE / FLAGS
- Click em row → selectTarget() → Target Details no right panel
- Paginação básica ("Showing N of M")

### Melhorias de Layout

| # | Melhoria | Tier | Descrição |
|---|----------|------|-----------|
| I-L1 | Sortable table headers | T1 | Click nas colunas da vuln table ordena por aquele campo (score, encryption, stage). Seta indicando direção. Frontend-only usando os dados já carregados. |
| I-L2 | Filtros inline | T1 | Dropdowns acima da tabela: filtro por Encryption, Stage, Flag (usa params já suportados pelo endpoint: `encryption`, `stage`). |
| I-L3 | Score distribution chart | T1 | Mini histogram de attack_score (0-100) acima da tabela. Mostra distribuição da attack surface em buckets visuais. |
| I-L4 | Row hover preview | T1 | Hover em um vuln row mostra tooltip com quick preview (encryption details, source badges, capture count) sem precisar clicar. |
| I-L5 | Flag legend | T1 | Primeiro render da aba mostra uma mini legenda de cores dos flags (critical=vermelho, warning=laranja, etc.) — dismiss-able. |
| I-L6 | Infinite scroll ou paginação real | T1 | Substituir "Showing N of M" por paginação com botões Next/Prev usando offset/limit do endpoint, ou infinite scroll. |

### Novas Features

| # | Feature | Tier | Descrição |
|---|---------|------|-----------|
| I-F1 | Security fingerprint column | T1 | Nova coluna "SEC" na vuln table mostrando AKM info (PSK, SAE, FT, 802.1X) extraída dos `.details`. Dados já existem no backend via fingerprint service. |
| I-F2 | Threat correlation | T2 | Cruzar threats_by_bssid com vuln matrix: marcar na tabela quais targets estão sofrendo deauth ativo. Nova flag "UNDER_DEAUTH" com count. |
| I-F3 | Attack history per target | T2 | No right panel (Target Details), adicionar seção "ATTACK HISTORY": lista de tentativas anteriores com mode, wordlist, status, duração. Endpoint: `GET /api/insights/score` já retorna parcial, expandir com entries do `.try`. |
| I-F4 | Export vuln matrix | T1 | Botão "EXPORT" que gera CSV/JSON da tabela completa (all rows, não só os visíveis). Útil para relatórios externos. |
| I-F5 | Network comparison | T2 | Selecionar 2 targets e ver side-by-side: scores, flags, evidence, history. Popup ou drawer com as duas colunas. |
| I-F6 | Smart recommendations | T2 | Para cada network no right panel, gerar recommendation: "Best attack: Hashcat + rockyou (PMKID available)" ou "Needs capture: run deauth first". Backend usa readiness_status + flags para decidir. |

---

## Tab 3 — OPS (Operations)

### Estado Atual
- KPI row: ATTACKS / CRACKED / SUCCESS% / AVG TIME
- Attack modes bar chart (dual bar: attempts vs cracked por mode)
- Top wordlists list (name + crack count)
- By encryption grid (targets + cracked por tipo de encryption)

### Melhorias de Layout

| # | Melhoria | Tier | Descrição |
|---|----------|------|-----------|
| O-L1 | Mode bars com tooltips | T1 | Hover em cada barra mostra popup com detalhes: exhausted count, failed count, avg time per mode. |
| O-L2 | Wordlist effectiveness rate | T1 | Ao lado de cada wordlist name, mostrar success rate (cracks / uses) como badge percentual, não só contagem absoluta. |
| O-L3 | Encryption donut chart | T2 | Substituir grid por donut chart — segmentos proporcionais por encryption type, inner ring mostra cracked vs uncracked. |
| O-L4 | Time-based filter | T2 | Dropdown "Last 24h / 7d / 30d / All time" que filtra operações por período. Requer param no endpoint. |

### Novas Features

| # | Feature | Tier | Descrição |
|---|---------|------|-----------|
| O-F1 | Active jobs monitor | T2 | Seção "ACTIVE OPERATIONS" no topo: lista de jobs rodando agora (cracking, PMK build, WPS) com progress bar inline e botão Cancel. Dados de `GET /api/jobs?status=running`. |
| O-F2 | Cracking velocity chart | T2 | Gráfico de linha: cracks ao longo do tempo (por dia/semana). Requer snapshots de history ou timestamps do `.try`. |
| O-F3 | Wordlist ROI ranking | T2 | Tabela expandida: wordlist name, total uses, cracks, success rate, avg crack time, file size. Ranking por ROI (cracks per MB). Ajuda a escolher wordlist mais eficiente. |
| O-F4 | PMK database inventory | T1 | Seção "PMK DATABASES": lista de databases existentes com SSID, size, entry count. Botões: Build New, Delete. Usa endpoints PMK já existentes. |
| O-F5 | Operation log / timeline | T2 | Timeline cronológica: "14:23 — Hashcat started on NetworkX", "14:31 — CRACKED (rockyou.txt)", "15:00 — PMK build completed". Agrega eventos de jobs e history. |
| O-F6 | Attack planner | T3 | Wizard: "Select targets → Choose strategy → Configure → Launch". Batch job creation com preview de tempo estimado e recursos necessários. |

---

## Tab 4 — GEO (GEOINT)

### Estado Atual
- KPI row: NETWORKS / ACTIVE 24H / ACTIVE 7D
- Freshness grid (4 cards: <24H, <7D, <30D, >30D)
- Hour distribution bar chart (24 barras verticais)
- Peak hours chips + Peak days chips
- Observation window (first seen / last seen)

### Melhorias de Layout

| # | Melhoria | Tier | Descrição |
|---|----------|------|-----------|
| G-L1 | Day-of-week heatmap | T1 | Substituir peak days chips por grid estilo GitHub contributions: 7 colunas (days) × 24 rows (hours), cor = density. Visualização muito mais rica dos patterns temporais. |
| G-L2 | Freshness stacked bar | T1 | Além dos cards, adicionar uma stacked bar horizontal mostrando proporção visual 24H/7D/30D/ancient. |
| G-L3 | Interactive hour chart | T1 | Hover em cada barra do hour distribution mostra count e %. Click seleciona/deselecciona para highlight. |

### Novas Features

| # | Feature | Tier | Descrição |
|---|---------|------|-----------|
| G-F1 | Geospatial cluster view | T3 | Mini-mapa integrado dentro da aba GEO mostrando clusters de networks (sem sair do Recon Center). Usa lat/lng já disponíveis no dataset. Plotar dots com cor = attack_score. |
| G-F2 | Area-of-interest analysis | T2 | Define bounding box no mini-mapa → mostra stats só daquela região: total networks, encryption breakdown, crackability. Novo endpoint: `GET /api/recon/area-intel?bbox=...`. |
| G-F3 | Network age histogram | T1 | Gráfico de distribuição: "quantas networks foram vistas pela primeira vez há X dias". Mostra ritmo de descoberta. |
| G-F4 | Temporal anomaly detection | T2 | Backend detecta anomalias: "spike de 15 networks novas em 1h no dia X" ou "0 atividade por 48h após período ativo". Flag alertas no frontend. |
| G-F5 | Source-based temporal split | T1 | Filtro no hour distribution: ver atividade por source (Pwnagotchi vs Bruce vs M5Evil vs Wardrive). Cada source em cor diferente no chart. |
| G-F6 | Observation timeline | T2 | Timeline visual: barra horizontal onde cada network é uma linha com span first_seen→last_seen. Mostra sobreposição temporal e gaps. Scroll vertical, zoom horizontal. |

---

## Tab 5 — SIGINT (Probe Intelligence)

### Estado Atual
- Lazy-load: check cache → show PROCESS button or cached data
- KPI row: PROBES / CLIENTS / SSIDs / BROADCAST
- "PCAPs scanned" meta
- Most probed SSIDs table (top 20): SSID / CLIENTS / PROBES
- Top probing clients table (top 20): CLIENT MAC / SSIDs chips / PROBES / AVG SIG

### Melhorias de Layout

| # | Melhoria | Tier | Descrição |
|---|----------|------|-----------|
| SI-L1 | SSID search/filter | T1 | Input de busca acima da tabela de SSIDs para localizar rapidamente um SSID específico. |
| SI-L2 | Client MAC OUI resolution | T1 | Ao lado de cada client_mac, mostrar manufacturer name (OUI lookup). Backend já retorna `oui_prefix`, só falta resolver. Endpoint ou local DB de OUI. |
| SI-L3 | Signal strength heatmap | T1 | Na tabela de clients, colorir a célula de AVG SIG com gradient: verde (forte) → vermelho (fraco). |
| SI-L4 | Expandable client rows | T1 | Click em um client row expande para mostrar lista completa de SSIDs probados (atualmente trunca em 5 com "+N more"). |
| SI-L5 | Tab-level mini stats | T1 | Ao lado do título da aba SIGINT, badge com total de probes (fica visível mesmo quando está em outra aba). |

### Novas Features

| # | Feature | Tier | Descrição |
|---|---------|------|-----------|
| SI-F1 | SSID-Network correlation | T2 | Cruzar SSIDs dos probes com redes conhecidas no dataset. Marcar na tabela: "✓ KNOWN" se o SSID corresponde a uma rede que temos. Abre possibilidade de evil twin detection. |
| SI-F2 | Client tracking timeline | T2 | Click em um client → drawer/panel mostra timeline de probes desse client: hora, SSID, signal. Mostra padrão de movimentação do client. |
| SI-F3 | Probe frequency analysis | T1 | Nova coluna na tabela de SSIDs: "RATE" — probes por minuto/hora. Identifica SSIDs com probe burst (indicador de client procurando rede ausente). |
| SI-F4 | Hidden network discovery | T2 | Cruzar probes com broadcast probes (SSID vazio). Agrupar clients que fazem directed probes para SSIDs hidden. Seção: "HIDDEN NETWORK CANDIDATES" com SSIDs que só aparecem em directed probes. |
| SI-F5 | De-randomization hints | T3 | Análise heurística de MAC randomization: agrupar MACs randomizados por padrões de probe (mesmo conjunto de SSIDs → provavelmente mesmo device). Badge "LIKELY SAME DEVICE" linking MACs. |
| SI-F6 | Export probe data | T1 | Botão "EXPORT" → CSV com todos clients/SSIDs/probes para análise externa. |
| SI-F7 | Probe geo-correlation | T3 | Se networks probadas têm GPS no dataset, mostrar raio estimado do client baseado em qual rede está procurando. Mini-mapa com "client was here" markers. |

---

## Tab 6 — REPORT (Audit Report)

### Estado Atual
- Methodology block: tools, sources, networks analyzed
- Findings block: total networks, cracked, crackable remaining, with handshake, EAPOL evidence, crack rate, encryption distribution, device distribution
- Statistics block: first/last observation, span days
- Generated timestamp

### Melhorias de Layout

| # | Melhoria | Tier | Descrição |
|---|----------|------|-----------|
| R-L1 | Executive summary card | T1 | Card visual no topo com métricas-chave em layout de dashboard: crack rate em gauge grande, cracked/total em big numbers, overall risk grade (A-F). |
| R-L2 | Encryption pie chart | T1 | Ao lado de encryption distribution, pie chart visual com cores por tipo. |
| R-L3 | Collapsible sections | T1 | Cada seção (Methodology, Findings, Statistics) tem header clicável que expande/colapsa. Default: todas expandidas. |
| R-L4 | Print-friendly mode | T1 | Botão "PRINT" que abre versão formatada para impressão (CSS @media print ou popup window). |

### Novas Features

| # | Feature | Tier | Descrição |
|---|---------|------|-----------|
| R-F1 | Recommendations engine | T2 | Seção "RECOMMENDATIONS" gerada pelo backend baseada nos findings: "28 networks have EAPOL evidence — convert hashes to .22000", "15 networks are WEP — use direct attack", "PMKID available on 8 targets — prioritize". Lógica rule-based. |
| R-F2 | Risk scoring model | T2 | Classificar toda a attack surface com nota A-F: A = >80% cracked, F = <10% com hash. Breakdown por encryption type. Visual de "security posture". |
| R-F3 | Export full report | T1 | Botão "EXPORT PDF" / "EXPORT MD" — gerar relatório formatado para compartilhamento. JSON payload → markdown template → download. |
| R-F4 | Compliance checklist | T2 | Lista de checks: "☑ All handshakes converted", "☑ No WEP networks remaining", "☐ All targets with score>70 attacked". Toggle marks as you go. Persiste em localStorage. |
| R-F5 | Historical comparison | T3 | Comparar relatório atual com snapshot anterior: "Δ +12 networks since last report, +5 cracked, crack rate improved from 22% → 28%". Requer snapshots de report. |
| R-F6 | Data health integration | T1 | Incluir seção "DATA QUALITY" puxando de `GET /api/data-health/summary`: invalid details, missing details, pending RAW files. Dados já existem, só falta renderizar. |
| R-F7 | Coverage analysis | T2 | Seção "COVERAGE": % de networks com GPS, % com fingerprint details, % com RAW data, % with multiple sources. Mostra completeness do dataset. |

---

## Possível Nova Aba — COMMS (Communications Intel)

> Se o escopo permitir, uma 7ª aba focada em intel de comunicações e correlação entre entities.

| # | Feature | Tier | Descrição |
|---|---------|------|-----------|
| C-F1 | Network-Client relationship graph | T3 | Grafo visual: nós = networks + clients, arestas = probes/associations. Mostra quais clients acessam quais networks. Usa dados de probe intel + associations. |
| C-F2 | Device fingerprinting dashboard | T2 | Agregar todos os device types por OUI: "Apple devices: 45", "Samsung: 12", "Unknown: 30". Cards com ícones por manufacturer. |
| C-F3 | Co-location analysis | T3 | Networks que sempre aparecem juntas (mesmo local, mesmo timestamp). Sugere que pertencem ao mesmo operador ou building. |

---

## Roadmap Sugerido

### Fase 1 — Quick Wins (todos T1)
> Melhorias imediatas que usam dados já existentes, sem novos endpoints.

- S-L1, S-L2, S-L3 (Surface filters e expand)
- I-L1, I-L2, I-L4, I-L5, I-L6 (Intel table polishing)
- O-L1, O-L2 (OPS tooltips e rates)
- G-L1, G-L2, G-L3 (GEO visual upgrades)
- SI-L1, SI-L3, SI-L4 (SIGINT table polish)
- R-L1, R-L2, R-L3, R-L4 (Report visual upgrade)
- S-F5 (Recommended targets)
- I-F1 (Security fingerprint column)
- I-F4 (Export vuln matrix)
- G-F3, G-F5 (Age histogram, source split)
- SI-F3, SI-F6 (Probe frequency, export)
- R-F3, R-F6 (Export report, data health)

### Fase 2 — Core Expansions (T2)
> Features que necessitam de novos endpoints ou lógica backend moderada.

- S-F1, S-F2, S-F4 (Quick attack, transitions, bulk ops)
- I-F2, I-F3, I-F5, I-F6 (Threat correlation, history, comparison, recommendations)
- O-F1, O-F2, O-F3, O-F4, O-F5 (Active jobs, velocity, wordlist ROI, PMK inventory, timeline)
- O-L3, O-L4 (Donut chart, time filter)
- G-F2, G-F4, G-F5, G-F6 (Area analysis, anomalies, source split, observation timeline)
- SI-F1, SI-F2, SI-F4 (SSID correlation, client timeline, hidden networks)
- R-F1, R-F2, R-F4, R-F7 (Recommendations, risk scoring, compliance, coverage)

### Fase 3 — Advanced (T3)
> Features complexas que requerem infraestrutura nova.

- S-L5, S-F3 (Sankey chart, kill-chain snapshots)
- G-F1 (Mini-mapa integrado)
- SI-F5, SI-F7 (MAC de-randomization, probe geo-correlation)
- R-F5 (Historical comparison)
- O-F6 (Attack planner wizard)
- COMMS tab (C-F1, C-F2, C-F3)

---

## Notas de Implementação

1. **Novos endpoints necessários (Fase 2)**:
   - `GET /api/recon/kill-chain/transitions` — stage change log
   - `GET /api/recon/kill-chain/history` — periodic snapshots
   - `GET /api/recon/area-intel?bbox=` — geospatial query
   - Expand attack-effectiveness com `?period=24h|7d|30d|all`
   - Expand audit-report com `recommendations` section

2. **Patterns de implementação**: Seguir o lazy-load pattern existente (status → scan → result) para qualquer feature pesada nova.

3. **State management**: Novas features de filtro/sort na INTEL tab podem ser 100% client-side (dados já carregados). Evitar round-trips desnecessários.

4. **Snapshots para histórico**: Criar dir `backend/data/snapshots/` e salvar JSON periódico de kill-chain counts, report findings, etc. Mecanismo leve de versioning.

5. **Mini-mapa (GEO)**: Usar Leaflet.js (já existe no projeto para map view). Instanciar mapa menor com tile layer simplificado.
