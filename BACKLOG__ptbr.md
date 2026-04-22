# KOVIL MAP - BACKLOG

**Última atualização:** 22 de Abril de 2026  
**Iniciativas rastreadas:** 29

Este backlog e publico. Ele pode misturar itens de roadmap para contribuidores e tarefas de release sob responsabilidade dos mantenedores, mas nao deve conter segredos, detalhes pessoais de infraestrutura ou notas operacionais privadas.

## Legenda

### Prioridade

| Prioridade | Significado |
| --- | --- |
| `CRÍTICA` | bloqueia outras entregas, afeta segurança, ou é obrigatória antes de publicar |
| `ALTA` | impacto importante em UX, operação, ou fluxo principal |
| `MÉDIA` | melhoria valiosa, mas não urgente |
| `BAIXA` | polimento, cleanup, ou melhoria de cauda longa |

### Status

| Status | Significado |
| --- | --- |
| `TODO` | não iniciado |
| `IN PROGRESS` | em andamento |
| `IN REVIEW` | implementado, aguardando revisão |
| `DONE` | concluído e mergeado |

## 1. Ciclo de Vida dos Handshakes

### Artefatos derivados por captura

- Prioridade: `ALTA`
- Status: `DONE`
- Estimativa: `12-16h`
- Complexidade: `Alta`
- Objetivo: concluir o redesign de handshake sets migrando os artefatos derivados do modelo legado compartilhado em `backend/data/handshakes/` para sidecars específicos por captura, resolvidos por `capture_id`.
- Estado atual:
  - os artefatos derivados usam o basename do PCAP original ao lado da captura, por exemplo `<pcap-basename>.details`, `.22000`, `.try` e `.cracked`
  - artefatos legados/compartilhados continuam legíveis como fallback, mas não aparecem mais como seção principal no Cracking Operations
  - API e UI já expõem proveniência e seleção por captura
  - há cobertura de regressão para `capture_id` e handshakes cross-source
- Requisitos:
  - `.details`, `.22000`, `.try` e `.cracked` baseados no basename do PCAP por captura
  - compatibilidade de leitura com artefatos legados/compartilhados
  - API e UI deixando claro o que é artefato específico da captura vs compartilhado
  - testes de regressão para colisões de basename entre Brucegotchi e M5 Evil

### Build combinado opcional para um mesmo BSSID

- Prioridade: `MÉDIA`
- Status: `DONE`
- Estimativa: `10-14h`
- Complexidade: `Alta`
- Objetivo: permitir que o operador combine manualmente múltiplas capturas válidas do mesmo handshake set para aumentar as chances de cracking, sem trocar o fluxo padrão baseado na captura preferida.
- Estado atual:
  - Cracking Operations expõe `COMBINED CANDIDATES` quando há capturas elegíveis
  - builds combinados ficam sob `backend/data/handshakes/combined/<mac_clean>/<build_id>/`
  - seleção por `combined_build_id` preserva proveniência sem alterar o fluxo padrão
- Requisitos:
  - ação manual no painel de cracking
  - deduplicação determinística e manifesto de proveniência
  - nada automático em background na v1
  - testes de scoring, fallback e override manual

## 2. Quality Gates e Segurança de Release

### Aplicar branch protection para `dev` e `main`

- Prioridade: `CRÍTICA`
- Status: `TODO`
- Estimativa: `3-5h`
- Complexidade: `Média`
- Objetivo: aplicar no GitHub o modelo novo de CI/CD para bloquear merges enquanto os checks esperados de `Quality` e `Security` não passarem.
- Processo:
  - abrir as configurações do repositório no GitHub em `Settings -> Branches -> Add branch protection rule`
  - criar uma regra para `dev`
  - criar uma regra para `main`
  - habilitar `Require a pull request before merging`
  - habilitar `Require status checks to pass before merging`
  - habilitar `Require branches to be up to date before merging`
  - bloquear force push e delete da branch
  - manter a estratégia de merge alinhada com a política do repositório (`squash`)
- Checks obrigatórios para configurar em `dev` e `main`:
  - `Quality / Artifact Guardrails`
  - `Quality / Backend Lint`
  - `Quality / Backend Unit Tests`
  - `Quality / Backend OpenAPI`
  - `Quality / Frontend Lint`
  - `Quality / Frontend Unit Tests`
  - `Quality / Frontend Validate`
  - `Security / SAST`
  - `Security / SBOM`
  - `Security / SCA`
  - `Security / Summary`
- Checklist de validação:
  - abrir uma PR para `dev` e confirmar que o merge fica bloqueado se qualquer check obrigatório falhar
  - abrir uma PR para `main` e confirmar o mesmo comportamento
  - verificar que as PRs automáticas de promoção criadas pelo bot também aguardam os checks obrigatórios
  - documentar qualquer diferença de nomenclatura se a UI do GitHub mostrar nomes diferentes dos jobs dos workflows

### Cobertura de branches do frontend de volta ao threshold

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `8-12h`
- Complexidade: `Média`
- Objetivo: voltar a ter `jest --coverage` passando sem reduzir o threshold atual de branches do frontend.
- Requisitos:
  - testes focados em `ui.js`, `map.js`, `ui_wardrive.js` e helpers relacionados
  - manter os thresholds globais como estão
  - documentar o fluxo de validação local antes de merge

### Smoke checks do app empacotado

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `6-8h`
- Complexidade: `Média`
- Objetivo: adicionar uma verificação repetível para builds empacotadas de Windows, macOS e Linux.
- Requisitos:
  - validar o backend binário correto por plataforma
  - subir o app empacotado e confirmar o boot do backend
  - testar `/api/health` após a inicialização
  - documentar o checklist de smoke test de release

## 3. Refatoração e Organização

### Clarificar `/scripts` vs `/backend/scripts`

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `4-6h`
- Complexidade: `Baixa`
- Objetivo: definir claramente a responsabilidade de scripts da raiz vs scripts específicos do backend.
- Entregáveis:
  - estrutura de pastas mais clara
  - docs atualizadas em `docs/03-DEVELOPMENT/`
  - READMEs locais onde fizer sentido

### Cleanup dos scripts do backend

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `6-8h`
- Complexidade: `Média`
- Objetivo: auditar scripts do backend, remover helpers obsoletos e documentar os que forem mantidos.
- Ações:
  - documentar cada script mantido
  - remover scripts legados
  - melhorar help/logging de forma consistente

## 4. Preparação para Open Source

### Cleanup e dados mock

- Prioridade: `CRÍTICA`
- Status: `DONE`
- Estimativa: `16-20h`
- Complexidade: `Alta`
- Objetivo: preparar a codebase para publicação pública com dados seguros e um modo demo utilizável.
- Estado atual:
  - código, config pública, docs e histórico Git foram saneados para o repositório público
  - dados reais de runtime não são versionados na árvore pública
  - o demo público atual usa o pack `backend/demo_data/showcase-core-v5/`
  - instalação/remoção do demo está disponível em `System Settings > Maintenance`
  - o snapshot de restauração é temporário e existe apenas enquanto o modo demo está ativo
- Tarefas:
  - remover paths absolutos pessoais
  - remover IPs privados, hostnames, tokens e credenciais
  - substituir SSIDs e MACs reais por dados mock
  - fornecer datasets demo em uma raiz dedicada
  - adicionar um bootstrap de first-run para demo

### Revisão de sensibilidade antes de publicar

- Prioridade: `CRÍTICA`
- Status: `DONE`
- Estimativa: `10-12h`
- Complexidade: `Alta`
- Objetivo: fazer uma auditoria ampla de dados sensíveis antes de qualquer release pública.
- Estado atual:
  - `.gitignore` cobre dados reais de handshakes, WarDrive, BrucePCAP, M5Evil, AIROLIB e backups
  - `backend/config.json` local deve continuar tratado como sensível e fora de commits
  - o review final ainda deve checar `git status`, `git diff --stat` e buscas direcionadas antes de cada release
- Áreas de auditoria:
  - arquivos-fonte
  - arquivos de configuração
  - histórico do Git
  - `backend/data/`
  - logs gerados e artefatos locais

## 5. Mapa e Visualização

### Melhorar cluster modes além do mais forte atual

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `12-16h`
- Complexidade: `Alta`
- Objetivo: melhorar os modos de cluster que hoje ficam atrás da melhor opção atual de agrupamento.
- Pontos de investigação:
  - por que o melhor modo atual performa melhor
  - como os thresholds devem variar por modo
  - como datasets mistos se comportam
  - se vale criar um modo automático mais inteligente

### Roll-up geográfico e escopo de foco para sessões WarDrive

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `6-10h`
- Complexidade: `Média`
- Objetivo: fazer a seleção e o foco de sessões WarDrive escolherem o menor escopo geográfico que representa a rota completa, não só a região mais profunda/com maior densidade.
- Comportamento atual:
  - o frontend já pode subir resultados de hierarchy focados em sessão para o ancestral visível comum
  - o hierarchy do backend ainda é baseado nas regiões das redes observadas, não na geometria completa da rota
- Requisitos futuros:
  - derivar cobertura da sessão a partir dos pontos da track, incluindo trechos sem redes observadas
  - retornar um `recommended_region_id` / `session_scope` explícito pela API de hierarchy ou de session track
  - subir sessões multi-bairro para cidade, multi-cidade para estado, multi-estado para país, preservando fallbacks robustos para regiões não mapeadas
  - adicionar testes de regressão de API e UI para sessões multi-bairro, multi-cidade, multi-estado e não mapeadas

## 6. Integrações de Dispositivos

### Expandir o auto-sync do M5Evil além do Cardputer

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `10-14h`
- Complexidade: `Média`
- Objetivo: expandir o fluxo novo de auto-sync do `M5Evil Cardputer` para outros dispositivos compatíveis do ecossistema M5 / Evil-M5 quando eles oferecerem o mesmo modelo de transporte web e armazenamento.
- Requisitos:
  - validar quais devices expõem o mesmo fluxo de `Admin WebUI` usado hoje no Cardputer
  - confirmar compatibilidade da estrutura de pastas no SD card para handshakes e exports de Wardrive
  - adicionar presets para targets compatíveis confirmados, como `M5 Core2`, `M5 AtomS3` e outras variantes suportadas do Evil-M5
  - manter compatibilidade retroativa com o profile atual do Cardputer
  - documentar diferenças de path ou capacidade por device em `docs/04-INTEGRATIONS/`

## 7. Inteligência Ofensiva — Tier 1 (Futuro)

> **Decisão (7 de Abril de 2026):** Features do Tier 1 aproveitam ferramentas e dados já existentes para adicionar camadas de inteligência. Documentadas aqui para implementação futura, após conclusão do Tier 2.

### Wordlist Arsenal Manager

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `14-18h`
- Complexidade: `Alta`
- Objetivo: CRUD completo + analytics de efetividade de wordlists. Upload, merge, split. Dashboard mostrando taxa de sucesso por wordlist × encryption × tipo de dispositivo.
- Notas: depende de pesquisa sobre geração de wordlists customizadas (iniciativa separada)

### Inteligência de Histórico de Ataques

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `10-14h`
- Complexidade: `Média`
- Objetivo: API de agregação sobre logs de histórico existentes. Taxa de sucesso por modo, por encryption, por wordlist. Timeline e análise de correlação.
- Notas: dados já existem nos arquivos `.try` e no history service

### Sequenciador Inteligente de Ataques

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `16-20h`
- Complexidade: `Alta`
- Objetivo: dado um MAC alvo, sugerir sequência ótima de ataques baseada em encryption, tipo de dispositivo e histórico de sucesso.
- Notas: depende da Inteligência de Histórico

### Hashcat Session/Restore

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `8-10h`
- Complexidade: `Média`
- Objetivo: adicionar suporte a `--session` e `--restore` no hashcat. Jobs pausáveis/resumíveis na UI.

### Modo PRINCE

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `6-8h`
- Complexidade: `Baixa`
- Objetivo: novo modo de ataque no hashcat usando PRINCE preprocessor para geração de passphrases.

### Candidatos por Markov Chain

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `8-12h`
- Complexidade: `Média`
- Objetivo: perfis `--markov-hcstat2` (inglês, português, numérico) para candidatos estatisticamente prováveis.

### Diagnóstico Kill-Chain

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `6-8h`
- Complexidade: `Baixa`
- Objetivo: expandir endpoint kill-chain com explicações de "por que travou" por rede (conversão faltando, .22000 vazio, sem EAPOL, etc.).

### Modo Loopback

- Prioridade: `BAIXA`
- Status: `TODO`
- Estimativa: `4-6h`
- Complexidade: `Baixa`
- Objetivo: modo `--loopback` onde senhas crackadas alimentam ataques futuros. Aprendizado de padrões de senhas reais.

## 8. Geração de Wordlists Customizadas (Pesquisa)

> **Decisão (7 de Abril de 2026):** Adiado até pesquisa de ferramentas open-source existentes para geração de wordlists. Avaliando soluções externas para integrar ao invés de construir do zero.

### Gerador de Wordlists Customizadas

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `TBD`
- Complexidade: `TBD`
- Objetivo: gerar wordlists direcionadas baseadas em SSID, região, idioma e padrões de senhas crackadas. Abordagem de integração (custom vs ferramenta externa) pendente de pesquisa.

## 9. Inteligência de Origem & Gestão de Sessões

> **Contexto:** o projeto já classifica arquivos wardrive por dispositivo (Bruce, M5Evil, uncategorized) e rastreia a origem GPS do pwnagotchi separadamente. Sessões são agrupadas por CSV, com suporte a merge (2-3 sessões por vez) e tagging de transporte. O próximo passo é elevar a origem dos dados de um rótulo por arquivo para uma feature de primeira classe com consciência de merges, análise de sobreposição multi-source, linhagem limpa de sessões e UI dedicada.

### Modelo Unificado de Origem

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `10-14h`
- Complexidade: `Alta`
- Objetivo: promover a classificação de origem de helpers dispersos (`_classify_wardrive_device`, `_is_bruce_wardrive_source`, `_is_m5evil_wardrive_source`) para um modelo único de origem que cubra todas as fontes de dados uniformemente — incluindo sessões mergeadas.
- Contexto:
  - hoje, a classificação de dispositivo roda no load do CSV e escreve um campo `device` (`bruce` / `m5evil` / `uncategorized`) por `wardrive_observation`
  - CSVs mergeados em `backend/data/wardrive/merged/` não herdam label de dispositivo; o manifesto de merge rastreia `source_leaf_session_ids` e `source_hashes` mas o arquivo mergeado é classificado como `uncategorized`
  - handshakes do pwnagotchi têm seu próprio caminho de origem mas nenhum campo `device` equivalente
  - dados do raw-sniffer (Bruce Raw Sniffing, M5Evil Raw Sniffing, M5Evil Master Raw Sniffing) carregam a origem implícita no nome do arquivo mas não são expostos no modelo de origem
- Plano de implementação:
  1. **Enum de origens** — definir um conjunto canônico de origens em um módulo compartilhado (`app/core/origins.py` ou similar): `PWNAGOTCHI`, `BRUCEGOTCHI`, `BRUCE_WARDRIVE`, `M5EVIL_WARDRIVE`, `BRUCE_RAW_SNIFFING`, `M5EVIL_RAW_SNIFFING`, `M5EVIL_MASTER_RAW_SNIFFING`, `MERGED`, `UNKNOWN`
  2. **Resolução de origem para merges** — ao criar uma sessão mergeada, computar uma origem composta: se todas as sessões-folha compartilham o mesmo dispositivo, a sessão mergeada herda (ex: `BRUCE_WARDRIVE`); se misto, taguear como `MERGED` com um array `leaf_origins` para drill-down
  3. **Tagging retroativo** — no reload de dados, preencher CSVs mergeados existentes usando seus `source_leaf_session_ids` para resolver tipos de dispositivo das folhas
  4. **Estender manifesto** — adicionar `device` e opcionalmente `leaf_origins` à entrada do manifesto wardrive para arquivos mergeados
  5. **Unificar pwnagotchi + raw-sniffer** — adicionar campos de origem equivalentes aos dicts de handshake e raw-sniffer para que toda rede carregue um campo `origin` consistente
- Testes:
  - merge de sessões all-Bruce → `BRUCE_WARDRIVE`
  - merge de sessões Bruce + M5Evil → `MERGED` com `leaf_origins: [BRUCE_WARDRIVE, M5EVIL_WARDRIVE]`
  - merge-de-merge (transitivo) resolve origens das folhas corretamente
  - CSVs existentes sem campo `device` no manifesto recebem backfill no reload

### Análise de Sobreposição Multi-Source

- Prioridade: `ALTA`
- Status: `TODO`
- Estimativa: `12-16h`
- Complexidade: `Alta`
- Objetivo: identificar e expor redes capturadas por múltiplas origens distintas, permitindo ao operador entender redundância de captura, gaps de cobertura e confiabilidade por fonte.
- Contexto:
  - cada rede já armazena um array `wardrive_sessions` com uma entrada por sessão detectora, mais dados opcionais do pwnagotchi
  - hoje, nenhuma API ou UI responde "quais redes foram vistas tanto pelo Bruce wardrive QUANTO pelo pwnagotchi?" ou "quantas redes são single-source vs multi-source?"
- Plano de implementação:
  1. **Computação de sobreposição** — no build do temporal-intel, computar por rede um set `source_origins` (usando o modelo unificado). Classificar cada rede como `single_source` ou `multi_source` com as origens contribuintes.
  2. **Estatísticas-resumo** — adicionar à resposta do temporal-intel:
     - `overlap.total_multi_source` — redes vistas por ≥2 origens distintas
     - `overlap.total_single_source` — redes vistas por exatamente 1 origem
     - `overlap.by_origin_pair` — para cada par de origens, contagem de redes compartilhadas (ex: `{"bruce_wardrive+pwnagotchi": 42}`)
     - `overlap.exclusive_by_origin` — redes vistas SOMENTE por aquela origem
  3. **Campo por rede** — adicionar `source_origins: string[]` a cada rede no data dict, disponível para o frontend consultar e filtrar
  4. **Inteligência de merge** — ao preparar um merge de sessões, mostrar ao operador quanta sobreposição as sessões selecionadas têm (MACs compartilhados, MACs novos, potencial de melhoria de GPS)
- Testes:
  - rede vista por bruce wardrive + pwnagotchi → `multi_source`, origins `{BRUCE_WARDRIVE, PWNAGOTCHI}`
  - rede vista apenas por M5Evil → `single_source`, exclusiva de `M5EVIL_WARDRIVE`
  - contagens de pares de overlap são simétricas e somam corretamente
  - preview de merge mostra contagem de MACs deduplicados correta

### Linhagem de Sessões & Árvore de Merge

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `8-12h`
- Complexidade: `Média`
- Objetivo: fornecer uma visão clara de linhagem de qualquer sessão até seus arquivos-fonte originais, incluindo merges transitivos, e expor isso na UI.
- Contexto:
  - o manifesto de merge já rastreia `merged_from_session_ids` e `source_leaf_session_ids` (transitivo)
  - `source_hashes` preserva SHA256 de todos os arquivos-folha
  - o painel de sessões no frontend mostra sessões mergeadas mas não visualiza a árvore de merge nem permite navegar relações pai→filho
- Plano de implementação:
  1. **API de linhagem** — `GET /api/wardrive/sessions/{id}/lineage` retornando uma estrutura de árvore: `{session, device, children: [...]}` para pais de merge, ou `{session, device, merged_into: [...]}` para sessões-folha
  2. **Enriquecimento do detalhe de sessão** — na API de listagem de sessões, incluir `is_merged`, `merge_depth` (0 para originais, 1 para primeiro nível de merge, 2+ para transitivo), e `leaf_count`
  3. **Árvore de merge no frontend** — no painel de detalhe da sessão Wardrive, renderizar um diagrama compacto de árvore (ASCII ou HTML/CSS simples) mostrando a linhagem: arquivos originais → sessão mergeada → opcionalmente mergeada novamente
  4. **Badges de proveniência de merge** — na lista de sessões, mostrar um badge para sessões mergeadas com profundidade de merge e origens das folhas (ex: "Merged · 14 sessões Bruce")
  5. **Lookup reverso** — a partir de qualquer sessão original, mostrar em quais sessões mergeadas ela participa
- Testes:
  - API de linhagem retorna árvore correta para merges de um nível e múltiplos níveis
  - leaf_count corresponde ao número real de CSVs originais
  - lookup reverso de folha para sessão mergeada é consistente

### Dashboard de Origem (Integração Geo Tab)

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `10-14h`
- Complexidade: `Média`
- Objetivo: expandir a seção GPS Origin existente na Geo tab para um Dashboard de Origem mais rico integrando sobreposição, linhagem de sessão e métricas de qualidade por captura.
- Contexto:
  - a seção Spatial Coverage da Geo tab já mostra barras de GPS Origin (pwnagotchi, wardrive:bruce, wardrive:m5evil, wardrive:uncategorized) e contagens de GPS por fonte
  - nenhuma UI atualmente mostra sobreposição multi-source, contribuição de merge ou qualidade por origem
- Plano de implementação:
  1. **Visualização de sobreposição** — adicionar um gráfico estilo Venn ou matriz mostrando sobreposição entre pares de origens (ex: quantas redes são compartilhadas entre bruce wardrive e pwnagotchi)
  2. **Barras exclusivo vs compartilhado** — na seção GPS Origin, dividir cada barra em "exclusivo" (só esta origem) e "compartilhado" (visto por outras origens também) com opacidades distintas
  3. **Contribuição de merge** — mostrar quantas redes vêm exclusivamente de sessões mergeadas vs já presentes em sessões individuais (justifica a operação de merge)
  4. **KPIs de qualidade por origem** — precisão GPS média, RSSI mediano, distribuição de encryption por origem
  5. **Contagem de sessões por origem** — contador pequeno mostrando quantas sessões alimentam cada barra de origem
- Entregáveis:
  - resposta temporal-intel estendida com dados de sobreposição
  - nova sub-seção na Geo tab ou seção Spatial Coverage enriquecida
  - layout responsivo para a matriz de sobreposição

### Melhorias de UX na Gestão de Sessões

- Prioridade: `MÉDIA`
- Status: `TODO`
- Estimativa: `8-10h`
- Complexidade: `Média`
- Objetivo: melhorar o fluxo de gestão de sessões wardrive com filtragem, agrupamento e orientação de merge melhores.
- Contexto:
  - o painel de sessões suporta ordenação (data, duração, distância, redes) e tagging de transporte
  - merge é limitado a 2-3 sessões por vez sem orientação sobre QUAIS sessões mesclar
  - sem agrupamento por dispositivo ou origem na lista de sessões
- Plano de implementação:
  1. **Agrupar por origem** — adicionar um toggle de agrupamento que junta sessões por origem de dispositivo (todas as Bruce juntas, todas as M5Evil juntas, mergeadas separadas)
  2. **Sugestões de merge** — quando o operador seleciona sessões para merge, mostrar um painel de preview com: MACs compartilhados, MACs únicos por sessão, delta de cobertura GPS, span de datas
  3. **Merge em lote** — estender o limite de 2-3 sessões para permitir selecionar um grupo de origem-dispositivo e mesclar todas as sessões daquela origem em uma (com confirmação + preview)
  4. **Indicador de duplicata** — na lista de sessões, marcar sessões que são 100% subsets de uma sessão mergeada (todos os MACs já existem em um arquivo mergeado)
  5. **Filtro por origem** — adicionar chips de filtro rápido para cada tipo de origem no header do painel de sessões

## Follow-ups de Documentação e Polimento de Produto

### Manutenção de IA de documentação e glossário

- Categoria: `doc gap`
- Prioridade: `MÉDIA`
- Status: `TODO`
- Objetivo: manter a documentação voltada ao operador alinhada conforme telas e fluxos de artefatos evoluem.
- Follow-ups:
  - manter README, Product Overview, Current Product Surface e Workflows by Objective sincronizados após mudanças grandes de UI
  - manter um glossário curto para estados como `locked`, `no_gps_locked`, `not_ready`, `cracked`, `canonical`, `combined` e `WDRS`
  - evitar descrever nomes internos de implementação como superfícies principais do produto

### Atualização de screenshots e mídia

- Categoria: `release blocker`
- Prioridade: `ALTA`
- Status: `TODO`
- Objetivo: substituir mídias pesadas ou desatualizadas dos READMEs/docs antes do próximo release público.
- Follow-ups:
  - substituir GIFs grandes por assets menores ou por um walkthrough otimizado regravado
  - verificar que screenshots usam apenas dados demo/sintéticos
  - manter seções de mídia equivalentes entre README e README PT-BR

### Hints de fluxo operacional na UI

- Categoria: `UX improvement`
- Prioridade: `MÉDIA`
- Status: `TODO`
- Objetivo: fazer a UI ensinar o ciclo do produto sem exigir que o operador leia todas as páginas de documentação primeiro.
- Follow-ups:
  - adicionar orientação leve em empty states do Tactical Map, No-GPS, Batch, Recon, WarDrive e Raw Sniffer
  - linkar demo mode e first-run actions em empty states quando fizer sentido
  - manter hints curtos e dispensáveis para não atrapalhar operadores avançados

### Checks contra drift entre documentação e código

- Categoria: `technical debt`
- Prioridade: `MÉDIA`
- Status: `TODO`
- Objetivo: detectar docs públicas obsoletas mais cedo quando APIs, nomes de artefatos ou workspaces mudarem.
- Follow-ups:
  - adicionar checks direcionados de CI para frases obsoletas como artefatos `capture.*` em pasta, nomes de demo pack removidos e telas aposentadas
  - documentar o checklist de atualização de docs quando Cracking Operations, Demo Mode, WarDrive ou Recon mudarem
  - considerar um smoke test simples de docs para validar paths de imagens dos READMEs e links de entrada principais

## Resumo

| Área | Count | Faixa de prioridade |
| --- | --- | --- |
| Ciclo de vida dos handshakes | 2 | Alta / Média |
| Quality gates e segurança de release | 3 | Crítica / Alta / Média |
| Refatoração / organização | 2 | Média |
| Preparação para open source | 2 | Crítica |
| Mapa / visualização | 1 | Alta |
| Integrações de dispositivos | 1 | Média |
| Inteligência ofensiva — Tier 1 | 8 | Alta / Média / Baixa |
| Geração de wordlists customizadas | 1 | Alta (TBD) |
| Inteligência de origem & gestão de sessões | 5 | Alta / Média |
| Documentação e polimento de produto | 4 | Alta / Média |

**Esforço total estimado:** `~233-313h`

**Owner:** Vitor Martins
