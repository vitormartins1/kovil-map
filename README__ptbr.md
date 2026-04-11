# KOVIL MAP

[![Quality](https://github.com/vitormartins1/kovil-map/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil-map/actions/workflows/quality.yml) [![Security](https://github.com/vitormartins1/kovil-map/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil-map/actions/workflows/security.yml) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg) ![License](https://img.shields.io/badge/License-MIT-purple.svg)

KOVIL MAP e um centro de comando desktop local-first para reconhecimento Wi-Fi, inteligencia geoespacial, cracking, enriquecimento de capturas RAW e analise de WarDrive.

Ele combina um frontend Electron com um backend FastAPI e concentra o fluxo operacional em um unico lugar:

- inteligencia de mapa e popups para redes conhecidas
- operacoes de cracking com Hashcat, Aircrack-ng, HCX tools, historico e quality gate
- ingestao do RAW Sniffer e preparacao hibrida RAW-to-hash
- workspace de WarDrive com hierarquia regional, sessoes, tags de veiculo e inventario de mapas
- workspace de Analytics com hotspots adaptativos, heatmaps, resumos de canal/dispositivo e contexto de WarDrive
- perfis de sync remoto para Pwnagotchi via SSH/SFTP e para M5Evil Cardputer via Admin WebUI

## Destaques Recentes

- o Recon Center agora usa carregamento lazy com cache por aba e por rede, com invalidacao por manifesto de cache e reabertura mais rapida
- COMMS e SIGINT ganharam visualizacoes mais ricas: mini barras, Communication Graph reformulado, Likely Device Groups e Probe Geocorrelation
- o WarDrive Workspace foi redesenhado para sessoes grandes com Replay Dock, Active Region, Workspace Explorer e skeleton loading sem bloquear tanto a interface
- a ingestao RAW agora trata capturas Bruce RAW, M5Evil RAW e M5Evil Master Sniffer como fontes distintas de enriquecimento em Recon, Geo e analytics
- os temas Professional, Synthwave e Military agora seguem de forma mais consistente o mesmo template visual nos workspaces principais

## Documentacao

O hub principal da documentacao fica em [`docs/INDEX.md`](docs/INDEX.md).

Entradas principais:

- [`docs/00-GETTING_STARTED/`](docs/00-GETTING_STARTED/) - instalacao e primeira execucao
- [`docs/01-ARCHITECTURE/`](docs/01-ARCHITECTURE/) - arquitetura e fluxo de dados
- [`docs/02-FEATURES/`](docs/02-FEATURES/) - WarDrive, RAW Sniffer, cracking, analytics e normalizacao espacial
- [`docs/03-DEVELOPMENT/`](docs/03-DEVELOPMENT/) - setup, testes, scripts e mapas por pais
- [`docs/05-API-ENDPOINTS/`](docs/05-API-ENDPOINTS/) - referencia REST e WebSocket
- [`docs/07-OPERATIONS/`](docs/07-OPERATIONS/) - guias operacionais
- [`SECURITY.md`](SECURITY.md) - politica de seguranca
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - fluxo de branch e PR
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) - expectativas da comunidade
- [`LICENSE`](LICENSE) - licenca MIT

## Status Open Source

KOVIL MAP agora e publicado como open source sob a licenca MIT.

- `main` continua como branch estavel
- `dev` continua como branch publica de integracao
- a documentacao da raiz segue bilíngue
- dados operacionais locais e credenciais de dispositivos nao fazem parte do estado publicado do repositório

## Comunidade

- use GitHub Issues para bugs e pedidos de feature
- use disclosure privado para reports sensiveis de seguranca
- siga [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) ao contribuir

## Superficie Atual do Produto

### Workspace do Mapa

- mapa tatico em Leaflet com clusters, heatmap, radar, zonas conquistadas e zonas a conquistar
- popups modernos com secoes de overview, sinal, seguranca, RAW e acesso
- acoes inline para cracking, favoritos, targets e visualizacao de senha quando aplicavel
- redes somente de Wardrive com semantica de origem propria, sem forcar CTA de cracking
- busca por SSID ou MAC sem separadores, com botao de limpar que reseta o filtro ativo

### Recon Center

- workspace ofensivo com sete abas: Surface, Intel, Ops, Geo, SIGINT, Report e COMMS
- COMMS agora separa Device Intelligence de Top Vendors e usa mini barras compactas para seguranca, origem e devices
- Communication Graph reformulado com grafico em largura total e cards auxiliares abaixo para leitura mais clara
- cache-first por aba, snapshots persistidos por sessao, hidratacao progressiva por secao e carregamento de detalhe por rede sob demanda
- SIGINT enriquecido com unmatched target SSIDs, contexto conhecido para SSIDs/clientes, Likely Device Groups e Probe Geocorrelation
- hints/tooltips contextuais para explicar metricas e secoes mais densas

### Workspace de WarDrive

- modo dedicado com hierarquia regional e zonas DBSCAN
- lista de sessoes baseada em `backend/data/wardrive/*.csv`
- filtros por sessao em hierarquia, zonas e marcadores
- tags de veiculo persistidas em `backend/data/wardrive/session_tags.json`
- inventario de mapas baseado em country packs de `backend/data/maps/<country_code>/`
- reabertura rapida e fluxo de refresh explicito para uso local/offline
- replay com compare mode, camera follow, presets de zoom, timing modes e controles de pace mais amplos
- layout novo com Replay Dock, Active Region compacto e Workspace Explorer separado em Regions e Zones
- skeleton loading animado para diminuir a sensacao de travamento em sessoes muito grandes

### Workspace de Analytics

- hotspots adaptativos baseados em clustering espacial em vez de celulas fixas
- abertura priorizando heatmap sem desenhar hotspots automaticamente
- detalhes de hotspot com MACs priorizados e fluxo de add-to-targets
- resumos de canal/dispositivo com contexto de WarDrive, incluindo principais modos de transporte

### Fluxos de Cracking e RAW

- conversao de `.pcap` para `.22000` com `hcxpcapngtool`
- Hashcat, Aircrack-ng, batch cracking, historico, attack insights e quality gate
- extracao do RAW Sniffer a partir de `raw_*.pcap`
- semantica de origem para Bruce RAW, M5Evil RAW e M5Evil Master Sniffer
- acordeao `RAW Sniffer` dentro de Cracking Operations com gerenciamento de RAW PCAP / RAW `.22000` por device
- `BUILD CANONICAL` e `BUILD CANONICAL FROM ALL` gerando hashes canonicos como `<ssid>_<mac>__wdrs__.22000`
- catalogo de handshake sets agrupando capturas de Pwnagotchi, Brucegotchi e M5Evil por BSSID
- painel de cracking organizado por origem/dispositivo, com acordeoes agrupados, destaque do grupo ativo, opcao de comportamento single-open e artefatos legados recolhiveis
- artefatos derivados por captura em `backend/data/handshakes/captures/<capture_id>/` para conversao, fingerprint, Aircrack e historico
- acoes por `capture_id` para conversao, fingerprint e Aircrack
- fluxo manual `BUILD COMBINED CANDIDATE` para uma BSSID, gerando `.22000` deduplicado em `backend/data/handshakes/combined/`
- candidates combinados selecionados agora mostram `COMBINED ORIGIN` com capturas incluidas, origens e resultado da deduplicacao
- extracao de details de RAW PCAP filtrada pela BSSID selecionada, alem de RAW Analysis completo no workspace dedicado de RAW
- `RAW ANALYSIS` agora aparece no Process panel enquanto o relatorio do capture esta sendo gerado
- exclusao de RAW com limpeza do `.pcap`, metadados cacheados e `.22000` irmao quando existir
- `Sync` agora consegue puxar handshakes, `RawSniff`, `masterSniffer` e CSVs de Wardrive do M5Evil Cardputer automaticamente para o catalogo local

## Estrutura do Repositorio

```text
backend/   Backend FastAPI, jobs, services, testes e dados locais
frontend/  App Electron, modulos do renderer, CSS e testes unitarios
docs/      Documentacao canonica de produto, API, desenvolvimento e operacao
docs/scripts/  Utilitarios exclusivos da documentacao
backend/scripts/  Utilitarios de backend
backend/scripts/manual/  Helpers legados e ad-hoc
```

## Desenvolvimento Local

### Inicializadores recomendados

- macOS: `./run_dev_mac.sh`
- Windows: `run_dev.bat`

### Execucao manual

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Frontend:

```bash
cd frontend
npm install
npm start
```

## Testes

Backend:

```bash
cd backend
./.venv/bin/python -m pytest app/tests --cov=app/api --cov=app/core --cov=app/schemas --cov=app/services --cov=app/utils --cov-report=term-missing
```

Frontend:

```bash
cd frontend
npm run test:unit
npm run test:unit:coverage
npm run test:smoke:packaged
```

## Uso Responsavel

Este projeto e voltado para pesquisa autorizada, laboratorio, auditoria e aprendizado. Varias features sao de uso dual. Voce e responsavel por usa-lo apenas em redes, capturas, dispositivos e sistemas seus ou explicitamente autorizados.

## Licenca

Licenciado sob a [MIT License](LICENSE).
