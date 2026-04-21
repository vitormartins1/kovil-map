# KOVIL MAP

[![Quality](https://github.com/vitormartins1/kovil-map/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil-map/actions/workflows/quality.yml)
[![Security](https://github.com/vitormartins1/kovil-map/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil-map/actions/workflows/security.yml)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

[English](README.md) | Portugues (BR)

KOVIL MAP e um centro de comando desktop local-first para reconhecimento Wi-Fi, analise de WarDrive, sync remoto de capturas, enriquecimento RAW/PCAP e fluxos de cracking.

Ele combina um frontend Electron com um backend FastAPI para que o operador consiga inspecionar redes em um mapa tatico, entrar em workspaces especializados, executar jobs locais de longa duracao e manter o estado operacional em um unico lugar.

O produto se organiza em torno do Mapa Tatico e de workspaces dedicados para Recon, WarDrive e Raw Sniffer.

## Mapa Tatico

- cockpit principal para redes conhecidas, revisao de clusters, acoes de popup e triagem rapida de alvos
- overlays espaciais para zonas conquistadas, a conquistar, descobertas e zonas de inteligencia
- busca e revisao por status em datasets locais densos com contexto source-aware
- pontos de handoff para cracking, Recon e revisao de rotas a partir da mesma superficie operacional

## No-GPS

- workspace dedicado para redes que ainda nao possuem coordenadas utilizaveis no mapa tatico
- filtros por busca de SSID ou MAC, dispositivo de origem, status, visibilidade do nome e presenca de artefatos
- revisao separada entre itens cracked e locked para manter a triagem de evidencias sem GPS mais rapida
- handoff com um clique para operacoes de cracking a partir da entrada selecionada

## Batch

- workspace de alta vazao para montar um unico job de cracking a partir de varias redes e artefatos de handshake
- filtros operacionais por busca, localizacao, origem e presenca de artefatos antes de gerar o batch
- inventario de batches gerados e revisao do conteudo de cada batch depois da criacao
- pensado para datasets grandes de wardrive e pentest, em que subir o cracking engine por alvo seria ineficiente

## Recon Center

- workspace unificado de inteligencia com as abas SURFACE, INTEL, OPS, GEO, SIGINT, REPORT e COMMS
- hidratacao cache-first por aba para reabrir views densas mais rapido sem recarregar tudo de uma vez
- inteligencia de clusters em COMMS e Intelligence Zones projetadas de volta no mapa
- drilldown por alvo para superficie de ataque, threat analysis, signal intelligence e planejamento operacional

## WarDrive Workspace

<p align="center">
  <img src="docs/assets/screenshots/wardrive-sessions.gif" alt="Workspace de WarDrive do KOVIL MAP reproduzindo uma sessao no Rio de Janeiro" />
</p>

- hierarquia de sessoes e exploracao regional para conjuntos grandes de rotas em CSV
- replay de rota com pace, zoom, focus track e timeline controlada pelo operador
- contexto da regiao ativa com totais de redes e distribuicao entre abertas, cracked e locked
- workspace explorer para regioes e zonas, com handoff para visoes de map inventory
- fluxo local-first para revisar sessoes de wardrive e depois voltar ao mapa tatico e ao restante da operacao

## Raw Sniffer

- workspace source-aware para ingestao de capturas RAW de Bruce e M5Evil, metadados e limpeza de artefatos
- revisao de estado de cache, metadados de captura, hashes gerados e relatorios completos de RAW analysis
- ponte network-aware para fluxos de cracking por meio de hashes canonicos hibridos e artefatos de raw context
- pensado para gerenciar evidencias RAW sem empurrar todo artefato bruto para o mapa principal

## Zones, Targets e Favorites

- `ZONES` mantem overlays do mapa acionaveis com vistas dedicadas para zonas conquistadas, a conquistar, descobertas e de inteligencia
- `TARGETS` funciona como a lista de missao das redes que voce pretende atacar, analisar ou agrupar em batch
- `FAVORITES` mantem uma shortlist mais duravel de redes ou locais que valem revisita rapida
- esses paineis ajudam a sair da exploracao ampla do mapa para decisoes operacionais mais focadas

## Capacidades de Apoio

- **Operacoes de cracking** com Hashcat, Aircrack-ng, conversao HCX, helpers de PMK/WPS, execucao em lote, historico e acompanhamento de processos
- **Sync remoto** para Pwnagotchi via SSH/SFTP e para Bruce/M5Evil via fluxos baseados em WebUI

## Fluxo Tipico

1. Importar ou sincronizar handshakes, capturas RAW e sessoes de wardrive a partir de arquivos locais ou dispositivos remotos.
2. Revisar redes no mapa, inspecionar a inteligencia dos popups e escolher um alvo ou rota.
3. Migrar para Recon Center, WarDrive ou Raw Sniffer de acordo com a tarefa.
4. Executar jobs locais de cracking ou analise e acompanhar o progresso pelos paineis de processo.

## Como Comecar

Para operadores:

- instale uma release empacotada em [GitHub Releases](https://github.com/vitormartins1/kovil-map/releases)
- configure ferramentas externas como `hashcat`, `hcxpcapngtool`, `aircrack-ng` e `tshark` na tela de Settings
- use o [Guia de Primeira Execucao](docs/00-GETTING_STARTED/first-run.md) para sync/import e orientacao da UI

Para desenvolvimento:

```bash
git clone https://github.com/vitormartins1/kovil-map.git
cd kovil-map

cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python main.py
```

Abra um segundo terminal:

```bash
cd frontend
npm install
npm start
```

Documentos recomendados:

- [Guia de Instalacao](docs/00-GETTING_STARTED/installation.md)
- [Primeira Execucao](docs/00-GETTING_STARTED/first-run.md)
- [Superficie Atual do Produto](docs/00-GETTING_STARTED/current-product-surface.md)
- [Modos de Execucao](docs/00-GETTING_STARTED/runtime-modes.md)
- [Guia de Features](docs/02-FEATURES/README.md)
- [Fluxos por Objetivo](docs/07-OPERATIONS/workflows-by-objective.md)
- [Guia de Testes](docs/03-DEVELOPMENT/testing.md)

## Arquitetura

- `frontend/`: shell desktop em Electron, modulos do renderer, estilos e testes unitarios
- `backend/`: API FastAPI, services, background jobs, schemas e testes de backend
- `docs/`: documentacao de produto, arquitetura, API, operacao, seguranca e contribuicao

O backend foi desenhado para operacao local primeiro e normalmente atende o app desktop em `127.0.0.1:8000`. Builds empacotadas podem iniciar o backend automaticamente.

## Status do Projeto

- `main` e a branch estavel
- `dev` e a branch publica de integracao
- documentos de governanca e entrada da raiz seguem bilingues quando aplicavel
- o repositorio publica config inicial sanitizada, nao dados operacionais reais

## Documentacao

Comece pelo hub canonico: [docs/INDEX.md](docs/INDEX.md)

Entradas principais:

- [Getting Started](docs/00-GETTING_STARTED/README.md)
- [Superficie Atual do Produto](docs/00-GETTING_STARTED/current-product-surface.md)
- [Modos de Execucao](docs/00-GETTING_STARTED/runtime-modes.md)
- [Architecture](docs/01-ARCHITECTURE/README.md)
- [Features Guide](docs/02-FEATURES/README.md)
- [Fluxos por Objetivo](docs/07-OPERATIONS/workflows-by-objective.md)
- [API Overview](docs/01-ARCHITECTURE/api-overview.md)
- [Operations](docs/07-OPERATIONS/)
- [Politica de Seguranca](SECURITY.md)
- [Guia de Contribuicao](CONTRIBUTING.md)

## Uso Responsavel

KOVIL MAP e voltado para pesquisa autorizada, laboratorio, auditoria e aprendizado. Muitas capacidades sao de uso dual. Use o projeto apenas em redes, capturas, dispositivos e sistemas seus ou explicitamente autorizados.

### Conformidade Juridica, Etica e Responsabilidade Civil

Este software e classificado como uma ferramenta de Uso Dual (`Dual-Use`). Embora desenvolvido para fins educacionais e de auditoria de seguranca (`Pentest`), seu uso indevido pode acarretar serias consequencias legais.

Abaixo, detalhamos o enquadramento juridico no Brasil para promover a conscientizacao e o uso etico. Este resumo tem carater informativo e nao substitui orientacao juridica profissional.

#### 1. Esfera Penal (Crimes Ciberneticos)

O uso nao autorizado desta ferramenta pode configurar crimes tipificados no Codigo Penal Brasileiro e em tratados internacionais dos quais o Brasil e signatario, como a Convencao de Budapeste sobre Cibercrime.

**Invasao de Dispositivo (`Lei 12.737/2012` - `Lei Carolina Dieckmann`)**  
Art. 154-A: invadir dispositivo informatico alheio, incluindo roteadores e redes, conectado ou nao a rede, mediante violacao indevida de mecanismo de seguranca.

Atencao:
a simples tentativa de "quebrar" a senha, como uma chave WPA2, sem autorizacao, ja pode configurar o ato de violacao de mecanismo de seguranca.

**Interrupcao de Servico (`Art. 266` do Codigo Penal)**  
O uso de ataques de `Deauth` para capturar handshakes pode ser enquadrado como crime contra a seguranca de servico de utilidade publica, caso afete a conectividade de terceiros.

#### 2. Esfera Civil e Privacidade (Danos e Indenizacoes)

Alem de responder criminalmente, com pena de prisao e ou multa, o invasor esta sujeito a Responsabilidade Civil, devendo reparar danos materiais e morais.

**Lei Geral de Protecao de Dados (`LGPD` - `Lei 13.709/2018`)**  
Dados tecnicos como Endereco MAC e Handshakes, que contem trafego criptografado, podem ser considerados dados pessoais, pois identificam ou tornam identificavel uma pessoa fisica. A coleta e o tratamento desses dados sem base legal, como o consentimento do titular ou legitimo interesse comprovado, podem caracterizar violacao sujeita a sancoes.

**Marco Civil da Internet (`Lei 12.965/2014`)**  
Assegura a inviolabilidade da intimidade e da vida privada, garantindo indenizacao por danos decorrentes da violacao do sigilo das comunicacoes.

#### 3. O Mito da "Rede Aberta" e o Consentimento

Juridicamente, o fato de uma rede Wi-Fi estar aberta, sem senha, ou usar criptografia fraca, como WEP, nao constitui autorizacao tacita para invasao, interceptacao de trafego ou ataques.

**Consentimento Expresso**  
Para realizar testes de intrusao (`Pentest`) legalmente, e necessario um contrato ou autorizacao formal e escrita do proprietario da rede.

**Expectativa de Privacidade**  
Usuarios de redes, mesmo abertas, possuem uma expectativa juridicamente protegida de privacidade sobre seus dados.

### Codigo de Conduta do Usuario

Ao utilizar o KOVIL MAP, voce concorda em aderir aos seguintes principios eticos:

- **Principio da Autorizacao:** jamais atacar redes, dispositivos ou infraestruturas sem permissao explicita do proprietario.
- **Principio da Privacidade:** nao coletar, armazenar ou divulgar dados pessoais de terceiros obtidos acidentalmente.
- **Principio da Nao-Destruicao:** nao realizar acoes que possam degradar, interromper ou destruir servicos, como DoS persistente.
- **Responsabilidade:** assumir total responsabilidade legal por suas acoes. O desconhecimento da lei nao isenta o usuario de pena (`Ignorantia juris non excusat`).

KOVIL MAP — The world is yours to audit, ethically.

## Comunidade

- reporte bugs e pedidos de feature via GitHub Issues
- use [SECURITY.md](SECURITY.md) para disclosure sensivel de vulnerabilidades
- siga [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ao participar
- consulte [LICENSE](LICENSE) para os termos da licenca MIT
