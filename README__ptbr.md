# KOVIL MAP

[![Quality](https://github.com/vitormartins1/kovil-map/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil-map/actions/workflows/quality.yml)
[![Security](https://github.com/vitormartins1/kovil-map/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/vitormartins1/kovil-map/actions/workflows/security.yml)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

[English](README.md) | Portugues (BR)

KOVIL MAP e um centro de comando desktop local-first para reconhecimento Wi-Fi, analise de WarDrive, sync remoto de capturas, enriquecimento RAW/PCAP e fluxos de cracking.

Ele combina um frontend Electron com um backend FastAPI para que o operador consiga inspecionar redes em um mapa tatico, entrar em workspaces especializados, executar jobs locais de longa duracao e manter o estado operacional em um unico lugar.

As superficies principais atuais sao o Mapa Tatico, o Recon Center, o WarDrive Workspace e o Raw Sniffer. Alguns nomes internos ainda usam `analytics`, mas nao existe mais uma tela separada de Analytics na UI atual.

## Wardrive no Rio de Janeiro

<table>
  <tr>
    <td width="58%">
      <img src="docs/assets/screenshots/wardrive/wardrive-workspace-rio-de-janeiro.png" alt="Workspace de WarDrive do KOVIL MAP reproduzindo uma sessao no Rio de Janeiro" />
    </td>
    <td width="42%">
      <img src="docs/assets/illustrations/wardrive-rio-de-janeiro-hero.png" alt="Imagem ilustrativa de wardriving ambientada no Rio de Janeiro" />
    </td>
  </tr>
  <tr>
    <td>Vista real do WarDrive Workspace com replay de rota, contexto de regiao ativa e workspace explorer sobre dados do Rio de Janeiro.</td>
    <td>Arte ilustrativa para contextualizar visualmente o fluxo de Wardrive no Rio de Janeiro.</td>
  </tr>
</table>

## O Que o Projeto Faz

- **Mapa Tatico** para redes conhecidas, clusters, zonas, favoritos, alvos e acoes de popup.
- **Recon Center** para revisao de superficie de ataque, target intel, SIGINT, COMMS, GEO, OPS e fluxos de relatorios.
- **WarDrive Workspace** para hierarquia de sessoes CSV, replay, exploracao de regioes ativas e map inventory.
- **Raw Sniffer** para ingestao de capturas RAW, analise de metadados, enriquecimento e preparacao de artefatos prontos para cracking.
- **Operacoes de cracking** com Hashcat, Aircrack-ng, conversao HCX, helpers de PMK/WPS, execucao em lote, historico e acompanhamento de processos.
- **Sync remoto** para Pwnagotchi via SSH/SFTP e para Bruce/M5Evil via fluxos baseados em WebUI.

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

## Comunidade

- reporte bugs e pedidos de feature via GitHub Issues
- use [SECURITY.md](SECURITY.md) para disclosure sensivel de vulnerabilidades
- siga [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ao participar
- consulte [LICENSE](LICENSE) para os termos da licenca MIT
