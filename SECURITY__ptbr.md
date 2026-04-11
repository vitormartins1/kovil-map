# Politica de Seguranca

KOVIL MAP e uma ferramenta local-first de seguranca com capacidades de uso dual.
Use-a apenas em redes, capturas, dispositivos e sistemas seus ou explicitamente
autorizados.

## Como Reportar uma Vulnerabilidade

Nao abra uma issue publica para vulnerabilidades sensiveis.

Canais preferenciais:

1. GitHub private vulnerability reporting, se estiver habilitado no repositorio
2. Contato privado com o mantenedor pelos canais do perfil/repositorio

Inclua:

- componente ou arquivo afetado
- versao ou commit impactado
- passos de reproducao ou prova de conceito
- impacto esperado
- mitigacao sugerida, se voce ja tiver uma

## Escopo

Esta politica cobre:

- o backend FastAPI em `backend/`
- o app Electron em `frontend/`
- o tratamento de configuracao local em `backend/config.json`
- os dados locais em `backend/data/`
- workflows do repositório e automacoes relacionadas a release

## Metas de Resposta

Metas de melhor esforco para disclosure responsavel:

- confirmacao em ate 72 horas
- triagem inicial em ate 7 dias
- remediacao coordenada conforme severidade e explorabilidade

Essas metas nao sao garantias.

## Safe Harbor

Apoiamos pesquisa de seguranca feita de boa-fe que:

- evita violacao de privacidade e destruicao de dados
- evita indisponibilidade ou persistencia
- usa a prova de conceito minima necessaria
- mantem o finding privado ate a triagem pelos mantenedores

## Notas Operacionais de Seguranca

- mantenha o backend em localhost, salvo quando autenticação estiver explicitamente habilitada
- prefira `KOVIL_API_TOKEN` ou `KOVIL_REQUIRE_API_TOKEN=1` ao expor a API alem do loopback
- trate `backend/config.json` como sensivel se ele contiver credenciais ou paths locais
- trate `backend/data/` como sensivel se houver capturas, cracks, GPS ou artefatos de sync
- valide a confiança SSH antes de sincronizar com dispositivos remotos

## Fora de Escopo

Em geral ficam fora de escopo, a menos que resultem diretamente de uma falha deste repositorio:

- ataques que exigem acesso fisico a uma maquina destravada
- escolhas inseguras do operador em laboratorio local
- vulnerabilidades que existem apenas em ferramentas terceiras fora da camada de integracao
- issues que nao possam ser reproduzidas em uma branch suportada ou no estado atual do projeto

## Documentos Relacionados

- [`docs/08-SECURITY/README.md`](docs/08-SECURITY/README.md)
- [`docs/08-SECURITY/vulnerability-policy.md`](docs/08-SECURITY/vulnerability-policy.md)
- [`docs/08-SECURITY/hardening.md`](docs/08-SECURITY/hardening.md)
- [`docs/08-SECURITY/threat-model.md`](docs/08-SECURITY/threat-model.md)
