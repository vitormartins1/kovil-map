# Guia de Contribuicao

Obrigado por contribuir com o KOVIL MAP.

Este repositório continua com o fluxo `main + dev`:

- `main` e a branch estavel
- `dev` e a branch de integracao
- contribuições de feature normalmente devem ir para `dev`

## Formas de Contribuir

- reportar bugs usando o template de issue
- propor features usando o template de issue
- melhorar docs, testes, UX ou automacoes
- enviar pull requests focados para `dev`

## Nomes de Branch

Nomes recomendados:

- `feature/<nome>`
- `fix/<nome>`
- `chore/<nome>`
- `docs/<nome>`

## Fluxo Normal de Contribuicao

1. Crie a branch a partir de `dev`.
2. Faça uma mudança focada.
3. Rode os checks locais relevantes.
4. Abra uma pull request para `dev`.
5. Ajuste feedbacks e eventuais falhas de CI.
6. Depois do merge em `dev`, os mantenedores promovem `dev` para `main`.

Os mantenedores podem usar os workflows automáticos de promoção, mas contribuidores externos não precisam depender deles. Uma PR normal para `dev` continua sendo o caminho padrão.

## Validacao Local Antes do Push

Backend:

```bash
pip install -r backend/requirements.txt
pip install -r backend/requirements-dev.txt
ruff check backend/app
black --check backend/app
pytest backend/app/tests --cov=backend/app --cov-fail-under=70
```

Frontend:

```bash
npm ci --prefix frontend
npm --prefix frontend run test:unit:coverage
```

## Expectativas para Pull Requests

- mantenha cada PR focada em um problema ou melhoria
- adicione testes quando houver mudança de comportamento
- atualize a documentação quando setup ou comportamento público mudarem
- não faça commit de segredos, tokens, configs pessoais ou capturas operacionais
- descreva impacto e validação no corpo da PR

## Visao Geral da CI

Workflows principais:

- `.github/workflows/quality.yml`
- `.github/workflows/security.yml`

Helpers de promoção usados por mantenedores:

- `.github/workflows/auto-pr-feature-to-dev.yml`
- `.github/workflows/auto-pr-dev-to-main.yml`

## Padroes da Comunidade

- leia [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) antes de participar
- use [`SECURITY.md`](SECURITY.md) para reports sensiveis de vulnerabilidade
- trate `backend/data/` e `backend/config.json` como material local sensivel

## Configuracoes Recomendadas do Repositorio

1. Defina `main` como branch padrão.
2. Proteja `dev` e `main`.
3. Exija pull request antes de merge.
4. Exija os checks de `Quality` e `Security` nas branches protegidas.
5. Prefira merge por `squash` para PRs de contribuição.
