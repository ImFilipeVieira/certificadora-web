# Contributing

Obrigado por considerar contribuir com este projeto.

## Objetivo

Este projeto tem como objetivo fornecer uma plataforma para gerenciamento interno do ciclo de vida de certificados digitais, com foco em segurança, rastreabilidade e boas práticas operacionais.

## Como contribuir

### 1. Faça um Fork

Crie um fork do repositório e clone-o localmente.

### 2. Crie uma Branch

Utilize o fluxo Git Flow:

```bash
git checkout develop
git checkout -b feature/nome-da-feature
```

Exemplos:

```bash
feature/certificate-monitoring
feature/external-csr-signing
fix/login-timeout
```

### 3. Desenvolva

Siga os padrões já adotados pelo projeto:

* Código limpo e legível
* Princípios de segurança por padrão
* Menor privilégio
* Tratamento adequado de erros
* Não introduzir segredos ou credenciais no código

### 4. Testes

Antes de enviar alterações:

```bash
python -m unittest discover tests
```

Garanta que todos os testes passem.

### 5. Conventional Commits

Utilize mensagens compatíveis com Conventional Commits.

Exemplos:

```text
feat: add certificate expiration notifications
fix: correct ldap authentication validation
docs: update installation guide
refactor: simplify certificate storage service
test: add monitoring endpoint coverage
chore: update dependencies
```

### 6. Pull Request

Toda contribuição deve:

* Possuir descrição clara
* Informar objetivo da alteração
* Informar possíveis impactos
* Atualizar documentação quando necessário
* Atualizar CHANGELOG quando aplicável

## Requisitos de Segurança

Contribuições que afetem:

* Autenticação
* MFA
* LDAP
* RBAC
* Certificados
* Criptografia

devem incluir avaliação de impacto de segurança.

## Código de Conduta

Ao contribuir, você concorda com o CODE_OF_CONDUCT.md deste projeto.
