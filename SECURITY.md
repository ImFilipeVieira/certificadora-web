# Security Policy

## Supported Versions

Atualmente apenas a versão mais recente é considerada suportada para correções de segurança.

| Version        | Supported |
| -------------- | --------- |
| Latest         | ✅         |
| Older Releases | ❌         |

## Reporting a Vulnerability

Caso você identifique uma vulnerabilidade de segurança, não abra uma issue pública.

Solicita-se que a vulnerabilidade seja reportada de forma responsável ao mantenedor do projeto.

O relatório deve conter:

* Descrição da vulnerabilidade
* Impacto potencial
* Vetor de exploração
* Evidências ou PoC (quando possível)
* Sugestão de mitigação

## Escopo de Segurança

Este projeto possui componentes relacionados a:

* PKI
* Certificados digitais
* LDAP/Active Directory
* MFA
* Controle de acesso baseado em papéis (RBAC)
* Auditoria de eventos

Por esse motivo, qualquer alteração que afete:

* Autenticação
* Autorização
* Sessões
* Criptografia
* Armazenamento de certificados
* Chaves privadas

deve ser tratada com atenção especial.

## Divulgação Responsável

O projeto segue o princípio de Responsible Disclosure.

Após validação da vulnerabilidade:

1. A correção será desenvolvida.
2. Uma nova versão será publicada.
3. O CHANGELOG registrará a correção.
4. A divulgação pública ocorrerá apenas após a disponibilização do patch.

## Boas Práticas

Nunca versione:

* Arquivos .env
* Certificados reais
* Chaves privadas
* Arquivos PFX/P12 operacionais
* Backups de produção
* Logs contendo dados sensíveis
* Credenciais LDAP/AD

## Isenção

Este projeto é disponibilizado "como está" e não substitui auditorias formais de segurança, testes de invasão ou validações corporativas.

## Reportar via GitHub Security Advisories

Este repositório utiliza o recurso de
[Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
do GitHub. Utilize-o para enviar relatórios de forma confidencial sem abrir uma issue pública.