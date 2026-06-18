# CHANGELOG

Todas as mudanças relevantes deste projeto serão documentadas neste arquivo.

O formato segue uma estrutura baseada em versões e datas, agrupando as alterações por tipo.

## [Unreleased]

Nenhuma alteração pendente.

## [v1.4.1] - 2026-06-15

### Changed
- Validada a documentação principal do projeto após a revisão completa de português do Brasil realizada na `v1.4.0`.
- Atualizado o `README.md` para refletir a versão `v1.4.1`, mantendo a centralização da documentação no repositório e a referência à documentação operacional interna em `/documentation/`.
- Revisados comandos, fluxos, caminhos, orientações de deploy, rollback, validação e segurança operacional para confirmar aderência ao estado atual do projeto.

### Documentation
- Registrada a melhoria documental da `v1.4.1`, focada em consistência, clareza, versionamento e coerência entre `README.md`, `CHANGELOG.md` e documentação operacional interna.
- Corrigidos ajustes residuais de português, acentuação e concordância em trechos documentais.
- Confirmada a ausência de dependência da pasta `docs`; o conteúdo relevante permanece consolidado em arquivos principais e na rota interna `/documentation/`.

### Breaking changes
- Nenhum breaking change identificado. A versão `v1.4.1` não altera regras de negócio, rotas, APIs, banco de dados ou integrações.

## [v1.4.0] - 2026-06-15

### Added
- Implementada a funcionalidade **Assinar CSR externa** em `/certificates/request/external-csr`.
- Adicionada interface para envio de CSR por upload de arquivo `.csr`, `.pem` ou `.txt`, ou por colagem de conteúdo PEM.
- Criado fluxo de solicitação pendente para CSRs externas, preservando aprovação/recusa antes da emissão.
- Adicionada assinatura de CSR externa pela CA interna sem importar, gerar ou armazenar a chave privada do equipamento de origem.
- Incluídos atalhos para assinatura de CSR externa nas telas Início, Solicitações e Certificados emitidos.
- Adicionados testes automatizados específicos para validação, rejeição de chave fraca, emissão por CSR externa e criação da solicitação pendente.

### Changed
- Atualizada a versão padrão da aplicação e do `.env.example` para `1.4.0`.
- Atualizada a documentação operacional para refletir a nova funcionalidade, os controles de segurança e as diferenças entre certificados gerados pelo sistema e certificados assinados a partir de CSR externa.
- Ajustados downloads de certificados emitidos por CSR externa para não oferecer `.key`, `.pfx`, `.p12` ou `.zip` com chave privada, pois a chave privada permanece no equipamento externo.

### Security
- Validada a assinatura interna da CSR antes de criar solicitação ou assinar certificado.
- Exigido Common Name na CSR.
- Aplicada política mínima de chave pública: RSA 2048 bits ou superior, ou ECDSA em curvas aprovadas.
- Definido limite de tamanho de 64 KB para entrada de CSR.
- Bloqueado envio simultâneo por upload e colagem para evitar ambiguidade operacional.
- Impedido reaproveitamento de `BasicConstraints` da CSR como CA; certificados assinados por CSR externa são emitidos com `ca=False`.
- Mantida segregação de funções: a CSR externa entra como solicitação pendente e depende de aprovação com permissão `cert.approve`.

### Tests
- Suite automatizada ampliada de 14 para 18 testes.
- Validada compilação Python, parse de templates Jinja e `unittest discover`.

### Documentation
- Atualizados `README.md`, documentação interna em `/documentation/`, `CHANGELOG.md`, relatório de prontidão e runbook de homologação para `v1.4.0`.
- Documentado o comportamento seguro de download para certificados com chave privada externa.
- Consolidado o conteúdo relevante da antiga pasta `docs` em `README.md` e `CHANGELOG.md`, eliminando dependência de documentação fragmentada no repositório.

### Breaking changes
- Nenhum breaking change identificado. O fluxo existente de solicitação gerada pelo sistema permanece disponível e sem alteração intencional de contrato.

### Observações
- Data de homologação registrada como `2026-06-15`, conforme data do ambiente desta revisão. Confirmar se a ata formal de homologação utiliza outra data.

## [v1.3.0] - 2026-06-12

### Changed
- Otimizada a tela de monitoramento de certificados para aplicar busca, filtros e paginação no banco de dados em vez de carregar lote fixo em memoria.
- Reduzido o padrão N+1 nas telas administrativas de usuários e grupos.
- Substituídos inserts SQL manuais de downloads e revogações por modelos ORM dedicados.
- Atualizada a versão da aplicação e documentação interna para `1.3.0`.
- Criado runbook de deploy em homologação com checklist de produção.

### Database
- Adicionados modelos SQLAlchemy para `certificate_downloads` e `revocations`.
- Preparada criação idempotente de índices de performance para certificados, solicitações, downloads, RBAC e auditoria.
- Declarados relacionamentos ORM para certificados, grupos de certificados, downloads, revogações, usuários e permissões.
- Aplicadas foreign keys físicas para certificados, downloads, grupos, usuários e permissões no schema `certificadora_db`.
- Padronizada a collation de `certificadora_db.certificate_groups` para `utf8mb4_unicode_ci`.
- Removido índice redundante `audit_log.mfa_users.idx_mfa_username`, mantendo o índice único `username`.
- Atualizadas estatísticas das tabelas de `certificadora_db` e `audit_log` com `ANALYZE TABLE`.
- Criados `migration_homologacao.sql`, `rollback_homologacao.sql` e `validation_homologacao.sql`.

### Security
- Melhorada a rastreabilidade estrutural de downloads e revogações por meio de modelos e relacionamentos explícitos.
- Mantida criação de foreign keys físicas fora da execução automática para evitar risco de indisponibilidade em produção sem saneamento prévio dos dados.
- Ajustados grants de `certificadora_app` e `certificadora_audit` para reduzir privilégios fora do escopo confirmado.
- Documentado plano de rollback e registro auditável da execução, posteriormente consolidado no `README.md`.
- Criado `.env.example` sanitizado e `.gitignore` para bloquear `.env`, logs, caches, CA, storage, certificados, chaves e backups locais.
- Gerado `requirements.lock.txt` para homologação com dependências fixadas do ambiente validado.

### Tests
- Mantida cobertura automatizada de monitoramento e storage após as otimizações de consulta.
- Validada compilação Python, templates Jinja, bootstrap Flask, `pip check` e suíte `unittest`.

### Breaking changes
- Nenhum breaking change identificado.

### Observações
- A versão `v1.3.0` é uma evolução minor sobre `v1.2.0`, pois adiciona preparação operacional de banco, segurança e homologação sem alterar contratos externos intencionalmente.

## [v1.2.0] - 2026-06-12

### Added
- Adicionada camada central de armazenamento de artefatos de certificados em `app/certificates/storage.py`.
- Incluída nova variável `STORAGE_ROOT`, usada como raiz lógica para novos artefatos em disco.
- Criada cobertura automatizada para validar layout reorganizado, escrita, resolução de paths, compatibilidade legada e rejeição de path traversal.

### Changed
- Reorganizada a gravação de novos artefatos em `storage`, separando certificados emitidos, certificados importados, chaves privadas e CSRs.
- Mantida compatibilidade de leitura para caminhos legados em `storage/certificates`.
- Atualizada a emissão de certificados para gravar novos `.crt`, `.key` criptografados e `.csr` em subpastas dedicadas.
- Atualizada a importação de certificados para gravar novos certificados importados por fingerprint.
- Atualizados `README.md` e documentação interna para refletir `STORAGE_ROOT`, a nova estrutura de armazenamento e a compatibilidade com artefatos legados.

### Fixed
- Removida a dependência de escrita direta em `Config.CERT_STORAGE_DIR` nos fluxos de emissão e importação.

### Security
- Centralizada a resolução de paths de artefatos de certificados, restringindo leitura e escrita a raízes de storage permitidas.
- Separadas chaves privadas de certificados públicos e CSRs para permitir controles de ACL, backup e auditoria mais granulares.
- Mantida leitura compatível de artefatos legados sem mover ou excluir arquivos existentes, reduzindo risco operacional durante a migração.

### Tests
- Adicionados testes unitários para a nova camada de storage.

### Breaking changes
- Nenhum breaking change identificado. Caminhos legados continuam sendo resolvidos para downloads e operação de certificados já emitidos.

### Observações
- A versão `v1.2.0` é uma evolução minor sobre `v1.1.0`, pois adiciona uma nova estrutura operacional de armazenamento sem alterar contratos externos intencionalmente.

## [v1.1.0] - 2026-06-12

### Added
- Busca textual na tela `/certificates/monitoring` por nome comum, emissor, serial ou fingerprint.
- Paginação do inventário de certificados monitorados.
- Cobertura automatizada para renderização, filtros, busca, paginação e estado vazio do monitoramento.
- Documentação técnica dos códigos de permissão, fluxos operacionais, runbooks, backup, rollback, segurança e supply chain.

### Changed
- Reorganização UX/UI de `/certificates/monitoring` em seções para certificados monitorados, grupos e importação.
- Redução da tabela de certificados monitorados para colunas prioritárias, com ação de grupo em painel compacto e layout responsivo em cards para telas menores.
- Atualização do controle de versão da documentação interna para `1.1.0`.
- Substituição do exemplo de `.env` por modelo sanitizado, sem valores reais de infraestrutura, usuários privilegiados ou segredos.
- Ajuste da descrição do runtime homologado para refletir execução via NSSM com `python .\run.py`.
- Ajuste da descrição de sessão para indicar política configurável e necessidade de validação em runtime.
- Atualização da seção de dependências para refletir `Gunicorn` em vez de `Waitress`.

### Fixed
- Corrigida a resolução de caminhos relativos dos arquivos da CA e do armazenamento de certificados para evitar falha de emissão quando o serviço é iniciado fora da raiz do projeto.
- Adicionado suporte a `WEB_SSL_KEY_PASSWORD` para carregar chave privada HTTPS protegida por senha sem prompt manual no startup do Flask.
- Corrigidas inconsistencias entre a documentação interna e a estrutura real do projeto.
- Corrigidas referências de sumário para âncoras de banco inexistentes.
- Corrigida a descrição do banco `audit_log`, indicando que eventos de autenticação, MFA e auditoria são centralizados em `logs_certificadora` nesta versão.

### Security
- A aprovação de solicitações agora falha de forma controlada quando os arquivos da CA estão ausentes ou inválidos, mantendo a solicitação pendente e registrando auditoria sem expor conteúdo sensível.
- O runtime agora bloqueia `FLASK_DEBUG=true` quando `APP_HOST` não é loopback, evitando exposição remota do debugger do Flask.
- Incluída orientação explícita para não versionar `.env`, chaves privadas, certificados reais, backups, PFX/P12 ou artefatos sensíveis.
- Incluída orientação para tratar exposição de chaves, segredos ou artefatos reais como incidente, com remoção controlada, rotação e registro de evidências.
- Incluída orientação de menor privilégio para usuários de banco e uso de variáveis de ambiente, arquivo local não versionado ou cofre corporativo aprovado.
- Incluídos controles a validar para HTTPS, LDAPS, security headers, limite de upload, arquivos importados e rate limiting.

### Tests
- Revisados testes automatizados de `/certificates/monitoring` para validar resumo, filtros de status e vencimento, busca por emissor, paginação e estado vazio.
- Mantida validação sintática recomendada para os módulos Python antes de publicação.

### Documentation
- Atualizado `README.md` com versão de produção, funcionalidades principais, comandos de teste, orientação de build/publicação e referência ao monitoramento.
- Atualizada a documentação interna do monitoramento para refletir seções, busca, filtros, paginação, grupos e importação.
- Documentado o comportamento de resolução de caminhos e falha segura para indisponibilidade da CA.
- Documentado o diagnóstico de `Enter PEM pass phrase`, validação de par `.crt`/`.key` e procedimento seguro para uso local de chave operacional sem senha.
- Criado e consolidado este `CHANGELOG.md` para padronizar o histórico de mudanças do projeto.

### Breaking changes
- Nenhum breaking change identificado.

### Observações
- A versão `v1.1.0` é a próxima versão adequada sobre `v1.0.0`, pois inclui melhorias funcionais e de UX/UI relevantes sem alteração incompatível.
- O aprovador da documentação interna permanece como "A definir" até validação formal da equipe.

## [v1.0.0] - 2026-05-29

### Added
- Estrutura inicial do projeto.
- Aplicação Flask para gestão interna do ciclo de vida de certificados digitais.
- Integração com LDAP/AD para autenticação de usuários.
- MFA TOTP para reforço de autenticação.
- RBAC por usuários, grupos e permissões.
- Fluxos de solicitação, aprovação, emissão, download, monitoramento e revogação de certificados.
- Auditoria estruturada em banco de dados.
- Persistencia operacional em MariaDB/MySQL-compatible.
- Armazenamento de certificados, chaves, CSRs e artefatos da CA em disco.
- Templates HTML para autenticação, administração, certificados, auditoria, monitoramento e documentação interna.

### Security
- Inclusão de controles de autenticação, MFA, RBAC e CSRF.
- Inclusão de trilha de auditoria para eventos administrativos, autenticação, MFA, downloads, emissão, recusa e revogação.
- Inclusão de bloqueio temporário por falhas de login.
- Inclusão de proteção padrão para exportação PFX/P12 com senha.

### Documentation
- Criação da documentação interna da Certificadora.
- Inclusão de seções de arquitetura, ambiente, configuração, autenticação, CA, módulos funcionais, fluxos operacionais, banco de dados, permissões, runbooks, backup, deploy, segurança, riscos, glossário e dependências.

### Observações
- A documentação inicial foi consolidada como base técnica, operacional e de auditoria do projeto.

