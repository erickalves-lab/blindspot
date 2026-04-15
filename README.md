# 🔍 BlindSpot

Framework de auditoria de segurança para Linux em desenvolvimento ativo.

O BlindSpot nasce da necessidade de tornar auditoria de conformidade acessível e prática. A ideia é simples: rodar a ferramenta num servidor Linux e receber um diagnóstico claro de onde estão os pontos cegos de segurança, com referência normativa, evidência coletada e recomendação de remediação.

---

## O que está sendo construído

Uma CLI em Python que audita ambientes Linux verificando conformidade com **ISO/IEC 27001:2022**, **NIST CSF 2.0** e **LGPD**, gerando score de maturidade por domínio e relatório Excel estruturado.

---

## Módulos

| Módulo | Domínio | Status |
|---|---|---|
| `iam` | Identidades e Acessos | ✅ Implementado |
| `ssh` | Configuração SSH | ✅ Implementado |
| `network` | Rede e Firewall | ✅ Implementado |
| `filesystem` | Permissões e Arquivos | ✅ Implementado |
| `logs` | Auditoria e Retenção | ✅ Implementado |
| `updates` | Patches e Atualizações | 🔄 Em desenvolvimento |
| `lgpd` | Privacidade e Dados Pessoais | 🔄 Em desenvolvimento |

---

## Roadmap

- [x] Estrutura base do projeto
- [x] Módulos de auditoria (IAM, SSH, Network, Filesystem, Logs)
- [ ] Módulos de auditoria (Updates, LGPD)
- [ ] Engine de score de maturidade
- [ ] Engine de comparação entre execuções
- [ ] Gerador de relatório Excel
- [ ] Menu interativo de seleção de módulos
- [ ] README completo com documentação de uso

---

## Autor

**Erick Alves** — Analista de GRC | Segurança da Informação
[![LinkedIn](https://img.shields.io/badge/LinkedIn-erick--alves--sec-blue)](https://linkedin.com/in/erick-alves-sec)