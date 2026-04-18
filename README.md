# 🔍 BlindSpot

**Framework de auditoria de segurança para Linux — ISO 27001:2022 | NIST CSF | LGPD**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Em%20desenvolvimento-orange.svg)]()

---

## O problema

Todo ambiente de TI tem pontos cegos de segurança. Controles que deveriam estar implementados mas não estão, configurações que saíram do padrão sem que ninguém percebesse, contas esquecidas, senhas fracas, serviços desnecessários expostos...

O problema não é a falta de normas, pois ISO 27001, NIST CSF e LGPD definem claramente o que precisa ser feito. O problema é que verificar manualmente dezenas de controles técnicos num servidor Linux é lento, sujeito a erro humano e impossível de escalar.

O BlindSpot foi criado para resolver isso.

---

## O que é

O BlindSpot é uma ferramenta CLI em Python que audita ambientes Linux de forma automatizada. Ela coleta dados reais do sistema, cruza com uma base de controles normativos e entrega um diagnóstico claro: o que está conforme, o que não está, qual é a evidência e o que precisa ser feito.

A saída não é só uma lista de problemas, é um score de maturidade por domínio, um plano de ação estruturado e um relatório Excel pronto para ser apresentado para gestão ou auditores.

---

## Arquitetura

O projeto foi construído em camadas com responsabilidades bem definidas:

blindspot/
├── blindspot.py        # Interface CLI — menu interativo e orquestração
├── modules/            # Camada de coleta — cada módulo audita um domínio
├── engine/             # Camada de análise — scoring e comparação
├── mappings/           # Base normativa — controles ISO 27001, NIST CSF e LGPD em JSON
└── reports/            # Camada de saída — gerador de relatório Excel

### Camada de coleta — `modules/`

Cada módulo é independente. Ele lê o estado real do sistema via comandos do SO, arquivos de configuração e APIs do kernel sem alterar nada. Retorna uma lista padronizada de verificações com status, evidência coletada e recomendação de remediação.

A independência dos módulos é intencional: novos domínios podem ser adicionados sem tocar no core da ferramenta.

### Camada de análise — `engine/`

**scorer.py** recebe os resultados de um módulo e calcula o score de maturidade (0 a 3) com base no percentual de conformidade. Transforma uma lista de verificações num diagnóstico de maturidade.

**comparator.py** salva um snapshot JSON após cada execução. Na próxima execução, compara com o snapshot anterior e calcula o delta por módulo mostrando evolução ou regressão ao longo do tempo.

### Base normativa — `mappings/`

Os controles normativos ficam em arquivos JSON separados do código. Cada controle tem ID, descrição, módulo responsável e função NIST CSF associada. Isso permite atualizar a base normativa sem alterar a lógica da ferramenta.

### Camada de saída — `reports/`

**report_engine.py** consolida todos os resultados e gera um arquivo Excel com quatro abas:

| Aba | Conteúdo |
|---|---|
| Resumo Executivo | Score geral, conformidade por módulo, nível de maturidade |
| Resultados | Todas as verificações com status, evidência e recomendação |
| Plano de Ação | Apenas não conformidades, com campos para responsável e prazo |
| Comparação | Delta entre a execução atual e a anterior |

---

## Módulos

| Módulo | Domínio | Controles | Verificações |
|---|---|---|---|
| `iam` | Identidades e Acessos | ISO 27001 A.5.15, A.5.18, A.8.2, A.8.5 | 6 |
| `ssh` | Configuração SSH | ISO 27001 A.8.20, A.8.5 / CIS 5.2 | 6 |
| `network` | Rede e Firewall | ISO 27001 A.8.20, A.8.21 / CIS 3.5 | 6 |
| `filesystem` | Permissões e Arquivos | ISO 27001 A.5.12, A.5.13, A.8.3 | 5 |
| `logs` | Auditoria e Retenção | ISO 27001 A.8.15, A.8.16 | 6 |
| `updates` | Patches e Atualizações | ISO 27001 A.8.8 / CIS 1.9 | 5 |
| `lgpd` | Privacidade e Dados Pessoais | LGPD Art. 46, 48, 49 / ISO 27001 A.5.34 | 5 |

**Total: 39 verificações automatizadas em 7 domínios.**

---

## Score de Maturidade

Cada módulo recebe um score de 0 a 3 calculado com base no percentual de verificações conformes:

| Score | Nível | Conformidade |
|---|---|---|
| 3 | Gerenciado | ≥ 80% |
| 2 | Definido | 50% – 79% |
| 1 | Inicial | 25% – 49% |
| 0 | Inexistente | < 25% |

O score geral do ambiente é a média dos scores por módulo. Isso transforma o relatório de uma lista de problemas em um diagnóstico de maturidade, a linguagem que gestores e auditores usam.

---

## Frameworks de Referência

Cada verificação é fundamentada em normas reconhecidas:

**ISO/IEC 27001:2022** — os controles do Anexo A definem o que deve ser verificado em cada domínio. O BlindSpot implementa verificações técnicas que evidenciam a aderência ou não-aderência a esses controles.

**NIST CSF 2.0** — cada verificação é categorizada por função (Identify, Protect, Detect, Respond, Recover), permitindo identificar em qual capacidade de segurança o ambiente é mais fraco.

**LGPD (Lei 13.709/2018)** — o módulo LGPD verifica controles técnicos relacionados à proteção de dados pessoais, como exposição de arquivos, dados em logs e criptografia.

---

## Decisões de Design

**Por que CLI e não interface web?**
Ferramentas de auditoria de segurança são usadas por analistas e administradores de sistema que vivem no terminal. CLI é mais rápida, mais auditável e mais fácil de integrar em pipelines automatizados. A complexidade de uma interface web não agrega valor para esse público.

**Por que módulos independentes?**
Cada módulo pode ser executado, testado e evoluído de forma isolada. Isso facilita a adição de novos domínios e permite que o analista audite apenas o que precisa sem rodar toda a ferramenta.

**Por que a base normativa em JSON?**
Separar os controles normativos do código permite atualizar a base quando as normas evoluem sem alterar a lógica de verificação. É o princípio de separação de responsabilidades aplicado a GRC.

**Por que Excel e não PDF ou HTML?**
Excel é a língua franca de auditoria. É o formato que gestores abrem, que auditores pedem e que permite edição — o analista pode preencher responsável e prazo diretamente no Plano de Ação.

---

## Contexto

Este projeto foi desenvolvido como parte de uma transição de carreira para GRC e Segurança da Informação. O objetivo foi construir algo que demonstrasse não só conhecimento técnico, mas pensamento de analista, entender o problema antes de escrever código, fundamentar cada decisão em normas reais e entregar um output que tenha valor prático.

O BlindSpot não é um exercício acadêmico. É uma ferramenta que resolve um problema real.

---

## Roadmap

- [x] Arquitetura modular em camadas
- [x] 7 módulos com 39 verificações automatizadas
- [x] Engine de score de maturidade
- [x] Engine de comparação entre execuções
- [x] Interface CLI interativa com menu
- [x] Relatório Excel com 4 abas estruturadas
- [ ] Mapeamento completo para controles ISO 27001 via JSON
- [ ] Suporte a múltiplos perfis de auditoria (mínimo, padrão, completo)
- [ ] Exportação de relatório em PDF
- [ ] Documentação de uso completa

---

## Autor

**Erick Alves** — Analista de GRC | Segurança da Informação

[![LinkedIn](https://img.shields.io/badge/LinkedIn-erick--alves--sec-blue)](https://linkedin.com/in/erick-alves-sec)
[![GitHub](https://img.shields.io/badge/GitHub-erickalves--lab-black)](https://github.com/erickalves-lab)