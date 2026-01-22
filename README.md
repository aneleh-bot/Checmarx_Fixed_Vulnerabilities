# Fixed Vulnerabilities + Severity ☆彡

Checkmarx One: FIXED Vulnerabilities Report with Severity Enrichment

## Description

This project aims to collect **all vulnerabilities marked as FIXED** in **Checkmarx One Analytics** and attempt to **enrich the technical severity** of each vulnerability whenever possible, using only **public APIs** from the platform.

Due to known limitations of Analytics and runtime APIs, not all FIXED vulnerabilities have retrievable technical severity. Therefore, the script is designed to produce **two clear, auditable, and technically justified datasets**.

---

## Objective

- Extract all FIXED vulnerabilities from Analytics
- Enrich technical severity when possible
- Separate reliable data from purely historical data
- Ensure traceability and technical justification for auditing

---

## Requirements

### Python
- **Python 3.9+** (Python 3.10 or higher recommended)

### Dependencies
Install dependencies with:

```bash
pip install requests python-dateutil
```

## Configuration

At the beginning of the script `export_fixed_with_severity.py`, configure the variables below:

```python
AST_BASE      = "https://eu.ast.checkmarx.net"
IAM_BASE      = "https://eu.iam.checkmarx.net"

TENANT        = "your-tenant"
CLIENT_ID     = "your-client-id"
CLIENT_SECRET = "your-client-secret"
```

> **Important:**  
> Adjust the URLs according to your region (US, US2, EU, EU2) and insert valid OAuth 2.0 credentials for your Checkmarx One tenant.

---

## How It Works

1. Authenticate with Checkmarx IAM via Client Credentials (OAuth2)  
2. Collect FIXED vulnerabilities via Analytics  
3. List projects and scans  
4. Intelligent selection of scans close to `dateFixed`  
5. Attempt enrichment via Results API  
6. Fallback via Rule Severity Map (when applicable)  
7. Classification of results into two CSV files  
8. Generation of a debug JSON file for auditing  

---

## Data Sources

### 1. Analytics – FIXED (Primary Source)

Endpoint used:

```POST /api/data_analytics/drilldown/fixedResults```

**Responsible for:**

- Defining the universe of FIXED vulnerabilities
- Providing historical information:
  - projectName
  - queryName
  - scanner
  - dateFixed
  - state / status

Known limitation:  
This endpoint does not return severity per vulnerability.

---

### 2. Runtime – Results API (Enrichment)

**Endpoints used:**

```GET /api/projects```
```GET /api/scans```
```GET /api/results```

**Strategy:**

- Prioritize scans immediately before `dateFixed`
- Also attempt the scan immediately after the fix
- Use multiple correlation methods:
  - similarityId / ruleId / queryId
  - queryName
  - contains
  - token overlap (especially for IaC / KICS)

**If found:**

- Severity is considered reliable
- Source is marked as `results`

---

### 3. Rule Severity Map (Intelligent Fallback)

When the finding no longer exists in runtime:

- The script builds a severity map by rule
- Uses recent scans from multiple projects

**Key:**

```(scanner, normalized_queryName) → severity```

Applicable for:

- SAST
- IaC / KICS
- **Not** applied to aggregated SCA (Cx...), as it is not reliable.

---

## 4. Generated Files

### 1. `fixed_with_severity.csv`

**FIXED vulnerabilities with reliable technical severity.**

**Additional columns:**
- severity
- severity_source (results or rulemap)
- match_method
- scanId_used

---

### 2. `fixed_analytics_only.csv`

**FIXED vulnerabilities available only as historical data.**

**Characteristics:**

- Technical severity not retrievable via public API
- Common in:
  - Aggregated SCA (Cx...)
  - Findings removed from runtime after fix

**These records do not represent errors.**

---

### 3. `fixed_enrichment_debug.json`

**Complete debug file containing:**
- All FIXED vulnerabilities
- Severity source
- Correlation method used
- Analyzed scan

**Recommended for:**

- Auditing
- Troubleshooting
- Technical validation

---

## Why Don’t All Vulnerabilities Have Severity?

- Severity available → Finding still accessible in some scan
- Severity missing → Finding exists only in Analytics
- Aggregated SCA (Cx...) → Finding removed after fix
- UI shows severity → Internal enrichment not exposed via API

---

## Known Limitations

- Analytics stores historical data in an internal warehouse
- Public APIs do not expose per-line severity for FIXED findings
- Runtime APIs reflect only the current state of scans
- Part of the data displayed in the UI is not retrievable via REST APIs

---

## Technical Justification (Audit)

1. The severity displayed in the Analytics UI is derived from consolidated historical data.
2. The public listing endpoint (`/api/data_analytics/drilldown/fixedResults`) does not return severity per vulnerability.
3. Runtime APIs do not preserve historical findings after fixes, especially for aggregated SCA.
4. Therefore, part of the FIXED vulnerabilities does not have technical severity retrievable via public APIs.

---

## 5. Execution

In the terminal:

```bash
python export_fixed_with_severity.py
```

During execution, the script will display progress logs:

```
[ANALYTICS] page=0 offset=0 got=500 total=500
[INFO] rulemap keys: 572
[PROGRESS] 800/1049 reliable=915 analytics_only=134
```

---

## 6. Code Structure

```
.
├── export_fixed_with_severity.py
├── fixed_with_severity.csv
├── fixed_analytics_only.csv
├── fixed_enrichment_debug.json
└── README.md
```

---

## 7. Status

- Validated solution
- Compatible with SAST, SCA, IaC, and KICS
- Auditable
- Ready for enterprise use

---
☆彡
---

# Vulnerabilidades Fixed + Severidade ☆彡
Checkmarx One: Relatório de Vulnerabilidades FIXED com Enriquecimento de Severidade

## Descrição

Este projeto tem como objetivo coletar **todas as vulnerabilidades marcadas como FIXED** no **Checkmarx One Analytics** e tentar **enriquecer a severidade técnica** de cada vulnerabilidade sempre que possível, utilizando exclusivamente **APIs públicas** da plataforma.

Devido às limitações conhecidas do Analytics e das APIs de runtime, nem todas as vulnerabilidades FIXED possuem severidade técnica recuperável. Por isso, o script foi desenhado para produzir **dois conjuntos de dados claros, auditáveis e tecnicamente justificáveis**.

---

## Objetivo

- Extrair todas as vulnerabilidades FIXED do Analytics
- Enriquecer severidade técnica quando possível
- Separar dados confiáveis de dados puramente históricos
- Garantir rastreabilidade e justificativa técnica para auditoria

---

## Requisitos

### Python
- **Python 3.9+** (recomendado Python 3.10 ou superior)

### Dependências
Instale as dependências necessárias com:

```bash
pip install requests python-dateutil
```

## Configuração

No início do script export_fixed_with_severity.py, configure as variáveis abaixo:

```python

AST_BASE      = "https://eu.ast.checkmarx.net"
IAM_BASE      = "https://eu.iam.checkmarx.net"

TENANT        = "seu-tenant"
CLIENT_ID     = "seu-client-id"
CLIENT_SECRET = "seu-client-secret"
```
> **Importante:**  
> Ajuste as URLs conforme sua região (US, US2, EU, EU2) e insira as credenciais válidas de OAuth 2.0 do seu tenant Checkmarx One.


## Funcionamento

1. Autentica no **IAM** do Checkmarx via Client Credentials (OAuth2).  
2. Coleta de vulnerabilidades FIXED via Analytics
3. Listagem de projetos e scans
4. Seleção inteligente de scans próximos ao dateFixed
5. Tentativa de enriquecimento via Results API
6. Fallback via Rule Severity Map (quando aplicável)
7. Classificação dos resultados em dois CSVs
8. Geração de arquivo JSON de debug para auditoria

---

## Fonte dos Dados

### 1. Analytics – FIXED (Fonte Primária)

Endpoint utilizado:

```POST /api/data_analytics/drilldown/fixedResults```

**Responsável por:**

- Definir o universo de vulnerabilidades FIXED
- Trazer informações históricas:
- projectName
- queryName
- scanner
- dateFixed
- state / status

Limitação conhecida:
Esse endpoint não retorna severidade por vulnerabilidade.

### 2. Runtime – Results API (Enriquecimento)

**Endpoints utilizados:**

```GET /api/projects```
```GET /api/scans```
```GET /api/results```

**Estratégia:**

Prioriza scans imediatamente antes do dateFixed
Também tenta o scan imediatamente após o fix
Utiliza múltiplos métodos de correlação:
- similarityId / ruleId / queryId
- queryName
- contains
- token overlap (especialmente para IaC / KICS)

**Se encontrado:**

- Severidade é considerada confiável
- Origem marcada como results

### 3. Rule Severity Map (Fallback Inteligente)

Quando o finding não existe mais no runtime:

- O script constrói um mapa de severidade por regra
- Usa scans recentes de vários projetos

***Chave:***

```(scanner, queryName_normalizado) → severity```

Aplicável para:

- SAST
- IaC / KICS
- **Não** aplicado para SCA agregado (Cx...), pois não é confiável.

---

## 4. Arquivos Gerados

### 1. ***fixed_with_severity.csv***

**Vulnerabilidades FIXED com severidade técnica confiável.**
**Colunas adicionais:**
- severity
- severity_source (results ou rulemap)
- match_method
- scanId_used

### 2. ***fixed_analytics_only.csv***

**Vulnerabilidades FIXED disponíveis apenas como dados históricos.**

**Características:**

- Severidade técnica não recuperável via API pública
- Comum em:
- SCA agregado (Cx...)
- Findings removidos do runtime após correção

**Esses registros não representam erro.**

### 3.***fixed_enrichment_debug.json***

**Arquivo de debug completo contendo:**
- Todas as vulnerabilidades FIXED
- Fonte da severidade
- Método de correlação utilizado
- Scan analisado

**Recomendado para:**

- Auditoria
- Troubleshooting
- Validação técnica

**Por que nem todas têm severidade?**

Severidade disponível -> Finding ainda acessível em algum scan
Severidade ausente -> Finding existe apenas no Analytics
SCA agregado (Cx...) -> Finding removido após correção
UI mostra severidade -> Enriquecimento interno não exposto por API

**Limitações Conhecidas**

- O Analytics armazena dados históricos em um warehouse interno
- As APIs públicas não expõem severidade por linha para FIXED
- APIs de runtime refletem apenas o estado atual dos scans
- Parte dos dados exibidos na UI não é recuperável via REST

**Justificativa Técnica (Auditoria)**

1. A severidade exibida na UI de Analytics é derivada de dados históricos consolidados.
2. O endpoint público de listagem (/api/data_analytics/drilldown/fixedResults) não retorna severidade por vulnerabilidade.
3. As APIs de runtime não preservam findings históricos após correção, especialmente para SCA agregado.
4. Por esse motivo, parte das vulnerabilidades FIXED não possui severidade técnica recuperável via API pública.

---

## 5. Execução

No terminal:
```bash
export_fixed_with_severity.py
``` 

Durante a execução, o script exibirá logs de progresso:
```
[ANALYTICS] page=0 offset=0 got=500 total=500
[INFO] rulemap keys: 572
[PROGRESS] 800/1049 reliable=915 analytics_only=134
```

## 6. Estrutura do Código
```
.
├── export_fixed_with_severity.py
├── fixed_with_severity.csv
├── fixed_analytics_only.csv
├── fixed_enrichment_debug.json
└── README.md
```


## 7. Status

- Solução validada
- Compatível com SAST, SCA, IaC e KICS
- Auditável
- Pronta para uso corporativo

---
☆彡





