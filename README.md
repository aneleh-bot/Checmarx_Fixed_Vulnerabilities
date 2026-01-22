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





