# fluentd-modsecurity (Envoy + Coraza)

Plugin de output (filtro) do [Fluentd](https://www.fluentd.org/) para ler o **audit log do [OWASP Coraza](https://coraza.io/)** rodando no **[Envoy Gateway](https://gateway.envoyproxy.io/)** (módulo dinâmico `coraza-waf` do [Built On Envoy](https://builtonenvoy.io/extensions/coraza-waf/)).

O plugin transforma cada evento do audit log (formato `Native`) em um registro estruturado, um registro por regra disparada, pronto para enviar ao Elasticsearch.

> Fork do plugin usado com o ModSecurity no ingress-nginx. Também continua lendo o formato do libmodsecurity3 (nginx).

## Fluxo

```
Envoy (Coraza) ──► /var/log/coraza/audit.log  (SecAuditLogFormat Native)
                       │  emptyDir compartilhado no pod Envoy
                       └─► sidecar fluentd ─► modsecurity-audit-format ─► geoip ─► Elasticsearch
```

## Diferenças em relação ao ModSecurity (nginx)

| Item | ModSecurity (libmodsecurity3) | Coraza | Tratamento no plugin |
|---|---|---|---|
| Separador do evento | `---a1b2c3d4---A--` (ID de 8) | `--ZXcsyrDxmwXuIxGl-A--` (ID de 16) | Aceita ID de 8 a 16 caracteres |
| Seção B (headers) | Headers normais | Inclui pseudo-headers HTTP/2 (`:path`, `:authority`) | Ignora linhas que começam com `:` |
| Seção F (resposta) | Status + headers | `HTTP/1.1 0`, sem headers (modo `REQUEST_ONLY`) | Aceita seção sem headers |
| Seção H (regras) | Linhas com `ModSecurity:` | Linhas com `Coraza:` | Aceita os dois |
| Seção K (regras) | `,id:942100` | `"id:942100` | Aceita os dois |

### Diferenças que permanecem nos dados

| Campo | ModSecurity | Coraza |
|---|---|---|
| `responseStatus` | `403`, `200`... | `0` (o módulo não processa a resposta no modo `REQUEST_ONLY`) |
| `modsec_timestamp` | `06/Nov/2026:19:12:58 +0000` | `2026/11/06 19:12:58` |
| `destIp` / `destPort` | IP do pod | `127.0.0.1` / `80` |
| `violation.severity` | número (`2`) | texto (`critical`) |

## Pré-requisitos

### Diretivas do Coraza (EnvoyExtensionPolicy)

```yaml
directives:
  - Include @coraza.conf
  - SecRuleEngine DetectionOnly
  - SecAuditEngine RelevantOnly
  - SecAuditLogParts ABDEFHIJKZ
  - SecAuditLogFormat Native
  - SecAuditLog /var/log/coraza/audit.log
  - Include @crs-setup.conf
  - Include @owasp_crs/*.conf
```

O caminho `/var/log/coraza` precisa ser um volume (`emptyDir`) montado no container `envoy` e no sidecar `fluentd`.

## Build

Gerar a gem:
```
gem build fluent-plugin-modsecurity.gemspec
```

Instalar no fluentd:
```
fluent-gem install ./fluent-plugin-modsecurity-*.gem
```

Imagem Docker (inclui `fluent-plugin-elasticsearch` e `fluent-plugin-geoip`):
```
docker build -t pedrobernardes/fluentd-modsecurity:<tag> .
```

## Exemplo de fluent.conf

```
# (1) Leitura do audit log do Coraza
<source>
  @type tail
  tag raw-modsec
  path /var/log/coraza/audit.log
  <parse>
    @type multiline
    format_firstline /^-{2,3}[a-zA-Z0-9]{8,16}-{1,3}A--$/
    format1 /(?<message>.*)/
  </parse>
</source>

# (2) Estrutura o evento (1 registro por regra disparada)
<match raw-modsec>
  @type modsecurity-audit-format
  tag modsec-formatted
</match>

# (3) Saída
<match modsec-formatted>
  @type stdout
</match>
```

## Exemplo de registro gerado

```json
{
  "sourceIp": "181.233.129.27",
  "httpMethod": "GET",
  "requestedUrl": "/?id=1'+OR+'1'%3D'1",
  "requestHeaders": { "host": "app.exemplo.com.br", "user-agent": "curl/8.10.1" },
  "responseStatus": "0",
  "secRuleIds": ["942100", "949110"],
  "violation": {
    "id": "942100",
    "msg": "SQL Injection Attack Detected via libinjection",
    "severity": "critical",
    "ver": "OWASP_CRS/4.25.0",
    "file": "@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
  },
  "tags": ["attack-sqli", "paranoia-level/1", "OWASP_CRS"]
}
```

## Referências

* Plugin original: https://github.com/bitsofinfo/fluentd-modsecurity
* Formato de audit log do ModSecurity: https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats
* Coraza WAF (Built On Envoy): https://builtonenvoy.io/extensions/coraza-waf/
* Envoy Gateway - Dynamic Modules: https://gateway.envoyproxy.io/latest/tasks/extensibility/dynamic-modules/

## Licença

Apache 2.0 - veja o arquivo [LICENSE](LICENSE).
