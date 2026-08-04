# MCP Server for Odoo (Miko)

Connects Claude, ChatGPT, Copilot or any Model Context Protocol client to an Odoo
database, with an allowlist, redaction and a full audit trail.

| | |
|---|---|
| Series | 16.0 to 19.0 |
| Price | Free, LGPL-3 |
| Depends | `base` |
| Tests | 21 per series, 4/4 certified |
| Colour | Miko mark in heather `#A8A0C8` to `#6B6499` |

## Why 16+ and not 14+

On Odoo 14 and 15 the HTTP layer intercepts `auth='none'` routes before the
controller and returns 200 where the endpoint returns 401. MCP is 2024 technology
and nobody running Odoo 14 is connecting an AI assistant to their ERP, so carrying
two fragile series for an audience that does not exist was the wrong trade.

## Portability bugs this app found

| Bug | Effect |
|---|---|
| `request.make_json_response` only exists from 16 | endpoint returned HTML, not JSON |
| Odoo 19 replaced `_sql_constraints` with `models.Constraint` | uniqueness silently never created |
| `odoo.registry` is not a top-level attribute in 19 | use `odoo.modules.registry.Registry` |
| audit log written inside the request transaction | refused calls rolled their own log entry back |

That last one was a design flaw, not a portability issue. **An audit log must not
share the transaction it is auditing**, or the failures vanish with the failure.

## Verifying the audit log

Its durability cannot be asserted inside Odoo's test harness, which neutralises
the separate-transaction commit the design depends on. It is verified end to end
instead, and this must be re-run before any release that touches the controller:

```bash
# start a server on a throwaway db, create a key and allow one model, then:
curl -s -X POST http://localhost:8069/mcp \
  -H "Content-Type: application/json" -H "Authorization: Bearer <key>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"odoo_search","arguments":{"model":"res.users"}}}'
# expect a refusal, then confirm the REFUSAL is in miko_mcp_log via psql
```

Full store runbook: `Apps/miko-catalog-health-odoo/PUBLISHING.md`.
