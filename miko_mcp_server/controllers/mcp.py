# -*- coding: utf-8 -*-
"""The MCP endpoint.

Model Context Protocol is JSON-RPC 2.0. This exposes it over HTTP at /mcp so any
MCP capable assistant can be pointed at an Odoo database.

Every request passes three gates before it touches data, in this order:

  1. The key must exist, be active and not expired.
  2. The model must be on the allowlist, and the allowlist entry must permit the
     operation being asked for.
  3. Odoo's own access rights and record rules apply, because the call is made as
     the user the key acts as. The allowlist can only ever NARROW what that user
     could already reach; it can never widen it.

The result is that a key handed to an assistant is strictly less powerful than the
person who created it, which is the property that makes it safe to hand out.
"""
import json
import logging
import time

from odoo import SUPERUSER_ID, _, api, http
from odoo.http import request, Response
from odoo.modules.registry import Registry

_logger = logging.getLogger(__name__)

class McpRefused(Exception):
    """A request the server deliberately declined.

    A dedicated class rather than the builtin PermissionError: that one subclasses
    OSError, and on some Odoo series the framework's own error handling reaches it
    before the controller does, turning a clean refusal into a generic 500.
    """


PROTOCOL_VERSION = '2024-11-05'
SERVER_NAME = 'odoo-miko-mcp'
SERVER_VERSION = '1.0.0'

# Fields never returned, whatever a model's configuration says.
STRUCTURAL_SKIP = {'__last_update'}


def json_response(payload, status=200):
    """Build a JSON response that works on every supported series.

    Odoo's own request.make_json_response() only exists from version 16.
    Constructing the Response directly behaves identically on 14 through 19.
    Relying on the helper meant the endpoint returned an HTML error page instead
    of JSON on the two oldest series, which every client then failed to parse.
    """
    return Response(json.dumps(payload, default=str),
                    status=status,
                    content_type='application/json; charset=utf-8')


def rpc_result(req_id, result):
    return {'jsonrpc': '2.0', 'id': req_id, 'result': result}


def rpc_error(req_id, code, message):
    return {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': code, 'message': message}}


class MikoMcpController(http.Controller):

    # ------------------------------------------------------------------ helpers
    def _key(self):
        auth = request.httprequest.headers.get('Authorization') or ''
        raw = auth[7:].strip() if auth.lower().startswith('bearer ') else None
        if not raw:
            raw = request.httprequest.headers.get('X-MCP-Key')
        return request.env['miko.mcp.key'].sudo()._authenticate(raw)

    def _allowed(self, key, model_name):
        """The allowlist entry for a model, or None."""
        if not model_name:
            return None
        return request.env['miko.mcp.model'].sudo().search(
            [('model_name', '=', model_name), ('active', '=', True)], limit=1)

    def _log(self, key, tool, model_name, args, count, ok, err, started):
        """Write the audit entry in its OWN transaction.

        This is deliberate, not incidental. Written inside the request
        transaction, a refused or failed call rolls the log entry back with it,
        which loses precisely the events an audit exists to capture. A separate
        cursor means the record of what was asked survives whatever happens to
        the answer.
        """
        payload = {
            'key_id': key.id if key else False,
            'user_id': key.user_id.id if key else False,
            'tool': tool,
            'model_name': model_name or False,
            'arguments': json.dumps(args or {}, default=str)[:4000],
            'record_count': count or 0,
            'success': ok,
            'error': (err or '')[:250] or False,
            'duration_ms': int((time.time() - started) * 1000),
        }
        try:
            db_name = request.env.cr.dbname
            with Registry(db_name).cursor() as cr:
                api.Environment(cr, SUPERUSER_ID, {})['miko.mcp.log'].create(payload)
                cr.commit()
        except Exception:            # logging must never break the response
            _logger.exception("miko_mcp: could not write the audit log")

    def _strip(self, entry, rows):
        """Remove redacted and structural fields from every row."""
        drop = entry._redacted_set() | STRUCTURAL_SKIP
        return [{k: v for k, v in row.items() if k not in drop} for row in rows]

    # ------------------------------------------------------------------ tools
    def _tool_definitions(self):
        return [
            {
                'name': 'odoo_list_models',
                'description': 'List the Odoo models this key is allowed to read, '
                               'with what may be done to each.',
                'inputSchema': {'type': 'object', 'properties': {}},
            },
            {
                'name': 'odoo_describe_model',
                'description': 'List the fields of one allowed model, with their '
                               'types, so a correct query can be written.',
                'inputSchema': {
                    'type': 'object',
                    'properties': {'model': {'type': 'string'}},
                    'required': ['model'],
                },
            },
            {
                'name': 'odoo_search',
                'description': 'Search records of an allowed model and return the '
                               'requested fields. Uses standard Odoo domain syntax.',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'model': {'type': 'string'},
                        'domain': {'type': 'array', 'description': "Odoo domain, e.g. [['state','=','sale']]"},
                        'fields': {'type': 'array', 'items': {'type': 'string'}},
                        'limit': {'type': 'integer'},
                        'order': {'type': 'string'},
                    },
                    'required': ['model'],
                },
            },
            {
                'name': 'odoo_count',
                'description': 'Count records matching a domain, without returning them.',
                'inputSchema': {
                    'type': 'object',
                    'properties': {'model': {'type': 'string'}, 'domain': {'type': 'array'}},
                    'required': ['model'],
                },
            },
        ]

    def _call_tool(self, key, name, args):
        """Run one tool. Returns (payload, record_count). Raises on refusal."""
        env = request.env(user=key.user_id.id)
        model_name = (args or {}).get('model')

        if name == 'odoo_list_models':
            entries = request.env['miko.mcp.model'].sudo().search([('active', '=', True)])
            rows = [{
                'model': e.model_name,
                'name': e.model_id.name,
                'can_read': e.allow_read,
                'can_write': bool(e.allow_write and key.allow_write),
                'max_records': e.max_records,
            } for e in entries if e.allow_read]
            return rows, len(rows)

        entry = self._allowed(key, model_name)
        if not entry:
            raise McpRefused(_(
                "The model '%s' is not on this server's allowlist. An Odoo "
                "administrator has to add it before it can be read.") % model_name)
        if not entry.allow_read:
            raise McpRefused(_("Reading '%s' is not permitted.") % model_name)

        if name == 'odoo_describe_model':
            drop = entry._redacted_set()
            fields_info = env[model_name].fields_get()
            rows = [{
                'name': fname,
                'type': meta.get('type'),
                'label': meta.get('string'),
                'relation': meta.get('relation'),
            } for fname, meta in sorted(fields_info.items())
                if fname not in drop and fname not in STRUCTURAL_SKIP]
            return rows, len(rows)

        domain = list(entry._base_domain()) + list((args or {}).get('domain') or [])

        if name == 'odoo_count':
            count = env[model_name].search_count(domain)
            return {'count': count}, count

        if name == 'odoo_search':
            limit = min(int((args or {}).get('limit') or entry.max_records),
                        entry.max_records)
            drop = entry._redacted_set()
            requested = [f for f in ((args or {}).get('fields') or []) if f not in drop]
            rows = env[model_name].search_read(
                domain, requested or None, limit=limit,
                order=(args or {}).get('order') or None)
            rows = self._strip(entry, rows)
            return rows, len(rows)

        raise ValueError(_("Unknown tool '%s'.") % name)

    # ------------------------------------------------------------------ endpoint
    @http.route('/mcp', type='http', auth='none', methods=['POST'], csrf=False,
                save_session=False)
    def mcp(self, **kw):
        started = time.time()
        try:
            body = json.loads(request.httprequest.get_data(as_text=True) or '{}')
        except Exception:
            return json_response(
                rpc_error(None, -32700, 'Parse error'), status=400)

        req_id = body.get('id')
        method = body.get('method')
        params = body.get('params') or {}

        key = self._key()
        if not key:
            self._log(None, method or '?', None, params, 0, False, 'unauthorised', started)
            return json_response(
                rpc_error(req_id, -32001,
                          'Unauthorised. Send a valid key as "Authorization: Bearer <key>".'),
                status=401)

        try:
            if method == 'initialize':
                key._touch()
                result = {
                    'protocolVersion': PROTOCOL_VERSION,
                    'capabilities': {'tools': {}},
                    'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION},
                }
                self._log(key, 'initialize', None, {}, 0, True, None, started)
                return json_response(rpc_result(req_id, result))

            if method in ('notifications/initialized', 'ping'):
                return json_response(rpc_result(req_id, {}))

            if method == 'tools/list':
                self._log(key, 'tools/list', None, {}, 0, True, None, started)
                return json_response(
                    rpc_result(req_id, {'tools': self._tool_definitions()}))

            if method == 'tools/call':
                name = params.get('name')
                args = params.get('arguments') or {}
                key._touch()
                payload, count = self._call_tool(key, name, args)
                self._log(key, name, args.get('model'), args, count, True, None, started)
                return json_response(rpc_result(req_id, {
                    'content': [{'type': 'text',
                                 'text': json.dumps(payload, default=str, indent=2)}],
                    'isError': False,
                }))

            self._log(key, method or '?', None, params, 0, False, 'unknown method', started)
            return json_response(
                rpc_error(req_id, -32601, "Unknown method '%s'." % method))

        except McpRefused as err:
            self._log(key, method, params.get('arguments', {}).get('model')
                      if isinstance(params.get('arguments'), dict) else None,
                      params, 0, False, str(err), started)
            return json_response(rpc_error(req_id, -32002, str(err)))
        except Exception as err:            # never leak a traceback to the client
            _logger.exception("miko_mcp: tool call failed")
            self._log(key, method, None, params, 0, False, str(err), started)
            return json_response(
                rpc_error(req_id, -32000, 'The request could not be completed.'))
