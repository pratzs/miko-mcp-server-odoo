# -*- coding: utf-8 -*-
"""API keys an MCP client authenticates with.

The key is stored hashed. It is shown once, at creation, and never again, because
a key that can be read back out of the database is a key that leaks with a backup.
"""
import hashlib
import secrets

from odoo import _, api, fields, models
from odoo.exceptions import UserError


def hash_key(raw):
    return hashlib.sha256((raw or '').encode('utf-8')).hexdigest()


class MikoMcpKey(models.Model):
    _name = 'miko.mcp.key'
    _description = 'MCP client key'
    _order = 'create_date desc'

    name = fields.Char(required=True, help="Which assistant or person this is for.")
    active = fields.Boolean(default=True)
    key_hash = fields.Char(string='Key hash', readonly=True, copy=False, index=True)
    key_preview = fields.Char(string='Key', readonly=True, copy=False,
                              help="The first characters, so a key can be told apart "
                                   "from another without storing it.")
    user_id = fields.Many2one(
        'res.users', string='Acts as', required=True,
        default=lambda self: self.env.user,
        help="Every request runs with this user's permissions. Record rules and "
             "access rights still apply on top of the allowlist, so a key can never "
             "reach further than the user behind it.")
    allow_write = fields.Boolean(
        string='May write', default=False,
        help="Master switch. Even a model that allows writing stays read only for "
             "a key with this off.")
    expires_on = fields.Date(string='Expires')
    last_used = fields.Datetime(readonly=True)
    call_count = fields.Integer(readonly=True, default=0)

    def action_generate_key(self):
        """Mint a key and show it exactly once."""
        self.ensure_one()
        raw = 'mcp_' + secrets.token_urlsafe(32)
        self.write({'key_hash': hash_key(raw), 'key_preview': raw[:12] + '...'})
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Copy this key now'),
                'message': _('%s\n\nIt cannot be shown again. If it is lost, '
                             'generate a new one.') % raw,
                'type': 'warning',
                'sticky': True,
            },
        }

    @api.model
    def _authenticate(self, raw_key):
        """Return the key record for a raw key, or None. Never raises."""
        if not raw_key:
            return None
        rec = self.sudo().search([('key_hash', '=', hash_key(raw_key))], limit=1)
        if not rec:
            return None
        if rec.expires_on and rec.expires_on < fields.Date.context_today(rec):
            return None
        return rec

    def _touch(self):
        self.sudo().write({
            'last_used': fields.Datetime.now(),
            'call_count': (self.call_count or 0) + 1,
        })
