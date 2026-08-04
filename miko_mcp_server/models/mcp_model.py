# -*- coding: utf-8 -*-
"""Which models an AI assistant may see, and what it may do with them.

The default is nothing. An empty allowlist means the assistant can list no models,
read no records and write nothing at all. That is deliberate: an MCP server that
exposes the whole database the moment it is installed is one nobody senior can
approve, and approval is the actual barrier to this being used at work.
"""
from odoo import _, api, fields, models
from odoo.exceptions import ValidationError

# Fields never sent to an assistant, whatever the configuration says. These are
# not a convenience; they are the ones that cause real harm when they leak.
ALWAYS_REDACTED = {
    'password', 'password_crypt', 'new_password', 'api_key', 'access_token',
    'refresh_token', 'secret', 'private_key', 'signature', 'totp_secret',
    'oauth_access_token', 'webhook_secret',
}


class MikoMcpModel(models.Model):
    _name = 'miko.mcp.model'
    _description = 'Model exposed to MCP clients'
    _rec_name = 'model_id'
    _order = 'model_name'

    model_id = fields.Many2one('ir.model', string='Model', required=True,
                               ondelete='cascade')
    model_name = fields.Char(related='model_id.model', store=True, index=True)
    active = fields.Boolean(default=True)

    allow_read = fields.Boolean(
        string='Allow reading', default=True,
        help="The assistant may search and read records of this model.")
    allow_write = fields.Boolean(
        string='Allow writing', default=False,
        help="The assistant may create and update records. Off by default, and it "
             "should stay off unless there is a specific reason.")

    redacted_fields = fields.Char(
        string='Never send these fields',
        help="Comma separated field names that are stripped from every response, "
             "such as a salary or a bank account. Secrets and passwords are always "
             "stripped whatever is written here.")
    domain_filter = fields.Char(
        string='Restrict to', default='[]',
        help="An optional Odoo domain the assistant can never see past, for example "
             "only this year's records, or only one company.")
    max_records = fields.Integer(
        string='Maximum rows per call', default=200,
        help="A ceiling on how much can be pulled in one question.")

    # A Python constraint rather than a SQL one: Odoo 19 replaced the
    # _sql_constraints list with models.Constraint, so a SQL declaration written
    # once is silently not created on one series or the other. This behaves
    # identically on 14 through 19.
    @api.constrains('model_id')
    def _check_model_unique(self):
        for rec in self:
            if not rec.model_id:
                continue
            clash = self.search([('model_id', '=', rec.model_id.id),
                                 ('id', '!=', rec.id)], limit=1)
            if clash:
                raise ValidationError(_(
                    "%s is already on the allowlist. Edit the existing entry "
                    "instead of adding a second one.") % rec.model_id.model)

    @api.constrains('max_records')
    def _check_max_records(self):
        for rec in self:
            if rec.max_records < 1 or rec.max_records > 5000:
                raise ValidationError(_(
                    "Maximum rows per call must be between 1 and 5000."))

    @api.constrains('domain_filter')
    def _check_domain(self):
        import ast
        for rec in self:
            if not rec.domain_filter:
                continue
            try:
                parsed = ast.literal_eval(rec.domain_filter)
            except Exception:
                raise ValidationError(_("Restrict to must be a valid Odoo domain."))
            if not isinstance(parsed, list):
                raise ValidationError(_("Restrict to must be a list."))

    def _redacted_set(self):
        """Field names to strip, always including the built in secrets."""
        self.ensure_one()
        extra = {f.strip() for f in (self.redacted_fields or '').split(',') if f.strip()}
        return ALWAYS_REDACTED | extra

    def _base_domain(self):
        import ast
        self.ensure_one()
        try:
            return ast.literal_eval(self.domain_filter or '[]') or []
        except Exception:
            # A malformed domain must never widen access. Deny instead.
            return [('id', '=', 0)]
