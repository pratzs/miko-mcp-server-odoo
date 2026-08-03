# -*- coding: utf-8 -*-
"""Every question the assistant asked, and what came back.

This is the feature that gets the module approved. Without it, "we connected an AI
to the ERP" is an unanswerable question at audit time.
"""
from odoo import fields, models


class MikoMcpLog(models.Model):
    _name = 'miko.mcp.log'
    _description = 'MCP request log'
    _order = 'create_date desc'
    _rec_name = 'tool'

    key_id = fields.Many2one('miko.mcp.key', string='Key', ondelete='set null', index=True)
    user_id = fields.Many2one('res.users', string='Acted as', index=True)
    tool = fields.Char(index=True)
    model_name = fields.Char(string='Model', index=True)
    arguments = fields.Text(help="Exactly what was asked, as received.")
    record_count = fields.Integer(string='Rows returned')
    success = fields.Boolean(default=True, index=True)
    error = fields.Char()
    duration_ms = fields.Integer(string='Took (ms)')
