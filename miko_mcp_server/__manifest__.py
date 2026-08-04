# -*- coding: utf-8 -*-
{
    'name': 'MCP Server for AI: Claude, ChatGPT, Copilot (Miko)',
    'version': '16.0.1.0.0',
    'summary': 'Let an AI assistant query your Odoo safely, with an allowlist and an audit trail',
    'description': """
Connects Claude, ChatGPT, Copilot or any Model Context Protocol client to this
Odoo database.

Built to be approved rather than merely installed. Nothing is exposed until you
say so: no model is readable by default, writing is off unless you turn it on per
model, named fields can be redacted so salaries and bank details never leave, and
every single question the assistant asks is written to an audit log with the key
that asked it.
""",
    'author': 'Tripster Developers',
    'website': 'https://tripsterdevelopers.com/odoo/',
    'category': 'Productivity',
    'license': 'LGPL-3',
    'depends': ['base'],
    'data': [
        'security/mcp_security.xml',
        'security/ir.model.access.csv',
        'views/miko_mcp_views.xml',
    ],
    'images': ['images/banner.gif', 'images/banner.png'],
    'application': True,
    'installable': True,
    'support': 'support@tripsterdevelopers.com',
}
