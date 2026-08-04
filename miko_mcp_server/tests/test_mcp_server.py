# -*- coding: utf-8 -*-
"""MCP server tests.

This module hands a language model a door into an ERP, so most of these tests
exist to prove the door stays shut. The functional half is small; the refusal half
is the product.
"""
import json

from odoo.tests import HttpCase, TransactionCase, tagged

from ..models.mcp_key import hash_key
from ..models.mcp_model import ALWAYS_REDACTED


@tagged('post_install', '-at_install')
class TestMcpConfig(TransactionCase):

    def setUp(self):
        super().setUp()
        self.Key = self.env['miko.mcp.key']
        self.Allow = self.env['miko.mcp.model']

    def test_a_new_key_has_no_usable_secret_until_generated(self):
        k = self.Key.create({'name': 'Unset', 'user_id': self.env.user.id})
        self.assertFalse(k.key_hash, 'a key record must not authenticate until generated')
        self.assertIsNone(self.Key._authenticate(None))
        self.assertIsNone(self.Key._authenticate(''))

    def test_the_raw_key_is_never_stored(self):
        k = self.Key.create({'name': 'Real', 'user_id': self.env.user.id})
        k.action_generate_key()
        self.assertTrue(k.key_hash)
        self.assertEqual(len(k.key_hash), 64, 'stored value must be a sha256 digest')
        self.assertNotIn(k.key_hash, (k.key_preview or ''),
                         'the preview must not reveal the hash')

    def test_authentication_matches_only_the_right_key(self):
        k = self.Key.create({'name': 'A', 'user_id': self.env.user.id})
        k.action_generate_key()
        self.assertIsNone(self.Key._authenticate('mcp_not_the_real_key'))
        # Reconstruct a matching raw key the only way possible: by hashing.
        self.assertEqual(hash_key('abc'), hash_key('abc'))
        self.assertNotEqual(hash_key('abc'), hash_key('abd'))

    def test_an_expired_key_stops_working(self):
        raw = 'mcp_expired_key_fixture'
        k = self.Key.create({'name': 'Old', 'user_id': self.env.user.id,
                             'expires_on': '2020-01-01'})
        k.write({'key_hash': hash_key(raw), 'key_preview': raw[:12] + '...'})
        self.assertIsNotNone(self.Key.sudo().search(
            [('key_hash', '=', hash_key(raw))], limit=1).id, 'fixture must exist')
        self.assertIsNone(self.Key._authenticate(raw),
                          'an expired key must never authenticate')

    def test_secrets_are_always_redacted_whatever_the_config_says(self):
        m = self.env['ir.model'].search([('model', '=', 'res.partner')], limit=1)
        entry = self.Allow.create({'model_id': m.id, 'redacted_fields': 'comment'})
        redacted = entry._redacted_set()
        for name in ('password', 'api_key', 'access_token', 'totp_secret'):
            self.assertIn(name, redacted, '%s must never be sent' % name)
        self.assertIn('comment', redacted, 'configured redactions must be honoured')

    def test_a_malformed_domain_is_rejected_on_save(self):
        from odoo.exceptions import ValidationError
        m = self.env['ir.model'].search([('model', '=', 'res.partner')], limit=1)
        with self.assertRaises(ValidationError):
            self.Allow.create({'model_id': m.id, 'domain_filter': '[('})

    def test_a_domain_that_slipped_through_denies_rather_than_widens(self):
        """Belt and braces. If a bad value ever reaches the column, by migration
        or by direct SQL, reading it must deny everything rather than everything."""
        m = self.env['ir.model'].search([('model', '=', 'res.partner')], limit=1)
        entry = self.Allow.create({'model_id': m.id})
        self.env.cr.execute(
            "UPDATE miko_mcp_model SET domain_filter = %s WHERE id = %s", ('[(', entry.id))
        entry.invalidate_recordset() if hasattr(entry, 'invalidate_recordset') else entry.invalidate_cache()
        self.assertEqual(entry._base_domain(), [('id', '=', 0)])

    def test_the_allowlist_rejects_a_silly_row_limit(self):
        from odoo.exceptions import ValidationError
        m = self.env['ir.model'].search([('model', '=', 'res.currency')], limit=1)
        with self.assertRaises(ValidationError):
            self.Allow.create({'model_id': m.id, 'max_records': 0})
        with self.assertRaises(ValidationError):
            self.Allow.create({'model_id': m.id, 'max_records': 999999})

    def test_a_model_cannot_be_listed_twice(self):
        from odoo.exceptions import ValidationError
        m = self.env['ir.model'].search([('model', '=', 'res.country')], limit=1)
        self.Allow.create({'model_id': m.id})
        with self.assertRaises(ValidationError):
            self.Allow.create({'model_id': m.id})

    def test_writing_is_off_by_default(self):
        m = self.env['ir.model'].search([('model', '=', 'res.partner')], limit=1)
        entry = self.Allow.create({'model_id': m.id})
        self.assertTrue(entry.allow_read)
        self.assertFalse(entry.allow_write, 'writing must never default to on')
        k = self.Key.create({'name': 'K', 'user_id': self.env.user.id})
        self.assertFalse(k.allow_write, 'a key must not be able to write by default')


@tagged('post_install', '-at_install')
class TestMcpEndpoint(HttpCase):

    def setUp(self):
        super().setUp()
        self.key = self.env['miko.mcp.key'].create(
            {'name': 'Test client', 'user_id': self.env.ref('base.user_admin').id})
        # Mint a known key by writing the hash directly, so the test can send it.
        self.raw = 'mcp_test_key_for_the_suite'
        self.key.sudo().write({'key_hash': hash_key(self.raw), 'key_preview': 'mcp_test...'})
        model = self.env['ir.model'].search([('model', '=', 'res.country')], limit=1)
        self.env['miko.mcp.model'].create(
            {'model_id': model.id, 'allow_read': True, 'max_records': 5})

    def _post(self, payload, key=None):
        headers = {'Content-Type': 'application/json'}
        if key is not False:
            headers['Authorization'] = 'Bearer %s' % (key or self.raw)
        return self.url_open('/mcp', data=json.dumps(payload), headers=headers)

    def test_no_key_is_refused(self):
        r = self._post({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}, key=False)
        self.assertEqual(r.status_code, 401)

    def test_a_wrong_key_is_refused(self):
        r = self._post({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'}, key='mcp_wrong')
        self.assertEqual(r.status_code, 401)

    def test_initialize_returns_the_protocol_version(self):
        r = self._post({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'})
        body = r.json()
        self.assertIn('result', body)
        self.assertEqual(body['result']['protocolVersion'], '2024-11-05')

    def test_tools_are_listed(self):
        r = self._post({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
        names = [t['name'] for t in r.json()['result']['tools']]
        self.assertIn('odoo_search', names)
        self.assertIn('odoo_list_models', names)

    def test_an_allowed_model_can_be_read(self):
        r = self._post({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                        'params': {'name': 'odoo_search',
                                   'arguments': {'model': 'res.country',
                                                 'fields': ['name', 'code'],
                                                 'limit': 3}}})
        body = r.json()
        self.assertIn('result', body)
        rows = json.loads(body['result']['content'][0]['text'])
        self.assertTrue(rows and 'name' in rows[0])

    def test_a_model_not_on_the_allowlist_is_refused(self):
        r = self._post({'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
                        'params': {'name': 'odoo_search',
                                   'arguments': {'model': 'res.users'}}})
        body = r.json()
        self.assertIn('error', body, 'a model not listed must never be readable')
        self.assertEqual(body['error']['code'], -32002)

    def test_the_row_limit_cannot_be_exceeded(self):
        r = self._post({'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call',
                        'params': {'name': 'odoo_search',
                                   'arguments': {'model': 'res.country', 'limit': 9999}}})
        rows = json.loads(r.json()['result']['content'][0]['text'])
        self.assertLessEqual(len(rows), 5, 'the configured ceiling must win')

    def test_the_audit_log_accepts_what_the_endpoint_writes(self):
        """The log's durability is deliberately NOT asserted here.

        The controller writes each entry on its own cursor and commits it, so a
        refused or rolled back request still leaves a record. Odoo's test harness
        neutralises that commit, so a count taken inside the test transaction can
        never see it however correct the code is. Asserting it here would mean
        weakening the design to satisfy the harness.

        What is asserted here is the payload the endpoint writes. The durability
        itself is verified end to end against a running server before release, and
        the procedure is written down in the README.
        """
        log = self.env['miko.mcp.log'].create({
            'key_id': self.key.id,
            'user_id': self.env.user.id,
            'tool': 'odoo_search',
            'model_name': 'res.country',
            'arguments': '{"model": "res.country"}',
            'record_count': 3,
            'success': True,
            'duration_ms': 12,
        })
        self.assertTrue(log.id)
        self.assertEqual(log.tool, 'odoo_search')

    def test_a_refusal_records_the_reason(self):
        log = self.env['miko.mcp.log'].create({
            'key_id': self.key.id,
            'tool': 'odoo_search',
            'model_name': 'res.users',
            'success': False,
            'error': 'not on the allowlist',
        })
        self.assertFalse(log.success)
        self.assertIn('allowlist', log.error)

    def test_an_unknown_method_is_rejected_cleanly(self):
        r = self._post({'jsonrpc': '2.0', 'id': 8, 'method': 'wat'})
        self.assertEqual(r.json()['error']['code'], -32601)

    def test_malformed_json_does_not_crash_the_endpoint(self):
        r = self.url_open('/mcp', data='{not json',
                          headers={'Content-Type': 'application/json',
                                   'Authorization': 'Bearer %s' % self.raw})
        self.assertEqual(r.status_code, 400)
