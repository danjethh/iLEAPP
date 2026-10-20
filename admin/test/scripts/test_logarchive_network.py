"""Network connection and NetworkExtension session artifacts, through the real logarchive chain.

The two artifacts read the logarchive table the producer imports, so the main test runs the real
ileapp.py on a synthetic 'log show' export (synthetic_network.py) and reads what each stage wrote.
Everything in the export is invented: example domains, documentation addresses, made-up tags.
The chain runs the dependent artifacts once logarchive_artifacts has written its table, so the export
holds one line an existing marker collects.
The unit tests cover the aggregation itself (counts, first and last time, link and interface,
bundle ids, malformed lines) without the chain.
"""
import inspect
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import synthetic_network as synthetic  # pylint: disable=wrong-import-position
from scripts.artifacts import logarchive  # pylint: disable=wrong-import-position

PROFILE = {'leapp': 'ileapp', 'format_version': 1,
           'plugins': ['logarchive', 'logarchive_network_connections', 'logarchive_network_sessions']}
BASE_EPOCH = datetime(2026, 3, 14, 15, 0, 0, tzinfo=timezone.utc).timestamp()  # 10:00:00 at -0500
MAILD, BROWSER, SESSIOND = synthetic.MAILD, synthetic.BROWSER, synthetic.SESSIOND
TAG = synthetic.HOST_TAG
SESSION = synthetic.SESSION

CONNECTION_COLUMNS = ('CAST(records AS INTEGER), process_image_path, endpoint_as_logged, port_as_logged, endpoint_form, '
                      'link_as_logged, interface_as_logged, states_seen_as_logged, bundle_ids_as_logged')


def _epoch(seconds):
    return BASE_EPOCH + seconds


class ChainTest(unittest.TestCase):
    """ileapp.py on the fixture: the producer, then the two artifacts."""

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        root = pathlib.Path(cls.folder.name)
        extraction = root / 'extraction'
        extraction.mkdir()
        (extraction / synthetic.FIXTURE_NAME).write_bytes(synthetic.to_bytes())
        profile = root / 'network.ilprofile'
        profile.write_text(json.dumps(PROFILE), encoding='utf-8')
        output = root / 'out'
        output.mkdir()
        environment = dict(os.environ, TZ='UTC')
        completed = subprocess.run(
            [sys.executable, str(REPO_ROOT / 'ileapp.py'), '-t', 'fs', '-i', str(extraction),
             '-o', str(output), '-m', str(profile)],
            capture_output=True, text=True, check=False, env=environment, cwd=REPO_ROOT, timeout=600)
        cls.log = completed.stdout + completed.stderr
        cls.returncode = completed.returncode
        reports = sorted(output.glob('iLEAPP_Output_*'))
        cls.report = reports[-1] if reports else None
        cls.db = None
        if cls.report is not None and (cls.report / '_lava_artifacts.db').exists():
            cls.db = sqlite3.connect(f'file:{cls.report / "_lava_artifacts.db"}?mode=ro', uri=True)

    @classmethod
    def tearDownClass(cls):
        if cls.db is not None:
            cls.db.close()
        cls.folder.cleanup()

    def connection_rows(self):
        return self.db.execute(
            f'SELECT first_seen, last_seen, {CONNECTION_COLUMNS} FROM logarchive_network_connections').fetchall()

    def connection_row(self, process, endpoint, port, link='', interface=''):
        rows = [row for row in self.connection_rows()
                if (row[3], row[4], row[5], row[7], row[8]) == (process, endpoint, port, link, interface)]
        self.assertEqual(len(rows), 1, (process, endpoint, port, link, interface))
        return rows[0]

    def test_the_run_completed_and_produced_the_database(self):
        self.assertEqual(self.returncode, 0, self.log[-2000:])
        self.assertIsNotNone(self.db, self.log[-2000:])
        self.assertIn('Report generation Completed.', self.log)

    def test_the_producer_imported_every_record(self):
        numbers = sorted(int(row[0]) for row in self.db.execute('SELECT row_number FROM logarchive'))
        self.assertEqual(numbers, list(range(1, len(synthetic.build_lines()) + 1)))

    def test_the_where_clauses_select_exactly_the_intended_lines(self):
        # A change that broadens or narrows either predicate fails here, with the decoys in the table.
        for where, kind in ((logarchive.NETWORK_CONNECTION_WHERE, 'conn'),
                            (logarchive.NETWORK_SESSION_WHERE, 'session')):
            with self.subTest(kind=kind):
                selected = sorted(int(row[0]) for row in self.db.execute(
                    f'SELECT row_number FROM logarchive WHERE {where}'))
                self.assertEqual(selected, synthetic.lines_of(kind))

    def test_every_connection_line_is_counted_once(self):
        total = sum(row[2] for row in self.connection_rows())
        self.assertEqual(total, len(synthetic.lines_of('conn')))
        self.assertEqual(total, 30)
        self.assertIn('logarchive network connections: 30 lines read', self.log)

    def test_one_row_per_process_endpoint_port_link_and_interface(self):
        rows = self.connection_rows()
        self.assertEqual(len(rows), 15)
        keys = [(row[3], row[4], row[5], row[7], row[8]) for row in rows]
        self.assertEqual(len(set(keys)), len(keys))
        # The same tag over three links is three rows; the same tag in two processes is two sets of rows.
        mail = [key for key in keys if key[0] == MAILD and key[1] == TAG]
        self.assertEqual(sorted((key[3], key[4]) for key in mail),
                         [('', ''), ('cell', 'pdp_ip0'), ('cell', 'utun4'), ('wifi', 'en0')])
        self.assertEqual([key for key in keys if key[0] == SESSIOND and key[1] == TAG],
                         [(SESSIOND, TAG, '443', '', '')])

    def test_counts_first_and_last_seen_states_and_bundles(self):
        row = self.connection_row(MAILD, TAG, '443')
        # Seven lines; the earliest was written last in the file, so First Seen is a minimum.
        self.assertEqual(row[2], 7)
        self.assertAlmostEqual(row[0], _epoch(5.0), places=3)
        self.assertAlmostEqual(row[1], _epoch(12.0), places=3)
        self.assertEqual(row[6], 'Host tag')
        self.assertEqual(set(row[9].split('; ')),
                         {'initial', 'in_progress', 'waiting', 'start', 'cancelled',
                          'is already cancelled, ignoring cancel'})
        self.assertEqual(row[10], 'com.example.mail, com.example.mail.shared')

    def test_link_and_interface_are_read_from_the_line(self):
        cell = self.connection_row(MAILD, TAG, '443', 'cell', 'utun4')
        self.assertEqual((cell[2], cell[9]), (1, 'ready'))
        self.assertAlmostEqual(cell[0], _epoch(20.0), places=3)
        self.assertEqual(self.connection_row(MAILD, TAG, '443', 'cell', 'pdp_ip0')[2], 1)
        self.assertEqual(self.connection_row(MAILD, TAG, '443', 'wifi', 'en0')[2], 1)
        wifi = self.connection_row(BROWSER, 'www.example.com', '443', 'wifi', 'en0')
        self.assertEqual(wifi[2], 2)
        self.assertAlmostEqual(wifi[0], _epoch(41.0), places=3)
        self.assertAlmostEqual(wifi[1], _epoch(41.5), places=3)

    def test_endpoint_forms(self):
        expected = {
            (BROWSER, 'www.example.com', '443', '', ''): 'Host name',
            (BROWSER, 'cdn.example.org', '8443', '', ''): 'Host name',
            (BROWSER, '192.0.2.10', '443', '', ''): 'IPv4 address',
            (BROWSER, '2001:db8::7', '443', 'wifi', 'en0'): 'IPv6 address',
            (BROWSER, 'IPv4#5ca1ab1e', '443', '', ''): 'IPv4 tag',
            (BROWSER, 'IPv6#cafef00d', '443', '', ''): 'IPv6 tag',
            (BROWSER, 'Hostname#feedface', '443', 'cell', 'pdp_ip0'): 'Host tag',
        }
        for key, form in expected.items():
            with self.subTest(key=key):
                self.assertEqual(self.connection_row(*key)[6], form)
        # A flag word before the endpoint does not hide it, and the child endpoint named after the
        # header is not taken for the endpoint.
        dry = self.connection_row(BROWSER, 'Hostname#feedface', '443', 'cell', 'pdp_ip0')
        self.assertEqual((dry[2], dry[9]), (1, 'in_progress'))

    def test_lines_without_an_endpoint_are_counted_under_their_process(self):
        none = {row[3]: row for row in self.connection_rows() if row[6] == 'No endpoint in line'}
        self.assertEqual(sorted(none), sorted([MAILD, BROWSER]))
        self.assertEqual(none[MAILD][2], 3)
        # A truncated header, an endpoint token that is not one, a tag with no port, an empty message
        # and a state-only line.
        self.assertEqual(none[BROWSER][2], 5)
        for row in none.values():
            self.assertEqual((row[4], row[5], row[7], row[8], row[10]), ('', '', '', '', ''))

    def test_bundle_ids_are_listed_sorted(self):
        row = self.connection_row(SESSIOND, TAG, '443')
        self.assertEqual((row[2], row[10]), (3, 'com.example.alpha, com.example.zeta'))
        self.assertEqual(set(row[9].split('; ')), {'start', 'cancel'})

    def test_session_events_are_one_row_per_process_and_template(self):
        rows = self.db.execute(
            'SELECT first_seen, last_seen, CAST(records AS INTEGER), process_image_path, event_template, '
            'first_message_as_logged, last_message_as_logged FROM logarchive_network_sessions').fetchall()
        self.assertEqual(sum(row[2] for row in rows), 9)
        self.assertEqual(sum(row[2] for row in rows), len(synthetic.lines_of('session')))
        self.assertEqual(len(rows), 6)
        self.assertEqual({row[3] for row in rows}, {synthetic.SESSION_MANAGER})
        by_template = {row[4]: row for row in rows}
        start = by_template[f'{SESSION}: Received a start command from fakemaild[<n>]']
        self.assertEqual(start[2], 3)
        self.assertAlmostEqual(start[0], _epoch(98.0), places=3)
        self.assertAlmostEqual(start[1], _epoch(101.0), places=3)
        # The earliest and latest messages by time, as logged, though the earliest was written last.
        self.assertEqual(start[5], f'{SESSION}: Received a start command from fakemaild[320]')
        self.assertEqual(start[6], f'{SESSION}: Received a start command from fakemaild[322]')
        tearing = by_template['Tearing down utun4']
        self.assertEqual(tearing[2], 2)
        self.assertEqual(by_template[
            f'<NESMServer: <hex>>: Register Enterprise VPN Session: {SESSION}'][5],
            f'<NESMServer: 0x7f0c44001200>: Register Enterprise VPN Session: {SESSION}')
        self.assertIn(f'{SESSION}: Entering state NESMVPNSessionStateStopping, timeout <n> seconds', by_template)

    def test_the_collection_stage_is_not_widened_for_these_lines(self):
        # These artifacts read the producer's table. A marker for the connection lines in
        # logarchive_artifacts would copy over a million rows on a large image; here that table holds
        # only the one line an existing marker collects.
        collected = [int(row[0]) for row in self.db.execute('SELECT row_number FROM logarchive_artifacts')]
        self.assertEqual(collected, [len(synthetic.build_lines())])
        source = inspect.getsource(logarchive.logarchive_artifacts.__wrapped__)
        for text in ("= 'com.apple.network'", 'nesessionmanager', "= 'connection'"):
            self.assertNotIn(text, source)


class FieldsTest(unittest.TestCase):
    def fields(self, message):
        return logarchive._network_connection_fields(message)  # pylint: disable=protected-access

    def test_state_line_with_a_tag(self):
        self.assertEqual(
            self.fields('[C1 Hostname#0badc0de:443 in_progress parent-flow (unsatisfied (No network route))] '
                        'event: flow:start_child @0.000s'),
            ('Hostname#0badc0de', '443', 'Host tag', '', '', 'in_progress', ''))

    def test_link_and_interface_come_from_the_path_description(self):
        message = ('[C4 Hostname#0badc0de:443 ready parent-flow (satisfied (Path is satisfied), '
                   'interface: utun4[nr_sa_sub6], ipv4, dns, uses cell, estimated upload: 1048576Bps)] event: x')
        self.assertEqual(self.fields(message)[3:6], ('cell', 'utun4', 'ready'))

    def test_description_line_takes_its_closing_action_and_bundle(self):
        message = ('[C2 00000000000000000000000000000AA1 Hostname#0badc0de:443 tcp, tls, bundle id: '
                   'com.example.mail, account id: 1a2b3c4d, attribution: website] is already cancelled, '
                   'ignoring forced cancel')
        self.assertEqual(self.fields(message)[5:], ('is already cancelled, ignoring forced cancel',
                                                    'com.example.mail'))

    def test_function_name_before_the_header_and_a_flag_word(self):
        message = ('nw_endpoint_resolver_update [C7.1.2 dry-run Hostname#feedface:443 in_progress resolver '
                   '(satisfied (Path is satisfied), interface: pdp_ip0[nr_sa_sub6], ipv6, dns, uses cell)] '
                   'Adding endpoint handler for IPv6#a56fa9a9.443')
        fields = self.fields(message)
        self.assertEqual((fields[0], fields[1], fields[3], fields[4], fields[5]),
                         ('Hostname#feedface', '443', 'cell', 'pdp_ip0', 'in_progress'))

    def test_only_the_first_header_is_read(self):
        fields = self.fields('[C1 www.example.com:443 initial path ((null))] then [C2 192.0.2.1:80 ready x]')
        self.assertEqual(fields[:3], ('www.example.com', '443', 'Host name'))

    def test_address_forms(self):
        self.assertEqual(self.fields('[C1 192.0.2.10:443 initial path ((null))]')[:3],
                         ('192.0.2.10', '443', 'IPv4 address'))
        self.assertEqual(self.fields('[C1.1 192.0.2.10.443 initial path ((null))]')[:3],
                         ('192.0.2.10', '443', 'IPv4 address'))
        self.assertEqual(self.fields('[C1 2001:db8::7.443 initial path ((null))]')[:3],
                         ('2001:db8::7', '443', 'IPv6 address'))
        self.assertEqual(self.fields('[C1 ::ffff:192.0.2.1.443 initial path ((null))]')[:3],
                         ('::ffff:192.0.2.1', '443', 'IPv6 address'))
        self.assertEqual(self.fields('[C1 IPv6#cafef00d.5223 initial path ((null))]')[:3],
                         ('IPv6#cafef00d', '5223', 'IPv6 tag'))

    def test_a_token_that_is_not_an_endpoint_is_not_one(self):
        for message in ('[C1] reporting state ready', '[C1 ', '', None, 123, 'no header here',
                        '[C1 Hostname#0badc0de initial path ((null))]', '[C1 notanendpoint initial path]',
                        '[C1 host.example.com initial path]', '[Cx Hostname#0badc0de:443 initial]'):
            with self.subTest(message=message):
                self.assertEqual(self.fields(message), ('', '', 'No endpoint in line', '', '', '', ''))

    def test_a_state_word_inside_another_word_is_not_a_state(self):
        fields = self.fields('[C1 www.example.com:443 readyish parent-flow ((null))]')
        self.assertEqual(fields[5], '')

    def test_interface_and_link_without_a_path_description_stay_blank(self):
        fields = self.fields('[C1 www.example.com:443 initial path ((null))] event: path:start @0.000s')
        self.assertEqual(fields[3:5], ('', ''))


class AggregationTest(unittest.TestCase):
    def rows(self, records):
        return logarchive._network_connection_rows(records)  # pylint: disable=protected-access

    def test_counts_and_first_and_last_seen_ignore_input_order(self):
        message = '[C1 www.example.com:443 initial path ((null))] event: path:start @0.000s'
        records = [(30.0, '/p', message), (10.0, '/p', message), (20.0, '/p', message)]
        for ordered in (records, records[::-1]):
            rows, total = self.rows(ordered)
            self.assertEqual(total, 3)
            self.assertEqual(len(rows), 1)
            first, last, count = rows[0][:3]
            self.assertEqual((count, first.timestamp(), last.timestamp()), (3, 10.0, 30.0))

    def test_a_timestamp_that_is_not_a_number_is_counted_but_not_ranged(self):
        message = '[C1 www.example.com:443 initial path ((null))]'
        rows, total = self.rows([(None, '/p', message), ('x', '/p', message), (True, '/p', message),
                                 (5.0, '/p', message)])
        self.assertEqual((total, rows[0][2], rows[0][0].timestamp(), rows[0][1].timestamp()), (4, 4, 5.0, 5.0))
        rows, _total = self.rows([(None, '/p', message)])
        self.assertEqual((rows[0][0], rows[0][1], rows[0][2]), (None, None, 1))

    def test_rows_split_by_process_link_interface_and_endpoint(self):
        wifi = '[C1 www.example.com:443 ready x (satisfied (Path is satisfied), interface: en0, uses wifi)]'
        cell = '[C1 www.example.com:443 ready x (satisfied (Path is satisfied), interface: pdp_ip0, uses cell)]'
        tun = '[C1 www.example.com:443 ready x (satisfied (Path is satisfied), interface: utun4, uses cell)]'
        other = '[C1 www.example.org:443 ready x ((null))]'
        rows, total = self.rows([(1.0, '/a', wifi), (2.0, '/a', cell), (3.0, '/a', tun), (4.0, '/a', other),
                                 (5.0, '/b', wifi), (6.0, '/a', wifi)])
        self.assertEqual(total, 6)
        self.assertEqual(sorted((row[3], row[4], row[7], row[8], row[2]) for row in rows),
                         [('/a', 'www.example.com', 'cell', 'pdp_ip0', 1), ('/a', 'www.example.com', 'cell', 'utun4', 1),
                          ('/a', 'www.example.com', 'wifi', 'en0', 2), ('/a', 'www.example.org', '', '', 1),
                          ('/b', 'www.example.com', 'wifi', 'en0', 1)])

    def test_the_sum_of_records_equals_the_lines_read(self):
        messages = ['[C1 www.example.com:443 initial path]', '[C2] reporting state ready', '', None, 'junk',
                    '[C3 IPv4#5ca1ab1e:443 waiting path]', '[C3 IPv4#5ca1ab1e:443 waiting path]']
        rows, total = self.rows([(float(index), '/p' if index % 2 else None, message)
                                 for index, message in enumerate(messages)])
        self.assertEqual(total, len(messages))
        self.assertEqual(sum(row[2] for row in rows), len(messages))

    def test_empty_input(self):
        self.assertEqual(self.rows([]), ([], 0))
        self.assertEqual(self.rows(iter(())), ([], 0))

    def test_bundle_ids_are_sorted_distinct_and_capped(self):
        records = [(float(index), '/p',
                    f'[C1 Hostname#0badc0de:443 tcp, tls, bundle id: com.example.app{index:02d}, a: b] start')
                   for index in range(25)]
        records += records[:3]  # repeats do not repeat the bundle id
        rows, _total = self.rows(records)
        listed = rows[0][10]
        limit = logarchive.NETWORK_BUNDLE_LIMIT
        self.assertTrue(listed.startswith('com.example.app00, com.example.app01'))
        self.assertTrue(listed.endswith(f'(+{25 - limit} more)'))
        self.assertEqual(listed.count('com.example.app'), limit)
        self.assertEqual(rows[0][2], 28)

    def test_rows_are_sorted_by_process_then_records_descending(self):
        a = '[C1 a.example.com:443 initial path]'
        b = '[C1 b.example.com:443 initial path]'
        rows, _total = self.rows([(1.0, '/z', a), (2.0, '/a', a), (3.0, '/a', b), (4.0, '/a', b)])
        self.assertEqual([(row[3], row[4], row[2]) for row in rows],
                         [('/a', 'b.example.com', 2), ('/a', 'a.example.com', 1), ('/z', 'a.example.com', 1)])

    def test_report_times_are_utc_datetimes(self):
        rows, _total = self.rows([(0.5, '/p', '[C1 www.example.com:443 initial path]')])
        self.assertEqual(rows[0][0], datetime(1970, 1, 1, 0, 0, 0, 500000, tzinfo=timezone.utc))


class SessionTest(unittest.TestCase):
    def template(self, message):
        return logarchive._network_event_template(message)  # pylint: disable=protected-access

    def test_numbers_and_addresses_are_replaced(self):
        self.assertEqual(self.template('Received a start command from fakemaild[321]'),
                         'Received a start command from fakemaild[<n>]')
        self.assertEqual(self.template('<NESMServer: 0x7f0c44001200>: x'), '<NESMServer: <hex>>: x')
        self.assertEqual(self.template('timeout 20 seconds, level <2>'), 'timeout <n> seconds, level <<n>>')

    def test_digits_inside_a_word_and_uuids_are_kept(self):
        self.assertEqual(self.template('Tearing down utun4'), 'Tearing down utun4')
        self.assertEqual(self.template('com.example.app2 and 3fa'), 'com.example.app2 and 3fa')
        uuid = '00000000-0000-4000-8000-0000000000aa'
        self.assertEqual(self.template(f'session {uuid} pid 7'), f'session {uuid} pid <n>')

    def test_unreadable_input_gives_an_empty_template(self):
        self.assertEqual(self.template(None), '')
        self.assertEqual(self.template(5), '')

    def test_rows_count_templates_and_keep_first_and_last_message_by_time(self):
        rows, total = logarchive._network_session_rows([  # pylint: disable=protected-access
            (20.0, '/n', 'start from x[2]'), (10.0, '/n', 'start from x[1]'), (30.0, '/n', 'start from x[3]'),
            (15.0, '/n', 'other'), (None, '/n', 'other'), (5.0, '/m', 'other')])
        self.assertEqual(total, 6)
        by_key = {(row[3], row[4]): row for row in rows}
        start = by_key[('/n', 'start from x[<n>]')]
        self.assertEqual((start[2], start[5], start[6]), (3, 'start from x[1]', 'start from x[3]'))
        self.assertEqual((start[0].timestamp(), start[1].timestamp()), (10.0, 30.0))
        self.assertEqual(by_key[('/n', 'other')][2], 2)
        self.assertEqual(by_key[('/m', 'other')][2], 1)
        self.assertEqual(sum(row[2] for row in rows), total)

    def test_no_valid_timestamp_keeps_the_first_message_seen(self):
        rows, _total = logarchive._network_session_rows([(None, '/n', 'a 1'), (None, '/n', 'a 2')])  # pylint: disable=protected-access
        self.assertEqual((rows[0][0], rows[0][1], rows[0][2], rows[0][5], rows[0][6]), (None, None, 2, 'a 1', 'a 1'))


class FixtureTest(unittest.TestCase):
    def test_fixture_is_reproducible_and_invented(self):
        self.assertEqual(synthetic.to_bytes(), synthetic.to_bytes())
        records = json.loads(synthetic.to_bytes())
        self.assertEqual(len(records), len(synthetic.build_lines()))
        for record in records:
            stamp = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S.%f%z')
            self.assertEqual(stamp.utcoffset(), timedelta(hours=-5))
            self.assertEqual(stamp.year, 2026)

    def test_fixture_holds_only_reserved_names_and_documentation_addresses(self):
        text = '\n'.join(record['eventMessage'] for record in json.loads(synthetic.to_bytes()))
        hosts = set(re.findall(r'\b((?:[a-z0-9-]+\.)+(?:com|org|net|io|apple))\b', text))
        self.assertTrue(hosts, 'the fixture should hold host names')
        for host in hosts:
            self.assertRegex(host, r'(^|\.)example\.(com|org|net)$|^com\.example\.')
        for address in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text):
            self.assertTrue(address.startswith(('192.0.2.', '198.51.100.', '203.0.113.')), address)
        for address in re.findall(r'\b[0-9a-f]{1,4}:[0-9a-f:]*:[0-9a-f]+\b', text):
            self.assertTrue(address.startswith('2001:db8:') or address.startswith('::ffff:'), address)


if __name__ == '__main__':
    unittest.main()
