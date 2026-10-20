#!/usr/bin/env python3
"""Build a SYNTHETIC Unified Log export for the network connection and NetworkExtension session artifacts.

The output has the shape of ``log show --style json``: a JSON list of records with
``timestamp``, ``processImagePath``, ``processID``, ``subsystem``, ``category``,
``eventMessage`` and ``traceID`` (iLEAPP's logarchive artifact accepts any ``logarchive*.json``).

Every process, bundle id, endpoint and session name is invented. Host names are under the reserved
example domains, addresses are in the documentation ranges (192.0.2.0/24, 2001:db8::/32), the
``Hostname#`` / ``IPv4#`` / ``IPv6#`` tags are made-up hexadecimal words, and every timestamp is
fixed, so the output is reproducible and carries nothing from a real device. The message shapes follow
what ``com.apple.network`` / ``connection`` and ``nesessionmanager`` lines looked like on iOS 26.6 and
iOS 27.0 sysdiagnose logs decoded with unifiedlog_iterator; shapes the real logs did not contain are
marked ``INVENTED SHAPE`` below, and they exist to exercise a branch, not to describe a device. How
such lines appear in a ``log show`` export was not examined.

    python synthetic_network.py [output.json]

``build_lines()`` labels each line 'conn' (read by the network connections artifact), 'session' (read by
the session events artifact) or 'never' (read by neither); ``lines_of(kind)`` gives the Row Numbers the
import assigns to them.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone

_ZONE = timezone(timedelta(hours=-5))
_BASE = datetime(2026, 3, 14, 10, 0, 0, tzinfo=_ZONE)

FIXTURE_NAME = 'logarchive_synthetic_network.json'

MAILD = '/usr/libexec/fakemaild'
BROWSER = ('/private/var/containers/Bundle/Application/FAKE0000-0000-0000-0000-000000000011/'
           'FakeBrowser.app/FakeBrowser')
SESSIOND = '/usr/libexec/fakesessiond'
SESSION_MANAGER = '/usr/libexec/nesessionmanager'
NE_HELPER = '/usr/libexec/fakenehelper'

NETWORK = 'com.apple.network'
EXTENSION = 'com.apple.networkextension'

HOST_TAG = 'Hostname#0badc0de'
SESSION = 'NESMVPNSession[Primary Tunnel:Fake VPN:00000000-0000-4000-8000-0000000000aa:(null)]'

SATISFIED = ('(satisfied (Path is satisfied), interface: {interface}[nr_sa_sub6], ipv4, dns, uses {link}, '
             'estimated upload: 1048576Bps, estimated download: 16777216Bps, LQM: moderate)')
UNSATISFIED = '(unsatisfied (No network route))'


def _path_line(connection, endpoint, state, stage, path, event):
    return f'[{connection} {endpoint} {state} {stage} {path}] event: {event}'


def _described(connection, endpoint, bundle, action, uuid=''):
    head = f'[{connection} {uuid + " " if uuid else ""}{endpoint} tcp, tls, bundle id: {bundle}, ' \
           f'account id: 1a2b3c4d, attribution: website]'
    return f'{head} {action}'


def build_lines():
    """(seconds after the base time, process path, pid, subsystem, category, message, kind) in file order.

    The last element names the branch each line exercises: 'conn' lines are read by the connections
    artifact, 'session' lines by the session events artifact, and 'never' lines by neither.
    """
    lines = []

    def add(sec, process, pid, message, kind, subsystem=NETWORK, category='connection'):
        lines.append((sec, process, pid, subsystem, category, message, kind))

    # --- fakemaild: one tag, many lines (the shape that makes a row per line unusable) ---
    add(10.000, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'initial', 'path', '((null))',
                                        'path:start @0.000s'), 'conn')
    add(10.100, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'in_progress', 'parent-flow', UNSATISFIED,
                                        'flow:start_child @0.000s'), 'conn')
    add(10.200, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'waiting', 'parent-flow', UNSATISFIED,
                                        'flow:child_failed @0.001s'), 'conn')
    add(10.300, MAILD, 2101, 'nw_connection_report_state_with_handler_on_nw_queue [C1] reporting state waiting',
        'conn')
    add(11.000, MAILD, 2101, _described('C2', f'{HOST_TAG}:443', 'com.example.mail', 'start',
                                        uuid='00000000000000000000000000000AA1'), 'conn')
    add(11.500, MAILD, 2101, _described('C2', f'{HOST_TAG}:443', 'com.example.mail', 'cancelled'), 'conn')
    add(12.000, MAILD, 2101, _described('C3', f'{HOST_TAG}:443', 'com.example.mail.shared',
                                        'is already cancelled, ignoring cancel'), 'conn')
    # The same tag over three different links is three rows.
    add(20.000, MAILD, 2101, _path_line('C4', f'{HOST_TAG}:443', 'ready', 'parent-flow',
                                        SATISFIED.format(interface='utun4', link='cell'),
                                        'path:satisfied @0.020s'), 'conn')
    add(21.000, MAILD, 2101, _path_line('C5', f'{HOST_TAG}:443', 'ready', 'parent-flow',
                                        SATISFIED.format(interface='pdp_ip0', link='cell'),
                                        'path:satisfied @0.020s'), 'conn')
    add(22.000, MAILD, 2101, _path_line('C6', f'{HOST_TAG}:443', 'ready', 'parent-flow',
                                        SATISFIED.format(interface='en0', link='wifi'),
                                        'path:satisfied @0.020s'), 'conn')
    # A line that is earlier than the rows above but written after them: First Seen is a minimum.
    add(5.000, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'initial', 'parent-flow', '((null))',
                                       'path:start @0.000s'), 'conn')
    # A state-only line and a line with a header but no endpoint.
    add(30.000, MAILD, 2101, '[C1] event: client:connection_idle @0.512s', 'conn')
    add(31.000, MAILD, 2101, 'nw_connection_report_state_with_handler_on_nw_queue [C2] reporting state ready',
        'conn')

    # --- FakeBrowser: names, addresses and tags of each form ---
    add(40.000, BROWSER, 2201, _path_line('C1', 'www.example.com:443', 'initial', 'parent-flow', '((null))',
                                          'path:start @0.000s'), 'conn')
    add(41.000, BROWSER, 2201, _path_line('C1', 'www.example.com:443', 'ready', 'parent-flow',
                                          SATISFIED.format(interface='en0', link='wifi'),
                                          'path:satisfied @0.030s'), 'conn')
    add(41.500, BROWSER, 2201, _path_line('C1', 'www.example.com:443', 'ready', 'parent-flow',
                                          SATISFIED.format(interface='en0', link='wifi'),
                                          'path:satisfied @0.031s'), 'conn')
    add(42.000, BROWSER, 2201, _path_line('C2', 'cdn.example.org:8443', 'initial', 'path', '((null))',
                                          'path:start @0.000s'), 'conn')
    add(43.000, BROWSER, 2201, _path_line('C3.1', '192.0.2.10:443', 'initial', 'path', '((null))',
                                          'path:start @0.000s'), 'conn')
    add(44.000, BROWSER, 2201, _path_line('C4.1.1', '2001:db8::7.443', 'in_progress', 'channel-flow',
                                          SATISFIED.format(interface='en0', link='wifi'),
                                          'path:satisfied @0.040s'), 'conn')
    add(45.000, BROWSER, 2201, _path_line('C5', 'IPv4#5ca1ab1e:443', 'initial', 'path', '((null))',
                                          'path:start @0.000s'), 'conn')
    add(46.000, BROWSER, 2201, _path_line('C6', 'IPv6#cafef00d.443', 'initial', 'path', '((null))',
                                          'path:start @0.000s'), 'conn')
    # INVENTED SHAPE: a dry-run flag before the endpoint, and a child endpoint named after the header.
    add(47.000, BROWSER, 2201,
        'nw_endpoint_resolver_update [C7.1 dry-run Hostname#feedface:443 in_progress resolver '
        + SATISFIED.format(interface='pdp_ip0', link='cell')
        + '] Adding endpoint handler for IPv6#a56fa9a9.443', 'conn')
    add(48.000, BROWSER, 2201, '[C1] event: client:connection_idle @0.512s', 'conn')

    # --- fakesessiond: the same tag as fakemaild is a separate row; bundle ids are listed ---
    add(50.000, SESSIOND, 2301, _described('C1', f'{HOST_TAG}:443', 'com.example.zeta', 'start'), 'conn')
    add(51.000, SESSIOND, 2301, _described('C2', f'{HOST_TAG}:443', 'com.example.alpha', 'start'), 'conn')
    add(52.000, SESSIOND, 2301, _described('C3', f'{HOST_TAG}:443', 'com.example.alpha', 'cancel'), 'conn')

    # --- lines that must not break or be counted as an endpoint ---
    # INVENTED SHAPE: a truncated header, an endpoint token that is no endpoint, a tag with no port,
    # and an empty message. Each is a line of the connection category and so is counted.
    add(60.000, BROWSER, 2201, '[C9 ', 'conn')
    add(61.000, BROWSER, 2201, '[C8 not-an-endpoint initial path ((null))] event: path:start @0.000s', 'conn')
    add(62.000, BROWSER, 2201, f'[C7 {HOST_TAG} initial path ((null))] event: path:start @0.000s', 'conn')
    add(63.000, BROWSER, 2201, '', 'conn')

    # --- decoys: same text under other subsystems or categories ---
    add(70.000, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'initial', 'path', '((null))',
                                        'path:start @0.000s'), 'never', category='tcp')
    add(71.000, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'initial', 'path', '((null))',
                                        'path:start @0.000s'), 'never', subsystem='com.apple.network.ServiceDiscovery')
    add(72.000, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'initial', 'path', '((null))',
                                        'path:start @0.000s'), 'never', category='Connection')
    add(73.000, MAILD, 2101, _path_line('C1', f'{HOST_TAG}:443', 'initial', 'path', '((null))',
                                        'path:start @0.000s'), 'never', category='')

    # --- NetworkExtension session manager ---
    add(99.000, SESSION_MANAGER, 2401, 'applyIPDefaultDrop: IP Drop-All disabled', 'session',
        subsystem=EXTENSION, category='')
    add(100.000, SESSION_MANAGER, 2401, f'{SESSION}: Received a start command from fakemaild[321]', 'session',
        subsystem=EXTENSION, category='')
    add(101.000, SESSION_MANAGER, 2401, f'{SESSION}: Received a start command from fakemaild[322]', 'session',
        subsystem=EXTENSION, category='')
    add(102.000, SESSION_MANAGER, 2401, f'{SESSION}: Entering state NESMVPNSessionStateStarting', 'session',
        subsystem=EXTENSION, category='')
    add(103.000, SESSION_MANAGER, 2401,
        f'{SESSION}: Entering state NESMVPNSessionStateStopping, timeout 20 seconds', 'session',
        subsystem=EXTENSION, category='')
    add(104.000, SESSION_MANAGER, 2401,
        f'<NESMServer: 0x7f0c44001200>: Register Enterprise VPN Session: {SESSION}', 'session',
        subsystem=EXTENSION, category='')
    add(105.000, SESSION_MANAGER, 2401, 'Tearing down utun4', 'session', subsystem=EXTENSION, category='')
    # A line before the others, written after them: First Message is the earliest by time.
    add(98.000, SESSION_MANAGER, 2401, f'{SESSION}: Received a start command from fakemaild[320]', 'session',
        subsystem=EXTENSION, category='')
    # The category Large exists in the real logs; the artifact reads the subsystem, not the category.
    add(106.000, SESSION_MANAGER, 2401, 'Tearing down utun4', 'session', subsystem=EXTENSION,
        category='Large')

    # --- session decoys ---
    add(110.000, NE_HELPER, 2501, 'Setting UUID cache generation to 7', 'never', subsystem=EXTENSION,
        category='')
    add(111.000, SESSION_MANAGER, 2401, f'{SESSION}: Entering state NESMVPNSessionStateStarting', 'never',
        subsystem='com.apple.xpc', category='connection')
    add(112.000, '/usr/libexec/nesessionmanager2', 2402, 'Tearing down utun4', 'never', subsystem=EXTENSION,
        category='')
    # One line an existing logarchive_artifacts marker collects. The two-stage chain runs the dependent
    # artifacts only once that table exists, which on a real image it always does; without a line like
    # this one the fixture would give an empty table and the artifacts would not run.
    add(120.000, '/usr/libexec/fakeshot', 2601, 'Take screenshot', 'never', subsystem='com.example.fake',
        category='')
    return lines


def _stamp(seconds):
    return (_BASE + timedelta(seconds=seconds)).strftime('%Y-%m-%d %H:%M:%S.%f%z')


def build_records():
    """The JSON list in file order. traceID is a fixed, invented number per line."""
    records = []
    for index, (sec, process, pid, subsystem, category, message, _kind) in enumerate(build_lines()):
        records.append({
            'traceID': 1000 + index,
            'eventMessage': message,
            'eventType': 'logEvent',
            'source': None,
            'formatString': '%{public}s',
            'activityIdentifier': 0,
            'subsystem': subsystem,
            'category': category,
            'threadID': 4000 + index,
            'senderImageUUID': '00000000-0000-0000-0000-000000000000',
            'senderImagePath': process,
            'machTimestamp': 1000000 + index,
            'messageType': 'Default',
            'processImageUUID': '00000000-0000-0000-0000-000000000001',
            'processUniqueID': pid,
            'processID': pid,
            'processImagePath': process,
            'timestamp': _stamp(sec),
            'timezoneName': '',
            'creatorActivityID': 0,
            'parentActivityIdentifier': 0,
        })
    return records


def to_bytes(records=None):
    return (json.dumps(build_records() if records is None else records, indent=1) + '\n').encode('utf-8')


def lines_of(kind):
    """1-based file positions (the Row Number the import assigns) of the lines of one kind."""
    return [index for index, line in enumerate(build_lines(), start=1) if line[6] == kind]


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else FIXTURE_NAME
    with open(target, 'wb') as handle:
        handle.write(to_bytes())
    print(f'wrote {target}: {len(build_lines())} records')
