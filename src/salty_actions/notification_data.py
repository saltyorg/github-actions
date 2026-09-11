"""Apply optional, run-bound presentation data to an existing notification."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError('invalid notification text')
    return value


def apply_notification_data(
    notification: dict[str, Any],
    path: Path,
    workflow_run: Mapping[str, Any],
) -> dict[str, Any]:
    # Bounded read; never execute artifact content or use it for result identity.
    with path.open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('notification data exceeds 64 KiB')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('notification data must be an object')
    for key, expected in [('schema', 1), ('run_id', workflow_run['id']),
                          ('run_attempt', workflow_run['run_attempt'])]:
        if type(data.get(key)) is not int or data[key] != expected:
            raise ValueError('notification data does not match this run attempt')
    if set(data) - {'schema', 'run_id', 'run_attempt', 'event_details', 'fields'}:
        raise ValueError('unknown notification data property')

    result = deepcopy(notification)
    embed = result['embeds'][0]
    fields = embed['fields']
    if 'event_details' in data:
        fields[2] = {'name': f"Event - {workflow_run.get('event') or 'unknown'}",
                     'value': _text(data['event_details'], 1024), 'inline': False}
    custom = data.get('fields', [])
    if not isinstance(custom, list) or len(custom) > 20:
        raise ValueError('invalid custom field list')
    inserted = []
    inline_count = 0
    for field in custom:
        if not isinstance(field, dict) or set(field) - {'name', 'value', 'inline'}:
            raise ValueError('invalid custom field')
        inline = field.get('inline', False)
        if type(inline) is not bool:
            raise ValueError('inline must be boolean')
        inserted.append({'name': _text(field.get('name'), 256),
                         'value': _text(field.get('value'), 1024), 'inline': inline})
        inline_count = inline_count + 1 if inline else 0
    # Complete the final three-column row before the existing metadata fields.
    for _ in range((-inline_count) % 3):
        inserted.append({'name': '\u200b', 'value': '\u200b', 'inline': True})
    fields[3:3] = inserted
    if len(fields) > 25:
        raise ValueError('notification exceeds Discord field limit')
    total = len(embed['title']) + len(embed['description'])
    total += sum(len(field['name']) + len(field['value']) for field in fields)
    if total > 6000:
        raise ValueError('notification exceeds Discord text limit')
    return result
