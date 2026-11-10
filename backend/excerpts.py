"""Verify model excerpts, including JSON string escapes, against immutable raw text."""
import json
import re


def excerpt_context_hints(content, quotes, *, risk_only=False):
    """Bounded literal context for re-extraction, never evidence acceptance.

    Similarity only selects which source passage to show the reviewer again.
    Ordinary excerpts remain exact; positive risks may use source-proven
    decoding through locate_risk_excerpt. Neither path uses fuzzy acceptance.
    """
    from difflib import SequenceMatcher

    views = [(content, None)]
    views.extend(json_string_views(content, limit=8))
    hints = []
    for quote in quotes[:4]:
        best = None
        for text, mapping in views:
            match = SequenceMatcher(None, text, quote[:1000], autojunk=False).find_longest_match()
            if match.size >= 12 and (best is None or match.size > best[0]):
                best = (match.size, text, mapping, match.a)
        if best is None:
            continue
        size, text, mapping, offset = best
        low, high = max(0, offset - 160), min(len(text), offset + min(size, 320) + 160)
        raw_low, raw_high = (mapping[low][0], mapping[high - 1][1]) if mapping else (low, high)
        hint = {'excerpt': text[low:high], 'start': raw_low, 'end': raw_high}
        if hint not in hints:
            hints.append(hint)
    if risk_only and quotes:
        readable = []
        # Long JSON escape sequences can dominate textual similarity. Inspect
        # the bounded decoded SOURCE views directly to prioritize a readable
        # positive-evidence hint; never decode the model's invented words.
        for text, mapping in views:
            for run in re.finditer(r'(?:\\[^\\]){12,}', text):
                low = max(0, run.start() - 80)
                end = min(run.end(), run.start() + 480)
                high = min(len(text), end + 80) if end == run.end() else end
                excerpt = text[low:high]
                projection = re.sub(r'(?:\\[^\\]){12,}', lambda m: ''.join(
                    c for c in m[0][1::2] if c not in _FORMAT_CONTROLS), excerpt)
                if projection == excerpt:
                    continue
                raw_low, raw_high = (mapping[low][0], mapping[high - 1][1]) if mapping else (low, high)
                location = locate_risk_excerpt(content, projection)
                if location and raw_low <= location[0] < location[1] <= raw_high:
                    hint = {'excerpt': excerpt, 'start': raw_low, 'end': raw_high,
                            'risk_projection': projection, 'risk_projection_transform': location[2]}
                    if hint not in readable:
                        readable.append(hint)
                if len(readable) == 4:
                    break
            if len(readable) == 4:
                break
        hints = readable + [hint for hint in hints if hint not in readable]
    return hints[:4]


def locate_excerpt(content, quote, depth=4):
    return _locate_excerpt(content, quote, depth, False)


def locate_risk_excerpt(content, quote, depth=4):
    """Map positive risk evidence only; never use this to authorize content."""
    match = locate_excerpt(content, quote, depth) or _locate_excerpt(content, quote, depth, True)
    if match:
        return match
    for _ in range(depth):
        try:
            decoded = json.loads('"' + quote + '"')
        except ValueError:
            break
        if decoded == quote:
            break
        quote = decoded
        match = _locate_excerpt(content, quote, depth, True)
        if match:
            low, high, transform = match
            return low, high, 'model_json_string_escapes+' + transform
    return None


_FORMAT_CONTROLS = frozenset('\u200b\u200c\u200d\u2060\ufeff')
_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
_FULLWIDTH_ASCII = {code: code - 0xfee0 for code in range(0xff01, 0xff5f)}


def _separated_risk_excerpt(content, quote):
    """Positive evidence in a run with a literal backslash before EVERY character.

    This is not a general escape decoder: paths, code and sporadic escapes do
    not qualify. Only separator loss in the model's copy is tolerated; visible
    characters, whitespace and ordering remain exact. Never used for release.
    """
    if not quote or len(quote) > 5000:
        return None
    for run in re.finditer(r'(?:\\[^\\]){12,}', content):
        # Decode only the proven source run. Keep the surrounding prefix and
        # suffix literal, so a prefixed model citation can still be mapped.
        low, high = max(0, run.start() - 2048), min(len(content), run.end() + 2048)
        encoded_positions = list(range(run.start() + 1, run.end(), 2))
        source_controls = {content[i] for i in encoded_positions if content[i] in _FORMAT_CONTROLS}
        has_controls = bool(source_controls)
        encoded_positions = [i for i in encoded_positions if content[i] not in _FORMAT_CONTROLS]
        visible = ''.join(content[i] for i in encoded_positions)
        middle = content[low:run.start()]
        tail = content[run.end():high]
        projected = middle + visible + tail
        positions = list(range(low, run.start())) + encoded_positions + list(range(run.end(), high))
        encoded = [False] * len(middle) + [True] * len(visible) + [False] * len(tail)
        folded = projected.translate(_ASCII_LOWER)
        requested = quote.translate(_ASCII_LOWER)
        def skip_encoded_controls(offset):
            nonlocal used_unicode_escape
            # The model can retain only some invisible source characters,
            # including their separators. This applies inside the proven run
            # only; surrounding literal context must still match exactly.
            while has_controls and offset < len(requested):
                # A model may spell an actual source format character as
                # literal \uXXXX while retaining per-character separators.
                # Decode only these five invisible characters, only when that
                # same character occurs in the proven source run. Never decode
                # arbitrary Unicode words or escapes in literal context.
                token = re.match(r'\\u([0-9a-f]{4})', requested[offset:offset + 6])
                if token and chr(int(token[1], 16)) in source_controls:
                    offset += 6
                    used_unicode_escape = True
                    continue
                step = int(requested[offset] == '\\')
                if offset + step >= len(requested) or requested[offset + step] not in _FORMAT_CONTROLS:
                    break
                offset += step + 1
            return offset
        # The citation may retain or omit separator backslashes, but only while
        # matching characters from this source-proven encoded run. Every other
        # character, including the quoted prefix/suffix, remains exact.
        for start, char in enumerate(folded):
            used_unicode_escape = False
            first = skip_encoded_controls(0) if encoded[start] else 0
            if first == len(requested):
                continue
            if char != requested[first] and not (encoded[start] and requested[first] == '\\'
                    and first + 1 < len(requested) and char == requested[first + 1]):
                continue
            p, q, encoded_count = start, 0, 0
            while p < len(folded) and q < len(requested):
                if encoded[p]:
                    q = skip_encoded_controls(q)
                if q == len(requested):
                    break
                separator = int(encoded[p] and requested[q] == '\\')
                if q + separator == len(requested) or folded[p] != requested[q + separator]:
                    break
                encoded_count += int(encoded[p])
                p += 1
                q += separator + 1
            if q == len(requested) and encoded_count >= 12:
                raw_start = positions[start] - int(encoded[start])
                transform = 'per_character_backslash+literal_context+ascii_case_insensitive'
                if has_controls:
                    transform += '+format_controls_removed'
                if used_unicode_escape:
                    transform += '+format_control_escapes'
                return raw_start, positions[p - 1] + 1, transform
    return None


def json_string_views(content, depth=4, limit=128):
    """Bounded decoded JSON strings with composed offsets into immutable input."""
    pending = [(content, None, 0)]
    emitted = 0
    while pending and emitted < limit:
        text, origin, level = pending.pop()
        if level >= depth:
            continue
        for decoded, mapping in _decoded_strings(text):
            if origin is not None:
                mapping = [(origin[low][0], origin[high - 1][1]) for low, high in mapping]
            yield decoded, mapping
            emitted += 1
            if emitted >= limit:
                return
            pending.append((decoded, mapping, level + 1))


def _locate_excerpt(content, quote, depth, allow_risk_transforms):
    if not quote:
        return None
    direct = content.find(quote)
    if direct >= 0:
        return direct, direct + len(quote), "original"
    if allow_risk_transforms:
        # ASCII case changes preserve character count and cannot erase words.
        # This path verifies positive risk evidence only, never authority.
        offset = content.translate(_ASCII_LOWER).find(quote.translate(_ASCII_LOWER))
        if offset >= 0:
            return offset, offset + len(quote), 'ascii_case_insensitive'
        positions = [i for i, char in enumerate(content) if char not in _FORMAT_CONTROLS]
        projected = ''.join(content[i] for i in positions)
        requested = ''.join(char for char in quote if char not in _FORMAT_CONTROLS)
        offset = projected.find(requested) if requested else -1
        if offset >= 0:
            return positions[offset], positions[offset + len(requested) - 1] + 1, 'format_controls_removed'
        offset = projected.translate(_ASCII_LOWER).find(requested.translate(_ASCII_LOWER)) if requested else -1
        if offset >= 0:
            return positions[offset], positions[offset + len(requested) - 1] + 1, 'format_controls_removed+ascii_case_insensitive'
        separated = _separated_risk_excerpt(content, quote)
        if separated:
            return separated
        # Positive evidence only: the fullwidth ASCII presentation is 1:1.
        # Reuse bounded risk transforms without changing raw character offsets;
        # never use NFKC, remove visible words, or relax benign quote coverage.
        narrow = content.translate(_FULLWIDTH_ASCII)
        if narrow != content:
            located = _locate_excerpt(narrow, quote.translate(_FULLWIDTH_ASCII), 0, True)
            if located:
                low, high, transform = located
                return low, high, 'fullwidth_ascii+' + transform
    if depth <= 0:
        return None
    for decoded, mapping in _decoded_strings(content):
        nested = _locate_excerpt(decoded, quote, depth - 1, allow_risk_transforms)
        if nested:
            low, high, transform = nested
            kind = 'json_string_escapes'
            for operation in ('fullwidth_ascii', 'per_character_backslash', 'format_controls_removed', 'format_control_escapes', 'ascii_case_insensitive'):
                if operation in transform.split('+'):
                    kind += '+' + operation
            return mapping[low][0], mapping[high - 1][1], kind
    return None


def _decoded_strings(content):
    for match in re.finditer(r'"(?:[^"\\]|\\.)*"', content):
        literal = match.group()
        try:
            decoded = json.loads(literal)
        except ValueError:
            continue
        mapping, cursor = [], 1
        while cursor < len(literal) - 1:
            start = cursor
            if literal[cursor] != "\\":
                cursor += 1
            elif literal[cursor + 1] == "u":
                code = int(literal[cursor + 2:cursor + 6], 16)
                cursor += 6
                if 0xD800 <= code <= 0xDBFF and literal[cursor:cursor + 2] == "\\u":
                    low = int(literal[cursor + 2:cursor + 6], 16)
                    if 0xDC00 <= low <= 0xDFFF:
                        cursor += 6
            else:
                cursor += 2
            mapping.append((match.start() + start, match.start() + cursor))
        if len(mapping) == len(decoded):
            yield decoded, mapping
