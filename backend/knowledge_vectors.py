"""Deterministic sparse TF-IDF vectors; lexical similarity, not semantic embeddings."""
from collections import Counter
import math
import re


def terms(text):
    words = re.findall(r"[a-z0-9_]+|[\u4e00-\u9fff]+", text.lower())
    result = []
    for word in words:
        result.extend([word[i:i + 2] for i in range(len(word) - 1)] if re.match(r"[\u4e00-\u9fff]", word) and len(word) > 1 else [word])
    return Counter(result)


def rank(query, segments):
    """The corpus must already be permission-filtered before computing vectors."""
    counts = [terms(s["content"]) for s in segments]
    document_frequency = Counter(term for c in counts for term in c)
    def vector(count):
        return {term: (1 + math.log(n)) * (1 + math.log((1 + len(counts)) / (1 + document_frequency[term]))) for term, n in count.items()}
    q = vector(terms(query))
    qnorm = math.sqrt(sum(v * v for v in q.values()))
    scored = []
    for item, count in zip(segments, counts):
        v = vector(count)
        denominator = qnorm * math.sqrt(sum(x * x for x in v.values()))
        score = sum(weight * v.get(term, 0) for term, weight in q.items()) / denominator if denominator else 0
        if score > 0:
            scored.append({**item, "score": round(score, 8)})
    return sorted(scored, key=lambda s: (-s["score"], s["document_id"], s["segment"]))
