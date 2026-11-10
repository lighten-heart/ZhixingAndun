import type { Finding } from "./types";

/** Finding ranges are Python Unicode codepoint offsets mapped back to original text. */
export default function HighlightedText({
  text,
  findings,
}: {
  text: string;
  findings: Finding[];
}) {
  const characters = Array.from(text);
  const intervals = findings
    .filter(
      (f) =>
        Number.isInteger(f.start) && Number.isInteger(f.end) && f.end > f.start,
    )
    .map((f) => ({
      start: Math.max(0, f.start),
      end: Math.min(characters.length, f.end),
    }))
    .filter((f) => f.start < f.end)
    .sort((a, b) => a.start - b.start);
  const merged: { start: number; end: number }[] = [];
  for (const interval of intervals) {
    const last = merged[merged.length - 1];
    if (last && interval.start <= last.end)
      last.end = Math.max(last.end, interval.end);
    else merged.push({ ...interval });
  }
  const nodes = [];
  let position = 0;
  for (const interval of merged) {
    if (interval.start > position)
      nodes.push(characters.slice(position, interval.start).join(""));
    nodes.push(
      <mark key={interval.start}>
        {characters.slice(interval.start, interval.end).join("")}
      </mark>,
    );
    position = interval.end;
  }
  if (position < characters.length)
    nodes.push(characters.slice(position).join(""));
  return <>{nodes}</>;
}
