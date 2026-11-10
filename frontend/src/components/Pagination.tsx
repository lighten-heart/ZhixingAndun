import { ChevronLeft, ChevronRight } from "lucide-react";

export function pageSlice<T>(items: T[], page: number, pageSize: number) {
  const current = Math.max(
    1,
    Math.min(page, Math.ceil(items.length / pageSize) || 1),
  );
  return items.slice((current - 1) * pageSize, current * pageSize);
}

export default function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  label = "记录",
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  label?: string;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.max(1, Math.min(page, pages));
  return (
    <nav className="pagination" aria-label={`${label}分页`}>
      <span className="pagination-summary" aria-live="polite">
        {total
          ? `${(current - 1) * pageSize + 1}–${Math.min(current * pageSize, total)}`
          : "0"}{" "}
        / 共 {total} 条{label}
      </span>
      <div className="pagination-controls">
        <label className="page-size-select">
          每页
          <select
            aria-label={`每页${label}数`}
            value={pageSize}
            onChange={(event) => {
              onPageSizeChange(Number(event.target.value));
              onPageChange(1);
            }}
          >
            {[...new Set([15, 30, 50, 100, pageSize])]
              .sort((a, b) => a - b)
              .map((size) => (
                <option value={size} key={size}>
                  {size} 条
                </option>
              ))}
          </select>
        </label>
        <span className="page-position">
          {current} / {pages} 页
        </span>
        <button
          className="icon-button"
          aria-label={`上一页${label}`}
          disabled={current === 1}
          onClick={() => onPageChange(current - 1)}
        >
          <ChevronLeft size={17} />
        </button>
        <button
          className="icon-button"
          aria-label={`下一页${label}`}
          disabled={current === pages}
          onClick={() => onPageChange(current + 1)}
        >
          <ChevronRight size={17} />
        </button>
      </div>
    </nav>
  );
}
