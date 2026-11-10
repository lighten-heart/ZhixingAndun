import { useCallback, useEffect, useState } from "react";
import { api } from "../api";

/** A route change cancels the obsolete read and never exposes another route's data. */
export function useResource<T>(path: string, tick = 0) {
  const [state, setState] = useState<{
    path: string;
    data: T | null;
    error: string;
    loading: boolean;
    updatedAt: string | null;
  }>({ path, data: null, error: "", loading: true, updatedAt: null });
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setState((previous) => ({
      path,
      data: previous.path === path ? previous.data : null,
      updatedAt: previous.path === path ? previous.updatedAt : null,
      error: "",
      loading: true,
    }));
    api<T>(path, { signal: controller.signal })
      .then((data) => {
        if (!controller.signal.aborted)
          setState({
            path,
            data,
            error: "",
            loading: false,
            updatedAt: new Date().toISOString(),
          });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted)
          setState((previous) => ({
            ...previous,
            // A failed read must not leave prior protected records on screen.
            data: null,
            error:
              error instanceof Error ? error.message : "数据读取失败，请重试。",
            loading: false,
          }));
      });
    return () => controller.abort();
  }, [path, tick, revision]);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  return {
    ...(state.path === path
      ? state
      : { data: null, error: "", loading: true, updatedAt: null }),
    refresh,
  };
}
