const TOKEN_KEY = "aegisguard-session-token";
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
export const getToken = () => sessionStorage.getItem(TOKEN_KEY) || "";
export const setToken = (value: string) => {
  value
    ? sessionStorage.setItem(TOKEN_KEY, value)
    : sessionStorage.removeItem(TOKEN_KEY);
};
export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body) headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("X-Guard-Token", token);
  let response: Response;
  try {
    response = await fetch(`/api${path}`, { ...options, headers });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new ApiError("无法连接本地服务，请确认后端已启动后重试。", 0);
  }
  const text = await response.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(
      "服务返回了无法识别的数据，请确认 API 服务正常。",
      response.status,
    );
  }
  if (!response.ok) {
    const detail = (data as { detail?: unknown })?.detail;
    throw new ApiError(
      response.status === 401 || response.status === 403
        ? "访问被拒绝，请检查会话访问令牌及操作权限。"
        : typeof detail === "string"
          ? detail
          : JSON.stringify(detail || `请求失败 (${response.status})`),
      response.status,
    );
  }
  return data as T;
}
export const post = <T>(path: string, data: unknown = {}) =>
  api<T>(path, { method: "POST", body: JSON.stringify(data) });
export function downloadJSON(value: unknown, filename: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], {
      type: "application/json;charset=utf-8",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
