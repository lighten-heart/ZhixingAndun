import { Component, type ReactNode } from "react";
import { RefreshCw, TriangleAlert } from "lucide-react";

export default class ErrorBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="app-recovery" role="alert">
        <TriangleAlert size={33} />
        <h1>页面暂时无法显示</h1>
        <p>已有操作保存在本地服务中。请重新加载页面后继续。</p>
        <button className="button primary" onClick={() => location.reload()}>
          <RefreshCw size={16} />
          重新加载
        </button>
      </div>
    );
  }
}
