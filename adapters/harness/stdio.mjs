import {spawn} from 'node:child_process';
import {StringDecoder} from 'node:string_decoder';

/** One outstanding request, fixed argv, bounded framing, kill on timeout. */
export class StdioMCP {
  constructor(command, args) {
    this.child = spawn(command, args, {stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true});
    this.counter = 0;
    this.pending = null;
    this.closed = false;
    this.queue = Promise.resolve();
    this.buffer = '';
    const decoder = new StringDecoder('utf8');
    const receive = line => {
      try {
        if (line.length > 200000) throw new Error('MCP response limit');
        const value = JSON.parse(line);
        if (value.jsonrpc !== '2.0') throw new Error('MCP framing');
        if (!('id' in value)) return;
        if (!this.pending || value.id !== this.pending.id) throw new Error('MCP correlation');
        const pending = this.pending;
        this.pending = null;
        clearTimeout(pending.timer);
        if (value.error || !value.result || typeof value.result !== 'object') pending.reject(new Error('MCP response rejected'));
        else pending.resolve(value.result);
      } catch { this.close(); }
    };
    this.child.stdout.on('data', chunk => {
      if (this.closed) return;
      this.buffer += decoder.write(chunk);
      let end;
      while (!this.closed && (end = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end + 1);
        receive(line);
      }
      if (this.buffer.length > 200000) this.close();
    });
    this.child.on('exit', () => this.close());
    this.child.on('error', () => this.close());
    this.child.stdin.on('error', () => this.close());
    // Idle MCP pipes must not keep a completed headless task alive.
    // Outstanding requests have a deadline timer; closing parent pipes gives the server EOF.
    this.child.unref();
    this.child.stdin.unref?.();
    this.child.stdout.unref?.();
  }
  async request(method, params = {}) {
    let release;
    const previous = this.queue;
    this.queue = new Promise(resolve => {release = resolve;});
    await previous;
    try {
      if (this.closed) throw new Error('MCP closed');
      return await new Promise((resolve, reject) => {
        const id = ++this.counter;
        const timer = setTimeout(() => this.close(), method === 'tools/call' ? 160000 : 15000);
        this.pending = {id, resolve, reject, timer};
        this.child.stdin.write(JSON.stringify({jsonrpc: '2.0', id, method, params}) + '\n');
      });
    } finally {release();}
  }
  notify(method) {
    if (this.closed) throw new Error('MCP closed');
    this.child.stdin.write(JSON.stringify({jsonrpc: '2.0', method}) + '\n');
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(new Error('MCP disconnected; effects unconfirmed'));
      this.pending = null;
    }
    this.buffer = '';
    this.child.stdin.end();
    this.child.kill();
  }
}
