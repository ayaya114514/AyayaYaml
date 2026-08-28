'use client';

import {
  Check,
  CircleAlert,
  Clipboard,
  ClipboardCheck,
  Download,
  FileInput,
  FileText,
  Network,
  RotateCcw,
  Trash2,
} from 'lucide-react';
import { useMemo, useRef, useState, type ChangeEvent, type CSSProperties } from 'react';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import {
  inspectMihomoYaml,
  parseProxyLinks,
  toMihomoYaml,
  toSingBoxJson,
  type MihomoProxyNode,
  type ParsedProxy,
} from '../lib/proxy';

const YAML_SAMPLE = `proxies:
  - name: Hong Kong 01
    type: vless
    server: hk.example.com
    port: 443

proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - Hong Kong 01`;

const VLESS_SAMPLE = 'vless://8133d14c-a942-4ce3-9424-13b9395fbf1d@82.139.194.56:443?encryption=none&security=reality&type=tcp&sni=elaon.de&fp=chrome&pbk=XSw3ExamplePublicKey&sid=f7d552&flow=xtls-rprx-vision#Reality%20Demo';

const MIHOMO_SAMPLE = `proxies:
  - name: Reality Demo
    type: vless
    server: 82.139.194.56
    port: 443
    uuid: 8133d14c-a942-4ce3-9424-13b9395fbf1d
    network: tcp
    tls: true
    servername: elaon.de
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: XSw3ExamplePublicKey
      short-id: f7d552
  - name: Hysteria Demo
    type: hysteria2
    server: hy.example.com
    port: 443
    password: demo-password`;

type ActiveTool = 'yaml' | 'proxy';
type SourceFormat = 'yaml' | 'json';
type ProxySource = 'share' | 'mihomo';
type ProxyView = 'details' | 'mihomo' | 'singbox' | 'share';

function parseStructuredText(input: string): { data: unknown; format: SourceFormat } {
  if (!input.trim()) throw new Error('请输入 YAML 或 JSON 内容');
  const looksLikeJson = /^[\s\r\n]*[\[{]/.test(input);

  if (looksLikeJson) {
    try {
      return { data: JSON.parse(input), format: 'json' };
    } catch {
      // JSON-shaped YAML can still be parsed as YAML.
    }
  }

  try {
    return { data: parseYaml(input), format: 'yaml' };
  } catch (error) {
    const message = error instanceof Error ? error.message.split('\n')[0] : '未知语法错误';
    throw new Error(message);
  }
}

function displayValue(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'string') return value || '""';
  return String(value);
}

function TreeNode({ value, label, depth = 0 }: { value: unknown; label?: string; depth?: number }) {
  if (value === null || typeof value !== 'object') {
    return (
      <div className="tree-leaf" style={{ '--tree-depth': depth } as CSSProperties}>
        {label !== undefined && <span className="tree-label">{label}</span>}
        <span className="tree-value">{displayValue(value)}</span>
      </div>
    );
  }

  const entries = Array.isArray(value)
    ? value.map((item, index) => [String(index), item] as const)
    : Object.entries(value as Record<string, unknown>);
  const visibleEntries = entries.slice(0, 100);

  return (
    <details className="tree-group" open={depth < 2} style={{ '--tree-depth': depth } as CSSProperties}>
      <summary>
        {label !== undefined && <span className="tree-label">{label}</span>}
        <span className="tree-kind">{Array.isArray(value) ? 'Array' : 'Object'}</span>
        <span className="tree-count">{entries.length}</span>
      </summary>
      <div className="tree-children">
        {visibleEntries.map(([key, item]) => (
          <TreeNode key={key} label={key} value={item} depth={depth + 1} />
        ))}
        {entries.length > visibleEntries.length && (
          <div className="tree-overflow">还有 {entries.length - visibleEntries.length} 项</div>
        )}
      </div>
    </details>
  );
}

function CopyButton({ value, label = '复制' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  }

  return (
    <button className="button" type="button" onClick={copy} disabled={!value}>
      {copied ? <ClipboardCheck size={14} /> : <Clipboard size={14} />}
      {copied ? '已复制' : label}
    </button>
  );
}

function ImportButton({ onImport, accept = '.yaml,.yml,.json' }: { onImport: (content: string, name: string) => void; accept?: string }) {
  const inputRef = useRef<HTMLInputElement>(null);

  async function readFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    onImport(await file.text(), file.name);
    event.target.value = '';
  }

  return (
    <>
      <button className="button" type="button" onClick={() => inputRef.current?.click()}>
        <FileInput size={14} /> 导入
      </button>
      <input ref={inputRef} className="visually-hidden" type="file" accept={accept} onChange={readFile} />
    </>
  );
}

function YamlStudio() {
  const [input, setInput] = useState(YAML_SAMPLE);
  const [fileName, setFileName] = useState('config.yaml');
  const [notice, setNotice] = useState('实时检查');
  const parsed = useMemo(() => {
    try {
      return { ...parseStructuredText(input), error: '' };
    } catch (error) {
      return {
        data: null,
        format: 'yaml' as SourceFormat,
        error: error instanceof Error ? error.message : '无法解析',
      };
    }
  }, [input]);

  function formatInput() {
    if (parsed.error) return;
    const formatted = parsed.format === 'json'
      ? JSON.stringify(parsed.data, null, 2)
      : stringifyYaml(parsed.data, { indent: 2, lineWidth: 0 });
    setInput(formatted.trimEnd());
    setNotice('已格式化');
  }

  function convertInput() {
    if (parsed.error) return;
    const nextFormat = parsed.format === 'yaml' ? 'json' : 'yaml';
    const next = nextFormat === 'json'
      ? JSON.stringify(parsed.data, null, 2)
      : stringifyYaml(parsed.data, { indent: 2, lineWidth: 0 }).trimEnd();
    setInput(next);
    setFileName(fileName.replace(/\.(ya?ml|json)$/i, `.${nextFormat}`));
    setNotice(`已转为 ${nextFormat.toUpperCase()}`);
  }

  function download() {
    const extension = parsed.format === 'json' ? 'json' : 'yaml';
    const blob = new Blob([input], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName.replace(/\.(ya?ml|json)$/i, `.${extension}`);
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="tool-surface">
      <div className="toolbar">
        <div className="toolbar-group">
          <ImportButton onImport={(content, name) => {
            setInput(content);
            setFileName(name);
            setNotice(`已导入 ${name}`);
          }} />
          <button className="button" type="button" onClick={formatInput} disabled={Boolean(parsed.error)}>格式化</button>
          <button className="button button-primary" type="button" onClick={convertInput} disabled={Boolean(parsed.error)}>
            转为 {parsed.format === 'yaml' ? 'JSON' : 'YAML'}
          </button>
        </div>
        <div className="toolbar-group compact-actions">
          <CopyButton value={input} />
          <button className="icon-button" type="button" onClick={download} aria-label="下载文件"><Download size={15} /></button>
          <button className="icon-button" type="button" onClick={() => { setInput(''); setFileName('config.yaml'); }} aria-label="清空"><Trash2 size={15} /></button>
        </div>
      </div>

      <div className="split-view">
        <section className="pane editor-pane">
          <div className="pane-heading">
            <span className="file-name"><FileText size={14} /> {fileName}</span>
            <span className="format-label">{parsed.format.toUpperCase()}</span>
          </div>
          <textarea
            className="text-editor"
            value={input}
            onChange={(event) => { setInput(event.target.value); setNotice('实时检查'); }}
            spellCheck={false}
            aria-label="YAML 或 JSON 编辑器"
            placeholder="粘贴内容，或导入 .yaml / .yml / .json 文件"
          />
        </section>

        <section className="pane preview-pane">
          <div className="pane-heading">
            <span>结构</span>
            <span className={parsed.error ? 'state state-error' : 'state'}>
              {parsed.error ? <CircleAlert size={13} /> : <Check size={13} />}
              {parsed.error ? '错误' : notice}
            </span>
          </div>
          <div className="tree-view">
            {parsed.error ? (
              <div className="message message-error">
                <CircleAlert size={17} />
                <div><strong>无法解析</strong><p>{parsed.error}</p></div>
              </div>
            ) : (
              <TreeNode value={parsed.data} label="root" />
            )}
          </div>
        </section>
      </div>

      <div className="statusbar">
        <span>{input.split(/\r?\n/).length} 行 · {new Blob([input]).size} bytes</span>
        <span>仅在浏览器本地处理</span>
      </div>
    </div>
  );
}

const FIELD_LABELS: Array<[keyof ParsedProxy, string]> = [
  ['uuid', 'UUID'],
  ['password', '密码'],
  ['transport', '传输'],
  ['security', '安全'],
  ['sni', 'SNI'],
  ['flow', 'Flow'],
  ['publicKey', 'PublicKey'],
  ['shortId', 'ShortID'],
  ['fingerprint', 'Fingerprint'],
  ['path', 'Path'],
  ['host', 'Host'],
  ['serviceName', 'ServiceName'],
];

interface ProxyDisplayNode {
  index: number;
  name: string;
  protocol: string;
  server?: string;
  port?: number;
  convertible: boolean;
  warning?: string;
  fields: Array<{ label: string; value: string }>;
}

function displayParsedProxy(proxy: ParsedProxy, index: number): ProxyDisplayNode {
  return {
    index,
    name: proxy.name,
    protocol: proxy.protocol,
    server: proxy.server,
    port: proxy.port,
    convertible: true,
    fields: FIELD_LABELS.flatMap(([key, label]) => {
      const value = proxy[key];
      return value === undefined || value === '' ? [] : [{ label, value: String(value) }];
    }),
  };
}

function displayMihomoProxy(node: MihomoProxyNode): ProxyDisplayNode {
  return {
    index: node.index,
    name: node.name,
    protocol: node.protocol,
    server: node.server,
    port: node.port,
    convertible: node.convertible,
    warning: node.warning,
    fields: node.fields,
  };
}

function ProxyDetails({ nodes }: { nodes: ProxyDisplayNode[] }) {
  return (
    <div className="proxy-list">
      {nodes.map((node) => (
        <article className={`node-card ${node.convertible ? '' : 'is-unsupported'}`} key={`${node.protocol}-${node.server}-${node.index}`}>
          <header className="node-header">
            <div className="node-title">
              <span className="protocol-badge">{node.protocol.toUpperCase()}</span>
              <div>
                <h3>{node.name}</h3>
                <p>{node.server ? `${node.server}${node.port ? `:${node.port}` : ''}` : '未提供服务器'}</p>
              </div>
            </div>
            <span className="node-number">{String(node.index + 1).padStart(2, '0')}</span>
          </header>
          {node.warning && <p className="node-warning"><CircleAlert size={13} /> {node.warning}</p>}
          <dl className="node-fields">
            {node.fields.map(({ label, value }) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </article>
      ))}
    </div>
  );
}

function ProxyStudio() {
  const [source, setSource] = useState<ProxySource>('share');
  const [input, setInput] = useState(VLESS_SAMPLE);
  const [fileName, setFileName] = useState('proxy-links.txt');
  const [view, setView] = useState<ProxyView>('details');

  const result = useMemo(() => {
    if (!input.trim()) return { proxies: [] as ParsedProxy[], nodes: [] as ProxyDisplayNode[], mihomo: '', singbox: '', share: '', unsupported: 0, error: '' };
    try {
      if (source === 'share') {
        const proxies = parseProxyLinks(input);
        return {
          proxies,
          nodes: proxies.map(displayParsedProxy),
          mihomo: toMihomoYaml(proxies),
          singbox: toSingBoxJson(proxies),
          share: '',
          unsupported: 0,
          error: '',
        };
      }
      const inspection = inspectMihomoYaml(input);
      return {
        proxies: inspection.nodes.flatMap((node) => node.parsed ? [node.parsed] : []),
        nodes: inspection.nodes.map(displayMihomoProxy),
        mihomo: '',
        singbox: '',
        share: inspection.shareLinks,
        unsupported: inspection.nodes.filter((node) => !node.convertible).length,
        error: '',
      };
    } catch (error) {
      return {
        proxies: [] as ParsedProxy[],
        nodes: [] as ProxyDisplayNode[],
        mihomo: '',
        singbox: '',
        share: '',
        unsupported: 0,
        error: error instanceof Error ? error.message : '无法解析',
      };
    }
  }, [input, source]);

  const output = view === 'mihomo'
    ? result.mihomo
    : view === 'singbox'
      ? result.singbox
      : view === 'share'
        ? result.share
        : source === 'mihomo' ? result.share : JSON.stringify(result.proxies, null, 2);
  const availableViews: Array<[ProxyView, string]> = source === 'share'
    ? [['details', '节点'], ['mihomo', 'Mihomo'], ['singbox', 'sing-box']]
    : [['details', '节点'], ['share', '分享链接']];

  function changeSource(next: ProxySource) {
    setSource(next);
    setInput(next === 'share' ? VLESS_SAMPLE : MIHOMO_SAMPLE);
    setFileName(next === 'share' ? 'proxy-links.txt' : 'mihomo.yaml');
    setView('details');
  }

  return (
    <div className="tool-surface">
      <div className="toolbar proxy-toolbar">
        <div className="segmented" role="group" aria-label="输入类型">
          <button className={source === 'share' ? 'is-active' : ''} type="button" onClick={() => changeSource('share')}>分享链接</button>
          <button className={source === 'mihomo' ? 'is-active' : ''} type="button" onClick={() => changeSource('mihomo')}>YAML</button>
        </div>
        <div className="toolbar-group compact-actions">
          {source === 'mihomo' && (
            <ImportButton accept=".yaml,.yml" onImport={(content, name) => { setInput(content); setFileName(name); }} />
          )}
          <button className="icon-button" type="button" onClick={() => changeSource(source)} aria-label="恢复示例"><RotateCcw size={15} /></button>
          <CopyButton value={output} label="复制结果" />
          <button className="icon-button" type="button" onClick={() => setInput('')} aria-label="清空"><Trash2 size={15} /></button>
        </div>
      </div>

      <div className="split-view proxy-split">
        <section className="pane editor-pane">
          <div className="pane-heading">
            <span className="file-name"><FileText size={14} /> {fileName}</span>
            <span className="format-label">{source === 'share' ? 'LINK' : 'YAML'}</span>
          </div>
          <textarea
            className="text-editor proxy-editor"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder={source === 'share' ? '每行粘贴一个代理分享链接' : '粘贴或导入包含 proxies 的 Mihomo YAML'}
            spellCheck={false}
            aria-label={source === 'share' ? '代理分享链接输入' : 'Mihomo YAML 输入'}
          />
        </section>

        <section className="pane preview-pane">
          <div className="pane-heading result-heading">
            <div className="result-tabs" role="tablist" aria-label="解析结果">
              {availableViews.map(([key, label]) => (
                <button key={key} className={view === key ? 'is-active' : ''} type="button" onClick={() => setView(key)}>{label}</button>
              ))}
            </div>
            {!result.error && input.trim() && <span className="state"><Check size={13} /> Ready</span>}
          </div>
          <div className="proxy-output">
            {!input.trim() ? (
              <div className="empty-state"><Network size={22} /><p>粘贴链接或导入 YAML</p></div>
            ) : result.error ? (
              <div className="message message-error">
                <CircleAlert size={17} />
                <div><strong>无法解析</strong><p>{result.error}</p></div>
              </div>
            ) : view === 'details' ? (
              <ProxyDetails nodes={result.nodes} />
            ) : (
              <pre className="conversion-output"><code>{output}</code></pre>
            )}
          </div>
        </section>
      </div>

      <div className="statusbar">
        <span>{result.error ? result.error : source === 'share'
          ? `${result.proxies.length} 个节点`
          : `${result.nodes.length} 个节点 · ${result.nodes.length - result.unsupported} 可转换${result.unsupported ? ` · ${result.unsupported} 暂不支持` : ''}`}</span>
        <span>仅在浏览器本地处理</span>
      </div>
    </div>
  );
}

export default function Home() {
  const [activeTool, setActiveTool] = useState<ActiveTool>('yaml');

  return (
    <main className="app-shell">
      <header className="app-header">
        <div className="brand" aria-label="AyayaYaml">
          <span className="brand-mark" aria-hidden="true">AY</span>
          <span>AyayaYaml</span>
        </div>
        <span className="local-note">Local only</span>
      </header>

      <div className="app-tabs" role="tablist" aria-label="工具选择">
        <button className={activeTool === 'yaml' ? 'is-active' : ''} type="button" role="tab" aria-selected={activeTool === 'yaml'} onClick={() => setActiveTool('yaml')}>YAML</button>
        <button className={activeTool === 'proxy' ? 'is-active' : ''} type="button" role="tab" aria-selected={activeTool === 'proxy'} onClick={() => setActiveTool('proxy')}>Proxy</button>
      </div>

      <section className="workspace" aria-label={activeTool === 'yaml' ? 'YAML 工作区' : 'Proxy 工作区'}>
        {activeTool === 'yaml' ? <YamlStudio /> : <ProxyStudio />}
      </section>
    </main>
  );
}
