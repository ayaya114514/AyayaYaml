'use client';

import { useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from 'react';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import {
  inspectMihomoYaml,
  inspectProxyLinks,
  toMihomoYaml,
  toSingBoxJson,
  type MihomoProxyNode,
  type ParsedProxy,
  type ProxyLinkInspectionNode,
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

// Documentation-only addresses (RFC 5737) so the samples never point at a real server.
const LINK_SAMPLE = [
  'vless://0b6f3c1e-5d2a-4c8e-9f41-7a2d6e9b3c10@203.0.113.10:443?encryption=none&security=reality&type=tcp&sni=www.example.com&fp=chrome&pbk=ExamplePublicKey&sid=f7d552&flow=xtls-rprx-vision#Reality%20Demo',
  'trojan://example-password@198.51.100.20:443?type=ws&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#Trojan%20WS',
].join('\n');

const MIHOMO_SAMPLE = `proxies:
  - name: Reality Demo
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: 0b6f3c1e-5d2a-4c8e-9f41-7a2d6e9b3c10
    network: tcp
    tls: true
    servername: www.example.com
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: ExamplePublicKey
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

const PROXY_SAMPLES: Record<ProxySource, string> = { share: LINK_SAMPLE, mihomo: MIHOMO_SAMPLE };

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

function formatBytes(size: number): string {
  return size < 1024 ? `${size} B` : `${(size / 1024).toFixed(1)} KB`;
}

function downloadText(fileName: string, text: string) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function writeClipboard(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch {
    // Clipboard API is unavailable on insecure origins or when permission is denied.
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  textarea.remove();
  if (!copied) throw new Error('copy failed');
}

function leafClass(value: unknown): string {
  if (value === null || value === undefined) return 'is-null';
  if (typeof value === 'string') return 'is-string';
  return 'is-literal';
}

function leafText(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'string') return value === '' ? '""' : value;
  return String(value);
}

const TREE_PAGE = 100;

function TreeNode({ value, label, depth = 0 }: { value: unknown; label?: string; depth?: number }) {
  const [limit, setLimit] = useState(TREE_PAGE);

  if (value === null || typeof value !== 'object') {
    return (
      <div className="tree-leaf">
        {label !== undefined && <span className="tree-key">{label}</span>}
        <span className={`tree-value ${leafClass(value)}`}>{leafText(value)}</span>
      </div>
    );
  }

  const isArray = Array.isArray(value);
  const entries = isArray
    ? value.map((item, index) => [String(index), item] as const)
    : Object.entries(value as Record<string, unknown>);

  return (
    <details className="tree-group" open={depth < 4}>
      <summary>
        {label !== undefined && <span className="tree-key">{label}</span>}
        <span className="tree-count">{isArray ? `[${entries.length}]` : `{${entries.length}}`}</span>
      </summary>
      <div className="tree-children">
        {entries.slice(0, limit).map(([key, item]) => (
          <TreeNode key={key} label={key} value={item} depth={depth + 1} />
        ))}
        {entries.length > limit && (
          <button className="tree-more" type="button" onClick={() => setLimit(entries.length)}>
            显示剩余 {entries.length - limit} 项
          </button>
        )}
      </div>
    </details>
  );
}

function CopyButton({ value, label = '复制', className = 'act' }: { value: string; label?: string; className?: string }) {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle');
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  async function copy() {
    try {
      await writeClipboard(value);
      setState('done');
    } catch {
      setState('failed');
    }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState('idle'), 1600);
  }

  return (
    <button className={className} type="button" onClick={copy} disabled={!value} aria-live="polite">
      {state === 'done' ? '已复制' : state === 'failed' ? '复制失败' : label}
    </button>
  );
}

function ImportButton({ onImport, accept }: { onImport: (content: string, name: string) => void; accept: string }) {
  const inputRef = useRef<HTMLInputElement>(null);

  async function readFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    onImport(await file.text(), file.name);
    event.target.value = '';
  }

  return (
    <>
      <button className="act" type="button" onClick={() => inputRef.current?.click()}>导入</button>
      <input ref={inputRef} className="visually-hidden" type="file" name="import-file" accept={accept} onChange={readFile} tabIndex={-1} />
    </>
  );
}

function Column({ bar, children, className = '' }: { bar: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`column ${className}`}>
      <div className="bar">{bar}</div>
      <div className="surface">{children}</div>
    </div>
  );
}

function YamlStudio() {
  const [input, setInput] = useState(YAML_SAMPLE);
  const [fileName, setFileName] = useState('config.yaml');
  const parsed = useMemo(() => {
    try {
      return { ...parseStructuredText(input), error: '' };
    } catch (error) {
      return {
        data: null,
        format: (/^\s*[\[{]/.test(input) ? 'json' : 'yaml') as SourceFormat,
        error: error instanceof Error ? error.message : '无法解析',
      };
    }
  }, [input]);
  const isEmpty = !input.trim();
  const nextFormat = parsed.format === 'yaml' ? 'json' : 'yaml';

  function serialize(format: SourceFormat): string {
    return format === 'json'
      ? JSON.stringify(parsed.data, null, 2)
      : stringifyYaml(parsed.data, { indent: 2, lineWidth: 0 }).trimEnd();
  }

  function convert() {
    if (parsed.error) return;
    setInput(serialize(nextFormat));
    setFileName(fileName.replace(/\.(ya?ml|json)$/i, '') + (nextFormat === 'json' ? '.json' : '.yaml'));
  }

  return (
    <div className="studio">
      <Column bar={(
        <>
          <span className="meta">
            <span className="meta-file">{fileName}</span>
            <span>{input.split(/\r?\n/).length} 行 · {formatBytes(new Blob([input]).size)}</span>
          </span>
          <span className="bar-actions">
            <ImportButton accept=".yaml,.yml,.json" onImport={(content, name) => { setInput(content); setFileName(name); }} />
            <button className="act" type="button" disabled={isEmpty} onClick={() => downloadText(fileName, input)}>下载</button>
            <CopyButton value={input} />
            <button className="act act-quiet" type="button" disabled={isEmpty} onClick={() => { setInput(''); setFileName('config.yaml'); }}>清空</button>
          </span>
        </>
      )}>
        <textarea
          className="editor"
          name="structured-text"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          spellCheck={false}
          aria-label="YAML 或 JSON 编辑器"
          placeholder="粘贴 YAML / JSON，或导入 .yaml / .yml / .json 文件"
        />
      </Column>

      <Column className="column-output" bar={(
        <>
          <span className={`meta ${parsed.error && !isEmpty ? 'meta-error' : ''}`} role="status">
            {isEmpty ? '等待输入' : parsed.error ? `${parsed.format.toUpperCase()} 语法错误` : `${parsed.format.toUpperCase()} · 语法正确`}
          </span>
          <span className="bar-actions">
            <button className="act" type="button" disabled={Boolean(parsed.error)} onClick={() => setInput(serialize(parsed.format))}>格式化</button>
            <button className="act act-primary" type="button" disabled={Boolean(parsed.error)} onClick={convert}>
              转为 {nextFormat.toUpperCase()}
            </button>
          </span>
        </>
      )}>
        <div className="scroll tree-view">
          {isEmpty ? (
            <p className="placeholder">结构会显示在这里</p>
          ) : parsed.error ? (
            <p className="error-text">{parsed.error}</p>
          ) : (
            <TreeNode value={parsed.data} />
          )}
        </div>
      </Column>
    </div>
  );
}

const FIELD_LABELS: Array<[keyof ParsedProxy, string]> = [
  ['uuid', 'UUID'],
  ['password', '密码'],
  ['sni', 'SNI'],
  ['flow', 'Flow'],
  ['publicKey', 'PublicKey'],
  ['shortId', 'ShortID'],
  ['fingerprint', 'Fingerprint'],
  ['path', 'Path'],
  ['host', 'Host'],
  ['serviceName', 'ServiceName'],
  ['alpn', 'ALPN'],
  ['skipCertVerify', '跳过证书验证'],
  ['encryption', '加密'],
  ['plugin', '插件'],
  ['pluginOpts', '插件参数'],
];

interface ProxyDisplayNode {
  key: string;
  name: string;
  tags: string[];
  address?: string;
  convertible: boolean;
  warning?: string;
  fields: Array<{ label: string; value: string }>;
}

function formatAddress(server?: string, port?: number): string | undefined {
  if (!server) return undefined;
  const host = server.includes(':') ? `[${server}]` : server;
  return port ? `${host}:${port}` : host;
}

function displayParsedProxy(proxy: ParsedProxy, index: number): ProxyDisplayNode {
  return {
    key: `link-${index}`,
    name: proxy.name,
    tags: [proxy.protocol, proxy.security, proxy.transport].filter((tag) => tag && tag !== 'none'),
    address: formatAddress(proxy.server, proxy.port),
    convertible: true,
    fields: FIELD_LABELS.flatMap(([key, label]) => {
      const value = proxy[key];
      if (value === undefined || value === '' || (key === 'encryption' && value === 'none')) return [];
      return [{ label, value: Array.isArray(value) ? value.join(', ') : value === true ? '是' : String(value) }];
    }),
  };
}

function displayProxyLink(node: ProxyLinkInspectionNode): ProxyDisplayNode {
  if (node.parsed) return displayParsedProxy(node.parsed, node.index);
  const protocol = node.raw.match(/^([a-z0-9+.-]+):\/\//i)?.[1].toLowerCase();
  return {
    key: `link-${node.index}`,
    name: `第 ${node.lineNumber} 行`,
    tags: protocol ? [protocol] : [],
    convertible: false,
    warning: node.warning,
    fields: [{ label: '原始内容', value: node.raw }],
  };
}

function displayMihomoProxy(node: MihomoProxyNode): ProxyDisplayNode {
  return {
    key: `mihomo-${node.index}`,
    name: node.name,
    tags: [node.protocol],
    address: formatAddress(node.server, node.port),
    convertible: node.convertible,
    warning: node.warning,
    fields: node.fields,
  };
}

function NodeList({ nodes }: { nodes: ProxyDisplayNode[] }) {
  return (
    <ol className="nodes">
      {nodes.map((node) => (
        <li className={node.convertible ? 'node' : 'node is-bad'} key={node.key}>
          <div className="node-head">
            <span className="node-name">{node.name}</span>
            {node.tags.length > 0 && <span className="node-tags">{node.tags.join(' · ')}</span>}
          </div>
          {node.address && <div className="node-address">{node.address}</div>}
          {node.warning && <p className="node-warning">{node.warning}</p>}
          {node.fields.length > 0 && (
            <dl className="kv">
              {node.fields.map(({ label, value }) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          )}
        </li>
      ))}
    </ol>
  );
}

interface ProxyResult {
  nodes: ProxyDisplayNode[];
  convertible: number;
  outputs: Partial<Record<ProxyView, string>>;
  notes: string[];
  error: string;
}

function inspectProxyInput(input: string, source: ProxySource): ProxyResult {
  if (!input.trim()) return { nodes: [], convertible: 0, outputs: {}, notes: [], error: '' };
  try {
    if (source === 'share') {
      const inspection = inspectProxyLinks(input);
      const { proxies } = inspection;
      const skipped = inspection.nodes.length - proxies.length;
      const duplicates = proxies.length - new Set(proxies.map((proxy) => proxy.name)).size;
      return {
        nodes: inspection.nodes.map(displayProxyLink),
        convertible: proxies.length,
        outputs: proxies.length ? { mihomo: toMihomoYaml(proxies), singbox: toSingBoxJson(proxies) } : {},
        notes: [
          inspection.base64 ? '已解码 Base64 订阅' : '',
          skipped ? `${skipped} 条无法解析，已跳过` : '',
          duplicates ? `${duplicates} 个重名节点，输出时自动编号` : '',
        ].filter(Boolean),
        error: '',
      };
    }
    const inspection = inspectMihomoYaml(input);
    const skipped = inspection.nodes.filter((node) => !node.convertible).length;
    return {
      nodes: inspection.nodes.map(displayMihomoProxy),
      convertible: inspection.nodes.length - skipped,
      outputs: inspection.shareLinks ? { share: inspection.shareLinks } : {},
      notes: skipped ? [`${skipped} 个节点暂不支持，已跳过`] : [],
      error: '',
    };
  } catch (error) {
    return { nodes: [], convertible: 0, outputs: {}, notes: [], error: error instanceof Error ? error.message : '无法解析' };
  }
}

const VIEW_LABELS: Record<ProxyView, string> = {
  details: '节点',
  mihomo: 'Mihomo',
  singbox: 'sing-box',
  share: '分享链接',
};

function ProxyStudio() {
  const [source, setSource] = useState<ProxySource>('share');
  const [inputs, setInputs] = useState<Record<ProxySource, string>>(PROXY_SAMPLES);
  const [view, setView] = useState<ProxyView>('details');
  const input = inputs[source];
  const result = useMemo(() => inspectProxyInput(input, source), [input, source]);

  const views: ProxyView[] = source === 'share' ? ['details', 'mihomo', 'singbox'] : ['details', 'share'];
  const activeView = views.includes(view) ? view : 'details';
  const output = activeView === 'details' ? '' : result.outputs[activeView] ?? '';
  const outputFile = activeView === 'mihomo' ? 'mihomo.yaml' : activeView === 'singbox' ? 'sing-box.json' : 'proxy-links.txt';

  function setInput(value: string) {
    setInputs((current) => ({ ...current, [source]: value }));
  }

  return (
    <div className="studio">
      <Column bar={(
        <>
          <div className="seg" role="radiogroup" aria-label="输入类型">
            {(['share', 'mihomo'] as const).map((key) => (
              <button key={key} type="button" role="radio" aria-checked={source === key} className={source === key ? 'is-active' : ''} onClick={() => setSource(key)}>
                {key === 'share' ? '分享链接' : 'Mihomo YAML'}
              </button>
            ))}
          </div>
          <span className="bar-actions">
            <ImportButton accept={source === 'share' ? '.txt,.conf,.list' : '.yaml,.yml'} onImport={(content) => setInput(content)} />
            <button className="act" type="button" disabled={input === PROXY_SAMPLES[source]} onClick={() => setInput(PROXY_SAMPLES[source])}>示例</button>
            <button className="act act-quiet" type="button" disabled={!input} onClick={() => setInput('')}>清空</button>
          </span>
        </>
      )}>
        <textarea
          className="editor editor-links"
          name="proxy-input"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder={source === 'share' ? '每行一个分享链接，也可以直接粘贴 Base64 订阅内容' : '粘贴或导入包含 proxies 的 Mihomo YAML'}
          spellCheck={false}
          aria-label={source === 'share' ? '代理分享链接输入' : 'Mihomo YAML 输入'}
        />
      </Column>

      <Column className="column-output" bar={(
        <>
          <div className="views" role="tablist" aria-label="输出格式">
            {views.map((key) => (
              <button key={key} type="button" role="tab" aria-selected={activeView === key} className={activeView === key ? 'is-active' : ''} onClick={() => setView(key)}>
                {VIEW_LABELS[key]}
                {key === 'details' && result.nodes.length > 0 && <span className="count">{result.nodes.length}</span>}
              </button>
            ))}
          </div>
          {activeView !== 'details' && (
            <span className="bar-actions">
              <button className="act" type="button" disabled={!output} onClick={() => downloadText(outputFile, output)}>下载</button>
              <CopyButton value={output} className="act act-primary" />
            </span>
          )}
        </>
      )}>
        <div className="scroll" role="tabpanel" aria-label={VIEW_LABELS[activeView]}>
          {!input.trim() ? (
            <p className="placeholder">{source === 'share' ? '粘贴分享链接后，这里会列出每个节点' : '粘贴 Mihomo YAML 后，这里会列出每个节点'}</p>
          ) : result.error ? (
            <p className="error-text">{result.error}</p>
          ) : (
            <>
              {result.notes.length > 0 && <p className="notes">{result.notes.join(' · ')}</p>}
              {activeView === 'details' ? (
                <NodeList nodes={result.nodes} />
              ) : output ? (
                <pre className="code"><code>{output}</code></pre>
              ) : (
                <p className="placeholder">没有可转换的节点</p>
              )}
            </>
          )}
        </div>
      </Column>
    </div>
  );
}

export default function Home() {
  const [activeTool, setActiveTool] = useState<ActiveTool>('yaml');
  const tools: Array<[ActiveTool, string]> = [['yaml', 'YAML / JSON'], ['proxy', '代理链接']];

  return (
    <main className="app">
      <header className="intro">
        <h1 className="brand"><span className="brand-mark" aria-hidden="true">AY</span>AyayaYaml</h1>
        <div className="tools" role="tablist" aria-label="工具">
          {tools.map(([key, label]) => (
            <button
              key={key}
              id={`tab-${key}`}
              type="button"
              role="tab"
              aria-selected={activeTool === key}
              aria-controls={`panel-${key}`}
              className={activeTool === key ? 'is-active' : ''}
              onClick={() => setActiveTool(key)}
            >
              {label}
            </button>
          ))}
        </div>
        <p className="lede">YAML、JSON 与代理分享链接互转。<strong>所有内容只在浏览器本地解析，不会上传。</strong></p>
      </header>

      {/* Keep both tools mounted so switching tabs never discards what was pasted. */}
      {tools.map(([key]) => (
        <section key={key} id={`panel-${key}`} role="tabpanel" aria-labelledby={`tab-${key}`} hidden={activeTool !== key}>
          {key === 'yaml' ? <YamlStudio /> : <ProxyStudio />}
        </section>
      ))}
    </main>
  );
}
