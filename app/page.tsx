'use client';

import {
  Fragment,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type ReactNode,
} from 'react';
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
type CodeLanguage = 'yaml' | 'json' | 'links';

const PROXY_SAMPLES: Record<ProxySource, string> = { share: LINK_SAMPLE, mihomo: MIHOMO_SAMPLE };

// Editor rows are a fixed height so the gutter and error bands line up with the textarea.
const ROW_HEIGHT = 20;
const EDITOR_PAD = 12;

interface StructuredParse {
  data: unknown;
  format: SourceFormat;
  error: string;
  errorLine?: number;
}

function parseStructuredText(input: string): StructuredParse {
  const looksLikeJson = /^[\s\r\n]*[\[{]/.test(input);
  if (!input.trim()) return { data: null, format: 'yaml', error: '' };

  if (looksLikeJson) {
    try {
      return { data: JSON.parse(input), format: 'json', error: '' };
    } catch {
      // JSON-shaped YAML can still be parsed as YAML.
    }
  }

  try {
    return { data: parseYaml(input), format: 'yaml', error: '' };
  } catch (error) {
    const message = error instanceof Error ? error.message.split('\n')[0] : '未知语法错误';
    const errorLine = (error as { linePos?: Array<{ line: number }> }).linePos?.[0]?.line;
    return { data: null, format: looksLikeJson ? 'json' : 'yaml', error: message, errorLine };
  }
}

function formatBytes(size: number): string {
  return size < 1024 ? `${size} B` : `${(size / 1024).toFixed(1)} KB`;
}

function countLines(text: string): number {
  let lines = 1;
  for (let index = text.indexOf('\n'); index !== -1; index = text.indexOf('\n', index + 1)) lines += 1;
  return lines;
}

function lineNumbers(count: number): string {
  return Array.from({ length: count }, (_, index) => index + 1).join('\n');
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

const LITERAL = /^(-?\d+(\.\d+)?([eE][+-]?\d+)?|true|false|null|~)$/;

function valueToken(raw: string, key: string | number): ReactNode {
  const value = raw.trim().replace(/,$/, '');
  if (!value || /^[{}[\],]+$/.test(value)) return <span key={key} className="t-dim">{raw}</span>;
  if (value.startsWith('#')) return <span key={key} className="t-com">{raw}</span>;
  if (LITERAL.test(value)) return <span key={key} className="t-lit">{raw}</span>;
  return <span key={key} className="t-str">{raw}</span>;
}

// A deliberately small highlighter: keys, scalars and comments are enough to scan output.
function highlightLine(line: string, language: CodeLanguage): ReactNode {
  if (language === 'links') {
    const match = line.match(/^([a-z][a-z0-9+.-]*:\/\/)([^#]*)(#.*)?$/i);
    if (!match) return line;
    return [
      <span key="s" className="t-key">{match[1]}</span>,
      <span key="b" className="t-dim">{match[2]}</span>,
      match[3] ? <span key="f" className="t-str">{match[3]}</span> : null,
    ];
  }

  if (language === 'json') {
    const match = line.match(/^(\s*)("(?:[^"\\]|\\.)*")(\s*:)(.*)$/);
    if (!match) return valueToken(line, 'v');
    return [match[1], <span key="k" className="t-key">{match[2]}</span>, <span key="c" className="t-dim">{match[3]}</span>, valueToken(match[4], 'v')];
  }

  if (/^\s*#/.test(line)) return <span className="t-com">{line}</span>;
  const pair = line.match(/^(\s*(?:-\s+)*)("[^"]*"|'[^']*'|[^\s#'"][^#]*?)(:)(\s.*|)$/);
  if (pair) return [pair[1], <span key="k" className="t-key">{pair[2]}</span>, <span key="c" className="t-dim">{pair[3]}</span>, valueToken(pair[4], 'v')];
  const item = line.match(/^(\s*-\s+)(.*)$/);
  if (item) return [item[1], valueToken(item[2], 'v')];
  return line;
}

function CodeEditor({ value, onChange, marks = [], label, placeholder, name }: {
  value: string;
  onChange: (value: string) => void;
  marks?: number[];
  label: string;
  placeholder: string;
  name: string;
}) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const bandsRef = useRef<HTMLDivElement>(null);
  const numbers = useMemo(() => lineNumbers(countLines(value)), [value]);

  const syncScroll = useCallback(() => {
    const offset = `translateY(${-(textareaRef.current?.scrollTop ?? 0)}px)`;
    if (gutterRef.current) gutterRef.current.style.transform = offset;
    if (bandsRef.current) bandsRef.current.style.transform = offset;
  }, []);

  // Replacing the value (sample, clear, import) can clamp scrollTop without a scroll event.
  useLayoutEffect(syncScroll, [value, syncScroll]);

  return (
    <div className="code-editor">
      <div className="gutter" aria-hidden="true">
        <div className="gutter-track" ref={gutterRef}>
          <pre className="gutter-numbers">{numbers}</pre>
          {marks.map((line) => (
            <span key={line} className="gutter-mark" style={{ top: EDITOR_PAD + (line - 1) * ROW_HEIGHT }}>{line}</span>
          ))}
        </div>
      </div>
      <div className="editor-field">
        <div className="bands" aria-hidden="true">
          <div ref={bandsRef}>
            {marks.map((line) => (
              <span key={line} className="band" style={{ top: EDITOR_PAD + (line - 1) * ROW_HEIGHT }} />
            ))}
          </div>
        </div>
        <textarea
          ref={textareaRef}
          className="editor"
          name={name}
          value={value}
          wrap="off"
          onChange={(event) => onChange(event.target.value)}
          onScroll={syncScroll}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          aria-label={label}
          placeholder={placeholder}
        />
      </div>
    </div>
  );
}

function CodeView({ text, language }: { text: string; language: CodeLanguage }) {
  const lines = useMemo(() => text.split('\n'), [text]);
  return (
    <div className="code-view">
      <pre className="code-gutter" aria-hidden="true">{lineNumbers(lines.length)}</pre>
      <pre className="code">
        <code>
          {lines.map((line, index) => (
            <Fragment key={index}>
              {highlightLine(line, language)}
              {index < lines.length - 1 ? '\n' : ''}
            </Fragment>
          ))}
        </code>
      </pre>
    </div>
  );
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
        {label !== undefined && <span className={isArray || !/^\d+$/.test(label) ? 'tree-key' : 'tree-key is-index'}>{label}</span>}
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

function Pane({ tabs, actions, children, className = '' }: { tabs: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`pane ${className}`}>
      <div className="pane-head">
        <div className="pane-tabs">{tabs}</div>
        {actions && <div className="pane-actions">{actions}</div>}
      </div>
      <div className="pane-body">{children}</div>
    </div>
  );
}

interface StatusItem {
  text: string;
  tone?: 'ok' | 'error';
}

function StatusBar({ items }: { items: StatusItem[] }) {
  const [main, ...rest] = items;
  return (
    <footer className="statusbar">
      <span className={`status-item ${main.tone ? `is-${main.tone}` : ''}`} role="status">{main.text}</span>
      {rest.map((item) => (
        <span key={item.text} className={`status-item ${item.tone ? `is-${item.tone}` : ''}`}>{item.text}</span>
      ))}
    </footer>
  );
}

function YamlStudio() {
  const [input, setInput] = useState(YAML_SAMPLE);
  const [fileName, setFileName] = useState('config.yaml');
  const parsed = useMemo(() => parseStructuredText(input), [input]);
  const isEmpty = !input.trim();
  const nextFormat = parsed.format === 'yaml' ? 'json' : 'yaml';
  const formatLabel = parsed.format.toUpperCase();

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

  const status: StatusItem = isEmpty
    ? { text: '等待输入' }
    : parsed.error
      ? { text: `${formatLabel} 语法错误${parsed.errorLine ? ` · 第 ${parsed.errorLine} 行` : ''}`, tone: 'error' }
      : { text: `${formatLabel} 语法正确`, tone: 'ok' };

  return (
    <div className="studio">
      <div className="panes">
        <Pane
          className="pane-in"
          tabs={<span className="tab is-active" title={fileName}><span className="tab-label">{fileName}</span></span>}
          actions={(
            <>
              <ImportButton accept=".yaml,.yml,.json" onImport={(content, name) => { setInput(content); setFileName(name); }} />
              <button className="act" type="button" disabled={isEmpty} onClick={() => downloadText(fileName, input)}>下载</button>
              <CopyButton value={input} />
              <button className="act act-quiet" type="button" disabled={isEmpty} onClick={() => { setInput(''); setFileName('config.yaml'); }}>清空</button>
            </>
          )}
        >
          <CodeEditor
            name="structured-text"
            value={input}
            onChange={setInput}
            marks={parsed.errorLine ? [parsed.errorLine] : []}
            label="YAML 或 JSON 编辑器"
            placeholder="粘贴 YAML / JSON，或点“导入”"
          />
        </Pane>

        <Pane
          className="pane-out"
          tabs={<span className="tab is-active">结构</span>}
          actions={(
            <>
              <button className="act" type="button" disabled={isEmpty || Boolean(parsed.error)} onClick={() => setInput(serialize(parsed.format))}>格式化</button>
              <button className="act act-primary" type="button" disabled={isEmpty || Boolean(parsed.error)} onClick={convert}>
                转为 {nextFormat.toUpperCase()}
              </button>
            </>
          )}
        >
          <div className="scroll tree-view">
            {isEmpty ? (
              <p className="placeholder">结构会显示在这里</p>
            ) : parsed.error ? (
              <p className="error-text">
                {parsed.errorLine && <span className="error-line">第 {parsed.errorLine} 行</span>}
                {parsed.error}
              </p>
            ) : (
              <TreeNode value={parsed.data} />
            )}
          </div>
        </Pane>
      </div>

      <StatusBar items={[status, { text: `${countLines(input)} 行` }, { text: formatBytes(new Blob([input]).size) }]} />
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
  marker: string;
  name: string;
  type: string;
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

function displayParsedProxy(proxy: ParsedProxy, index: number, marker: string): ProxyDisplayNode {
  return {
    key: `link-${index}`,
    marker,
    name: proxy.name,
    type: [proxy.protocol, proxy.security, proxy.transport].filter((tag) => tag && tag !== 'none').join(' / '),
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
  const marker = String(node.lineNumber);
  if (node.parsed) return displayParsedProxy(node.parsed, node.index, marker);
  const protocol = node.raw.match(/^([a-z0-9+.-]+):\/\//i)?.[1].toLowerCase();
  return {
    key: `link-${node.index}`,
    marker,
    name: `第 ${node.lineNumber} 行`,
    type: protocol ?? '未知',
    convertible: false,
    warning: node.warning,
    fields: [{ label: '原始内容', value: node.raw }],
  };
}

function displayMihomoProxy(node: MihomoProxyNode): ProxyDisplayNode {
  return {
    key: `mihomo-${node.index}`,
    marker: String(node.index + 1),
    name: node.name,
    type: node.protocol,
    address: formatAddress(node.server, node.port),
    convertible: node.convertible,
    warning: node.warning,
    fields: node.fields,
  };
}

function NodeTable({ nodes, markerLabel }: { nodes: ProxyDisplayNode[]; markerLabel: string }) {
  const openByDefault = nodes.length <= 6;
  return (
    <div className="node-table">
      <div className="node-cols node-head" aria-hidden="true">
        <span>{markerLabel}</span>
        <span>名称</span>
        <span>类型</span>
        <span>地址</span>
      </div>
      <ol>
        {nodes.map((node) => (
          <li key={node.key}>
            <details className={node.convertible ? 'node' : 'node is-bad'} open={openByDefault || !node.convertible}>
              <summary className="node-cols">
                <span className="node-marker">{node.marker}</span>
                <span className="node-name">{node.name}</span>
                <span className="node-type">{node.type}</span>
                <span className={node.address ? 'node-address' : 'node-address is-empty'}>{node.address ?? '—'}</span>
              </summary>
              <div className="node-body">
                {node.warning && <p className="node-warning">{node.warning}</p>}
                {node.fields.length > 0 && (
                  <dl className="kv">
                    {node.fields.map(({ label, value }) => (
                      <Fragment key={label}>
                        <dt>{label}</dt>
                        <dd>{value}</dd>
                      </Fragment>
                    ))}
                  </dl>
                )}
              </div>
            </details>
          </li>
        ))}
      </ol>
    </div>
  );
}

interface ProxyResult {
  nodes: ProxyDisplayNode[];
  convertible: number;
  outputs: Partial<Record<ProxyView, string>>;
  notes: string[];
  badLines: number[];
  error: string;
}

function inspectProxyInput(input: string, source: ProxySource): ProxyResult {
  const empty: ProxyResult = { nodes: [], convertible: 0, outputs: {}, notes: [], badLines: [], error: '' };
  if (!input.trim()) return empty;
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
        // Line numbers of a decoded Base64 subscription don't map onto the editor.
        badLines: inspection.base64 ? [] : inspection.nodes.filter((node) => !node.parsed).map((node) => node.lineNumber),
        error: '',
      };
    }
    const inspection = inspectMihomoYaml(input);
    const skipped = inspection.nodes.filter((node) => !node.convertible).length;
    return {
      ...empty,
      nodes: inspection.nodes.map(displayMihomoProxy),
      convertible: inspection.nodes.length - skipped,
      outputs: inspection.shareLinks ? { share: inspection.shareLinks } : {},
      notes: skipped ? [`${skipped} 个节点暂不支持，已跳过`] : [],
    };
  } catch (error) {
    return { ...empty, error: error instanceof Error ? error.message : '无法解析' };
  }
}

const VIEW_LABELS: Record<ProxyView, string> = {
  details: '节点',
  mihomo: 'Mihomo',
  singbox: 'sing-box',
  share: '分享链接',
};

const VIEW_FILES: Record<Exclude<ProxyView, 'details'>, [string, CodeLanguage]> = {
  mihomo: ['mihomo.yaml', 'yaml'],
  singbox: ['sing-box.json', 'json'],
  share: ['proxy-links.txt', 'links'],
};

function ProxyStudio() {
  const [source, setSource] = useState<ProxySource>('share');
  const [inputs, setInputs] = useState<Record<ProxySource, string>>(PROXY_SAMPLES);
  const [view, setView] = useState<ProxyView>('details');
  const input = inputs[source];
  const isEmpty = !input.trim();
  const result = useMemo(() => inspectProxyInput(input, source), [input, source]);

  const views: ProxyView[] = source === 'share' ? ['details', 'mihomo', 'singbox'] : ['details', 'share'];
  const activeView = views.includes(view) ? view : 'details';
  const output = activeView === 'details' ? '' : result.outputs[activeView] ?? '';
  const [outputFile, outputLanguage] = activeView === 'details' ? ['', 'links' as const] : VIEW_FILES[activeView];

  function setInput(value: string) {
    setInputs((current) => ({ ...current, [source]: value }));
  }

  const status: StatusItem = isEmpty
    ? { text: '等待输入' }
    : result.error
      ? { text: result.error, tone: 'error' }
      : result.convertible === 0
        ? { text: '没有可转换的节点', tone: 'error' }
        : { text: `${result.convertible} / ${result.nodes.length} 个节点可转换`, tone: 'ok' };

  return (
    <div className="studio">
      <div className="panes">
        <Pane
          className="pane-in"
          tabs={(
            <div className="tab-group" role="radiogroup" aria-label="输入类型">
              {(['share', 'mihomo'] as const).map((key) => (
                <button key={key} type="button" role="radio" aria-checked={source === key} className={source === key ? 'tab is-active' : 'tab'} onClick={() => setSource(key)}>
                  {key === 'share' ? '分享链接' : 'Mihomo YAML'}
                </button>
              ))}
            </div>
          )}
          actions={(
            <>
              <ImportButton accept={source === 'share' ? '.txt,.conf,.list' : '.yaml,.yml'} onImport={(content) => setInput(content)} />
              <button className="act" type="button" disabled={input === PROXY_SAMPLES[source]} onClick={() => setInput(PROXY_SAMPLES[source])}>示例</button>
              <button className="act act-quiet" type="button" disabled={!input} onClick={() => setInput('')}>清空</button>
            </>
          )}
        >
          <CodeEditor
            name="proxy-input"
            value={input}
            onChange={setInput}
            marks={result.badLines}
            label={source === 'share' ? '代理分享链接输入' : 'Mihomo YAML 输入'}
            placeholder={source === 'share' ? '每行一个分享链接，或 Base64 订阅' : '粘贴含 proxies 的 Mihomo YAML'}
          />
        </Pane>

        <Pane
          className="pane-out"
          tabs={(
            <div className="tab-group" role="tablist" aria-label="输出格式">
              {views.map((key) => (
                <button key={key} type="button" role="tab" aria-selected={activeView === key} className={activeView === key ? 'tab is-active' : 'tab'} onClick={() => setView(key)}>
                  {VIEW_LABELS[key]}
                  {key === 'details' && result.nodes.length > 0 && <span className="count">{result.nodes.length}</span>}
                </button>
              ))}
            </div>
          )}
          actions={activeView !== 'details' && (
            <>
              <button className="act" type="button" disabled={!output} onClick={() => downloadText(outputFile, output)}>下载</button>
              <CopyButton value={output} className="act act-primary" />
            </>
          )}
        >
          <div className="scroll" role="tabpanel" aria-label={VIEW_LABELS[activeView]}>
            {isEmpty ? (
              <p className="placeholder">{source === 'share' ? '粘贴分享链接后，这里会列出每个节点' : '粘贴 Mihomo YAML 后，这里会列出每个节点'}</p>
            ) : result.error ? (
              <p className="error-text">{result.error}</p>
            ) : activeView === 'details' ? (
              <NodeTable nodes={result.nodes} markerLabel={source === 'share' ? '行' : '#'} />
            ) : output ? (
              <CodeView text={output} language={outputLanguage} />
            ) : (
              <p className="placeholder">没有可转换的节点</p>
            )}
          </div>
        </Pane>
      </div>

      <StatusBar items={[
        status,
        { text: source === 'share' ? '分享链接' : 'Mihomo YAML' },
        ...result.notes.map((note) => ({ text: note })),
      ]} />
    </div>
  );
}

export default function Home() {
  const [activeTool, setActiveTool] = useState<ActiveTool>('yaml');
  const tools: Array<[ActiveTool, string]> = [['yaml', 'YAML / JSON'], ['proxy', '代理链接']];

  return (
    <main className="app">
      <header className="titlebar">
        <h1 className="brand">AyayaYaml</h1>
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
        <p className="local"><span className="local-dot" aria-hidden="true" />仅在本机浏览器解析，不上传任何内容</p>
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
