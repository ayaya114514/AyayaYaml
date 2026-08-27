'use client';

import {
  Braces,
  Check,
  CircleAlert,
  Clipboard,
  ClipboardCheck,
  Code2,
  Download,
  FileJson2,
  FileText,
  LockKeyhole,
  Network,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  Trash2,
  WandSparkles,
} from 'lucide-react';
import { useMemo, useState, type CSSProperties } from 'react';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import {
  mihomoYamlToShareLinks,
  parseProxyLinks,
  toMihomoYaml,
  toSingBoxJson,
  type ParsedProxy,
} from '../lib/proxy';

const YAML_SAMPLE = `proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - Hong Kong 01
      - Japan 01

rules:
  - DOMAIN-SUFFIX,openai.com,🚀 节点选择`;

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
      short-id: f7d552`;

type ActiveTool = 'yaml' | 'proxy';
type SourceFormat = 'yaml' | 'json';
type ProxySource = 'share' | 'mihomo';
type ProxyView = 'details' | 'mihomo' | 'singbox' | 'share';

function parseStructuredText(input: string): { data: unknown; format: SourceFormat } {
  if (!input.trim()) throw new Error('请输入 YAML 或 JSON 内容');
  const looksLikeJson = /^[\s\r\n]*[\[{]/.test(input);
  if (looksLikeJson) {
    try { return { data: JSON.parse(input), format: 'json' }; }
    catch {
      // JSON-shaped YAML is still valid YAML, so fall through to YAML parsing.
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
        <span className={`tree-value type-${typeof value}`}>{displayValue(value)}</span>
      </div>
    );
  }

  const entries = Array.isArray(value)
    ? value.map((item, index) => [String(index), item] as const)
    : Object.entries(value as Record<string, unknown>);
  const visibleEntries = entries.slice(0, 100);
  const kind = Array.isArray(value) ? 'array' : 'object';

  return (
    <details className="tree-group" open={depth < 2} style={{ '--tree-depth': depth } as CSSProperties}>
      <summary>
        {label !== undefined && <span className="tree-label">{label}</span>}
        <span className="tree-kind">{kind === 'array' ? 'Array' : 'Object'}</span>
        <span className="tree-count">{entries.length}</span>
      </summary>
      <div className="tree-children">
        {visibleEntries.map(([key, item]) => <TreeNode key={key} label={key} value={item} depth={depth + 1} />)}
        {entries.length > visibleEntries.length && (
          <div className="tree-overflow">还有 {entries.length - visibleEntries.length} 项未展开</div>
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
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <button className="subtle-button" type="button" onClick={copy} disabled={!value}>
      {copied ? <ClipboardCheck size={15} /> : <Clipboard size={15} />}
      {copied ? '已复制' : label}
    </button>
  );
}

function YamlStudio() {
  const [input, setInput] = useState(YAML_SAMPLE);
  const [notice, setNotice] = useState('实时语法检查已开启');
  const parsed = useMemo(() => {
    try { return { ...parseStructuredText(input), error: '' }; }
    catch (error) { return { data: null, format: 'yaml' as SourceFormat, error: error instanceof Error ? error.message : '无法解析' }; }
  }, [input]);

  function formatInput() {
    if (parsed.error) return;
    const formatted = parsed.format === 'json'
      ? JSON.stringify(parsed.data, null, 2)
      : stringifyYaml(parsed.data, { indent: 2, lineWidth: 0 });
    setInput(formatted.trimEnd());
    setNotice('格式化完成');
  }

  function convertInput() {
    if (parsed.error) return;
    const next = parsed.format === 'yaml'
      ? JSON.stringify(parsed.data, null, 2)
      : stringifyYaml(parsed.data, { indent: 2, lineWidth: 0 }).trimEnd();
    setInput(next);
    setNotice(parsed.format === 'yaml' ? '已转换为 JSON' : '已转换为 YAML');
  }

  function download() {
    const extension = parsed.format === 'json' ? 'json' : 'yaml';
    const blob = new Blob([input], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `config.${extension}`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <div className="workspace-actions">
        <span className="format-chip">{parsed.format.toUpperCase()}</span>
        <button className="subtle-button" type="button" onClick={formatInput} disabled={Boolean(parsed.error)}>
          <WandSparkles size={15} /> 格式化
        </button>
        <button className="primary-button" type="button" onClick={convertInput} disabled={Boolean(parsed.error)}>
          <FileJson2 size={15} /> 转为 {parsed.format === 'yaml' ? 'JSON' : 'YAML'}
        </button>
      </div>

      <div className="editor-grid">
        <section className="editor-pane">
          <div className="pane-heading">
            <span><span className="file-dot" /> config.{parsed.format}</span>
            <div className="pane-actions">
              <button type="button" onClick={() => { setInput(YAML_SAMPLE); setNotice('示例已恢复'); }} aria-label="恢复示例"><RotateCcw size={14} /></button>
              <CopyButton value={input} />
              <button type="button" onClick={download} aria-label="下载文件"><Download size={14} /></button>
              <button type="button" onClick={() => setInput('')} aria-label="清空编辑器"><Trash2 size={14} /></button>
            </div>
          </div>
          <textarea
            className="text-editor"
            value={input}
            onChange={(event) => { setInput(event.target.value); setNotice('实时语法检查已开启'); }}
            spellCheck={false}
            aria-label="YAML 或 JSON 编辑器"
          />
        </section>

        <section className="preview-pane">
          <div className="pane-heading">
            <span>结构预览</span>
            {parsed.error ? (
              <span className="invalid-state"><CircleAlert size={13} /> 发现错误</span>
            ) : (
              <span className="valid-state"><Check size={13} strokeWidth={3} /> 语法正确</span>
            )}
          </div>
          <div className="tree-view">
            {parsed.error ? (
              <div className="error-panel">
                <span><CircleAlert size={18} /></span>
                <div><strong>无法解析当前内容</strong><p>{parsed.error}</p></div>
              </div>
            ) : (
              <TreeNode value={parsed.data} label="root" />
            )}
          </div>
        </section>
      </div>

      <div className={`workspace-status ${parsed.error ? 'has-error' : ''}`}>
        <span>{parsed.error ? <CircleAlert size={14} /> : <Check size={14} strokeWidth={3} />} {parsed.error || notice}</span>
        <span>{input.split(/\r?\n/).length} lines · {new Blob([input]).size} bytes · 浏览器本地处理</span>
      </div>
    </>
  );
}

const FIELD_LABELS: Array<[keyof ParsedProxy, string]> = [
  ['protocol', '协议'],
  ['server', '服务器'],
  ['port', '端口'],
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

function ProxyDetails({ proxies }: { proxies: ParsedProxy[] }) {
  return (
    <div className="proxy-details">
      {proxies.map((proxy, index) => (
        <article className="node-card" key={`${proxy.protocol}-${proxy.server}-${index}`}>
          <div className="node-card-header">
            <div>
              <span className="protocol-badge">{proxy.protocol.toUpperCase()}</span>
              <h3>{proxy.name}</h3>
            </div>
            <span className="node-index">{String(index + 1).padStart(2, '0')}</span>
          </div>
          <dl>
            {FIELD_LABELS.map(([key, label]) => {
              const value = proxy[key];
              if (value === undefined || value === '') return null;
              return (
                <div key={key}>
                  <dt>{label}</dt>
                  <dd>{key === 'protocol' ? String(value).toUpperCase() : String(value)}</dd>
                </div>
              );
            })}
          </dl>
        </article>
      ))}
    </div>
  );
}

function ProxyStudio() {
  const [source, setSource] = useState<ProxySource>('share');
  const [input, setInput] = useState(VLESS_SAMPLE);
  const [view, setView] = useState<ProxyView>('details');

  const result = useMemo(() => {
    if (!input.trim()) return { proxies: [] as ParsedProxy[], mihomo: '', singbox: '', share: '', error: '' };
    try {
      if (source === 'share') {
        const proxies = parseProxyLinks(input);
        return { proxies, mihomo: toMihomoYaml(proxies), singbox: toSingBoxJson(proxies), share: '', error: '' };
      }
      return { proxies: [] as ParsedProxy[], mihomo: '', singbox: '', share: mihomoYamlToShareLinks(input), error: '' };
    } catch (error) {
      return { proxies: [] as ParsedProxy[], mihomo: '', singbox: '', share: '', error: error instanceof Error ? error.message : '无法解析' };
    }
  }, [input, source]);

  const output = view === 'mihomo' ? result.mihomo : view === 'singbox' ? result.singbox : view === 'share' ? result.share : JSON.stringify(result.proxies, null, 2);
  const availableViews: Array<[ProxyView, string]> = source === 'share'
    ? [['details', '解析详情'], ['mihomo', 'Mihomo YAML'], ['singbox', 'sing-box JSON']]
    : [['share', '分享链接']];

  function changeSource(next: ProxySource) {
    setSource(next);
    setInput(next === 'share' ? VLESS_SAMPLE : MIHOMO_SAMPLE);
    setView(next === 'share' ? 'details' : 'share');
  }

  return (
    <>
      <div className="workspace-actions proxy-toolbar">
        <div className="source-toggle" role="group" aria-label="输入类型">
          <button className={source === 'share' ? 'is-active' : ''} type="button" onClick={() => changeSource('share')}>分享链接</button>
          <button className={source === 'mihomo' ? 'is-active' : ''} type="button" onClick={() => changeSource('mihomo')}>Mihomo YAML</button>
        </div>
        <button className="subtle-button" type="button" onClick={() => setInput(source === 'share' ? VLESS_SAMPLE : MIHOMO_SAMPLE)}>
          <RotateCcw size={15} /> 加载示例
        </button>
        <CopyButton value={output} label="复制结果" />
      </div>

      <div className="editor-grid proxy-grid">
        <section className="editor-pane">
          <div className="pane-heading">
            <span><span className="file-dot" /> {source === 'share' ? 'proxy-links.txt' : 'mihomo.yaml'}</span>
            <div className="pane-actions">
              <button type="button" onClick={() => setInput('')} aria-label="清空输入"><Trash2 size={14} /></button>
            </div>
          </div>
          <textarea
            className="text-editor proxy-editor"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder={source === 'share' ? '粘贴 VLESS、VMess、Trojan 或 SS 分享链接，每行一条…' : '粘贴含 proxies 列表的 Mihomo YAML…'}
            spellCheck={false}
            aria-label={source === 'share' ? '代理分享链接输入' : 'Mihomo YAML 输入'}
          />
          <div className="input-hint">
            <LockKeyhole size={13} /> 输入内容不会离开当前浏览器
          </div>
        </section>

        <section className="preview-pane proxy-preview">
          <div className="pane-heading proxy-view-heading">
            <div className="view-tabs" role="tablist" aria-label="转换结果">
              {availableViews.map(([key, label]) => (
                <button key={key} className={view === key ? 'is-active' : ''} type="button" onClick={() => setView(key)}>{label}</button>
              ))}
            </div>
            {!result.error && input.trim() && <span className="valid-state"><Check size={13} strokeWidth={3} /> Ready</span>}
          </div>
          <div className="proxy-output">
            {!input.trim() ? (
              <div className="empty-state"><Network size={24} /><strong>等待输入</strong><p>粘贴链接或 YAML 后，结果会实时显示在这里。</p></div>
            ) : result.error ? (
              <div className="error-panel">
                <span><CircleAlert size={18} /></span>
                <div><strong>无法完成解析</strong><p>{result.error}</p></div>
              </div>
            ) : view === 'details' ? (
              <ProxyDetails proxies={result.proxies} />
            ) : (
              <pre className="conversion-output"><code>{output}</code></pre>
            )}
          </div>
        </section>
      </div>

      <div className={`workspace-status ${result.error ? 'has-error' : ''}`}>
        <span>
          {result.error ? <CircleAlert size={14} /> : <Check size={14} strokeWidth={3} />}
          {result.error || (source === 'share' ? `已解析 ${result.proxies.length} 个节点` : '已生成分享链接')}
        </span>
        <span>支持 VLESS · VMess · Trojan · Shadowsocks</span>
      </div>
    </>
  );
}

export default function Home() {
  const [activeTool, setActiveTool] = useState<ActiveTool>('yaml');

  function openTool(tool: ActiveTool) {
    setActiveTool(tool);
    window.requestAnimationFrame(() => document.querySelector('#workspace')?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  }

  return (
    <main className="site-shell" id="top">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="AyayaYaml 首页">
          <span className="brand-mark"><Braces size={19} strokeWidth={2.4} /></span>
          <span>Ayaya<span>Yaml</span></span>
        </a>
        <nav className="nav-links" aria-label="主要导航">
          <button className={activeTool === 'yaml' ? 'is-active' : ''} type="button" onClick={() => openTool('yaml')}>YAML 工具</button>
          <button className={activeTool === 'proxy' ? 'is-active' : ''} type="button" onClick={() => openTool('proxy')}>AyayaProxy</button>
          <a href="#privacy">本地与隐私</a>
        </nav>
        <div className="local-pill"><span className="status-dot" /> Local only</div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow"><Sparkles size={14} /> YAML, without the guesswork</p>
          <h1>把配置文件，<br /><span>变得一目了然。</span></h1>
          <p className="hero-description">编辑、格式化、检查与转换 YAML；解析代理分享链接，清楚看到每一个关键字段。</p>
        </div>
        <div className="privacy-card" id="privacy">
          <span className="privacy-icon"><LockKeyhole size={20} /></span>
          <div><strong>你的配置，只属于你</strong><p>所有内容仅在浏览器本地处理，不上传服务器。</p></div>
        </div>
      </section>

      <section className="workspace" id="workspace" aria-label={activeTool === 'yaml' ? 'YAML 编辑工作区' : '代理链接转换工作区'}>
        <div className="workspace-topbar">
          <div className="tool-tabs" role="tablist" aria-label="工具选择">
            <button className={`tool-tab ${activeTool === 'yaml' ? 'is-active' : ''}`} type="button" role="tab" aria-selected={activeTool === 'yaml'} onClick={() => setActiveTool('yaml')}>
              <FileText size={16} /> AYYAML
            </button>
            <button className={`tool-tab ${activeTool === 'proxy' ? 'is-active' : ''}`} type="button" role="tab" aria-selected={activeTool === 'proxy'} onClick={() => setActiveTool('proxy')}>
              <Network size={16} /> AyayaProxy <span className="new-badge">NEW</span>
            </button>
          </div>
        </div>
        {activeTool === 'yaml' ? <YamlStudio /> : <ProxyStudio />}
      </section>

      <section className="feature-strip" aria-label="产品特点">
        <article><span><ShieldCheck size={18} /></span><div><strong>100% Local</strong><p>无需上传，不保存内容</p></div></article>
        <article><span><Code2 size={18} /></span><div><strong>双向转换</strong><p>YAML、JSON 与代理格式</p></div></article>
        <article><span><WandSparkles size={18} /></span><div><strong>即时反馈</strong><p>输入时同步检查与预览</p></div></article>
      </section>

      <footer><span>AyayaYaml</span><p>Private by design · Built for clear configs</p></footer>
    </main>
  );
}
