import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

export type ProxyProtocol = 'vless' | 'vmess' | 'trojan' | 'ss';

export interface ParsedProxy {
  protocol: ProxyProtocol;
  name: string;
  server: string;
  port: number;
  uuid?: string;
  password?: string;
  encryption?: string;
  transport: string;
  security: string;
  sni?: string;
  flow?: string;
  publicKey?: string;
  shortId?: string;
  fingerprint?: string;
  path?: string;
  host?: string;
  serviceName?: string;
  alpn?: string[];
  skipCertVerify?: boolean;
  plugin?: SsPlugin;
  pluginOpts?: string;
  alterId?: number;
  raw: string;
}

export type SsPlugin = 'obfs-local' | 'v2ray-plugin';

export interface MihomoProxyNode {
  index: number;
  name: string;
  protocol: string;
  server?: string;
  port?: number;
  convertible: boolean;
  warning?: string;
  fields: Array<{ label: string; value: string }>;
  parsed?: ParsedProxy;
  shareLink?: string;
}

export interface MihomoYamlInspection {
  nodes: MihomoProxyNode[];
  shareLinks: string;
}

export interface ProxyLinkInspectionNode {
  index: number;
  lineNumber: number;
  raw: string;
  parsed?: ParsedProxy;
  warning?: string;
}

export interface ProxyLinkInspection {
  nodes: ProxyLinkInspectionNode[];
  proxies: ParsedProxy[];
  /** The input was a Base64-encoded subscription and has been decoded. */
  base64: boolean;
}

type UnknownRecord = Record<string, unknown>;

const SUPPORTED_PROTOCOLS = new Set<ProxyProtocol>(['vless', 'vmess', 'trojan', 'ss']);
const SUPPORTED_TRANSPORTS = new Set(['tcp', 'ws', 'grpc', 'h2', 'httpupgrade']);

function asString(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (typeof value === 'number') return String(value);
  return undefined;
}

function asNumber(value: unknown): number | undefined {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function read(record: UnknownRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (record[key] !== undefined && record[key] !== null) return record[key];
  }
  return undefined;
}

function normalizeInput(value: string): string {
  return value.trim().replace(/^([a-z]+)\\:\/\//i, '$1://');
}

function decodeBase64(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  if (typeof atob === 'function') {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  return Buffer.from(padded, 'base64').toString('utf8');
}

function encodeBase64(value: string): string {
  if (typeof btoa === 'function') {
    const bytes = new TextEncoder().encode(value);
    let binary = '';
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary);
  }
  return Buffer.from(value, 'utf8').toString('base64');
}

function normalizeTransport(value: string | undefined): string {
  const transport = (value || 'tcp').toLowerCase();
  // Xray renamed tcp to raw, and v2ray share links use http for HTTP/2.
  const normalized = transport === 'raw' ? 'tcp' : transport === 'http' ? 'h2' : transport;
  if (!SUPPORTED_TRANSPORTS.has(normalized)) throw new Error(`暂不支持 ${transport} 传输`);
  return normalized;
}

function splitList(value: unknown): string[] | undefined {
  const items = Array.isArray(value)
    ? value.flatMap((item) => asString(item) ?? [])
    : (asString(value) ?? '').split(',').map((item) => item.trim()).filter(Boolean);
  return items.length ? items : undefined;
}

function isTruthyFlag(value: string | null): boolean | undefined {
  return value === '1' || value === 'true' ? true : undefined;
}

function stripBrackets(host: string): string {
  return host.replace(/^\[(.*)\]$/, '$1');
}

function parseSsPlugin(value: string | null): Pick<ParsedProxy, 'plugin' | 'pluginOpts'> {
  if (!value) return {};
  const [name, ...options] = value.split(';');
  const plugin = name === 'simple-obfs' ? 'obfs-local' : name;
  if (plugin !== 'obfs-local' && plugin !== 'v2ray-plugin') throw new Error(`暂不支持 SS 插件 ${name}`);
  return { plugin, pluginOpts: options.join(';') || undefined };
}

function pluginOptions(value: string | undefined): Record<string, string> {
  return Object.fromEntries((value || '').split(';').filter(Boolean).map((option) => {
    const index = option.indexOf('=');
    return index < 0 ? [option, 'true'] : [option.slice(0, index), option.slice(index + 1)];
  }));
}

function parsePort(value: string | number | undefined): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('端口必须是 1–65535 之间的整数');
  }
  return port;
}

function decodeName(hash: string, fallback: string): string {
  if (!hash) return fallback;
  try {
    return decodeURIComponent(hash.replace(/^#/, '')) || fallback;
  } catch {
    return hash.replace(/^#/, '') || fallback;
  }
}

function parseVlessOrTrojan(raw: string, protocol: 'vless' | 'trojan'): ParsedProxy {
  const url = new URL(raw);
  const credential = decodeURIComponent(url.username);
  if (!credential) throw new Error(`${protocol.toUpperCase()} 链接缺少认证信息`);
  if (!url.hostname) throw new Error('分享链接缺少服务器地址');
  const server = stripBrackets(url.hostname);

  const transport = normalizeTransport(url.searchParams.get('type') || url.searchParams.get('network') || undefined);
  const security = url.searchParams.get('security') || (protocol === 'trojan' ? 'tls' : 'none');
  const publicKey = url.searchParams.get('pbk') || url.searchParams.get('publicKey') || undefined;
  if (security === 'reality' && !publicKey) throw new Error('Reality 链接缺少 PublicKey（pbk）');

  return {
    protocol,
    name: decodeName(url.hash, `${protocol.toUpperCase()} · ${server}`),
    server,
    port: parsePort(url.port),
    ...(protocol === 'vless' ? { uuid: credential } : { password: credential }),
    encryption: url.searchParams.get('encryption') || (protocol === 'vless' ? 'none' : undefined),
    transport,
    security,
    sni: url.searchParams.get('sni') || url.searchParams.get('servername') || undefined,
    flow: url.searchParams.get('flow') || undefined,
    publicKey,
    shortId: url.searchParams.get('sid') || url.searchParams.get('shortId') || undefined,
    fingerprint: url.searchParams.get('fp') || undefined,
    path: url.searchParams.get('path') || undefined,
    host: url.searchParams.get('host') || undefined,
    serviceName: url.searchParams.get('serviceName') || undefined,
    alpn: splitList(url.searchParams.get('alpn')),
    skipCertVerify: isTruthyFlag(url.searchParams.get('allowInsecure') ?? url.searchParams.get('insecure')),
    raw,
  };
}

function parseVmess(raw: string): ParsedProxy {
  const payload = raw.slice('vmess://'.length).split('#')[0];
  let config: UnknownRecord;
  try {
    config = JSON.parse(decodeBase64(payload)) as UnknownRecord;
  } catch {
    throw new Error('VMess 链接中的 Base64 JSON 无法解析');
  }

  const server = asString(read(config, 'add', 'server'));
  const uuid = asString(read(config, 'id', 'uuid'));
  if (!server || !uuid) throw new Error('VMess 链接缺少服务器或 UUID');
  const transport = normalizeTransport(asString(read(config, 'net', 'network')));
  const path = asString(read(config, 'path'));

  return {
    protocol: 'vmess',
    name: asString(read(config, 'ps', 'name')) || `VMess · ${server}`,
    server,
    port: parsePort(asString(read(config, 'port'))),
    uuid,
    alterId: asNumber(read(config, 'aid', 'alterId')) || 0,
    encryption: asString(read(config, 'scy', 'cipher')) || 'auto',
    transport,
    security: asString(read(config, 'tls', 'security')) || 'none',
    sni: asString(read(config, 'sni', 'servername')),
    // VMess share links carry the gRPC service name in `path`.
    path: transport === 'grpc' ? undefined : path,
    serviceName: transport === 'grpc' ? path : undefined,
    host: asString(read(config, 'host')),
    fingerprint: asString(read(config, 'fp')),
    alpn: splitList(read(config, 'alpn')),
    raw,
  };
}

function parseShadowsocks(raw: string): ParsedProxy {
  const withoutScheme = raw.slice('ss://'.length);
  const hashIndex = withoutScheme.indexOf('#');
  const mainPart = hashIndex < 0 ? withoutScheme : withoutScheme.slice(0, hashIndex);
  const fragment = hashIndex < 0 ? '' : withoutScheme.slice(hashIndex + 1);
  const queryIndex = mainPart.indexOf('?');
  const query = new URLSearchParams(queryIndex < 0 ? '' : mainPart.slice(queryIndex + 1));
  let authority = (queryIndex < 0 ? mainPart : mainPart.slice(0, queryIndex)).replace(/\/$/, '');

  if (!authority.includes('@')) {
    try { authority = decodeBase64(authority); }
    catch { throw new Error('SS 链接中的 Base64 内容无法解析'); }
  } else {
    const atIndex = authority.lastIndexOf('@');
    const credentials = authority.slice(0, atIndex);
    if (!credentials.includes(':')) {
      try { authority = `${decodeBase64(credentials)}${authority.slice(atIndex)}`; }
      catch { throw new Error('SS 链接中的认证信息无法解析'); }
    }
  }

  const match = authority.match(/^([^:]+):(.+)@\[?([^\]]+)\]?:([0-9]+)$/);
  if (!match) throw new Error('SS 链接格式不完整');
  const [, method, password, server, port] = match;

  return {
    protocol: 'ss',
    name: decodeName(fragment, `SS · ${server}`),
    server,
    port: parsePort(port),
    password: decodeURIComponent(password),
    encryption: decodeURIComponent(method),
    transport: 'tcp',
    security: 'none',
    ...parseSsPlugin(query.get('plugin')),
    raw,
  };
}

export function parseProxyLink(input: string): ParsedProxy {
  const raw = normalizeInput(input);
  const protocol = raw.match(/^([a-z]+):\/\//i)?.[1].toLowerCase() as ProxyProtocol | undefined;
  if (!protocol || !SUPPORTED_PROTOCOLS.has(protocol)) {
    throw new Error('暂不支持这个协议，请使用 VLESS、VMess、Trojan 或 SS 链接');
  }

  if (protocol === 'vless' || protocol === 'trojan') return parseVlessOrTrojan(raw, protocol);
  if (protocol === 'vmess') return parseVmess(raw);
  return parseShadowsocks(raw);
}

function decodeSubscription(input: string): string | undefined {
  const compacted = input.replace(/\s+/g, '');
  if (!compacted || input.includes('://') || !/^[A-Za-z0-9+/_-]+=*$/.test(compacted)) return undefined;
  try {
    const decoded = decodeBase64(compacted);
    return /^[a-z0-9]+:\/\//im.test(decoded) ? decoded : undefined;
  } catch {
    return undefined;
  }
}

export function inspectProxyLinks(input: string): ProxyLinkInspection {
  const decoded = decodeSubscription(input);
  const entries = (decoded ?? input).split(/\r?\n/).flatMap((line, index) => {
    const raw = line.trim();
    return raw && !raw.startsWith('#') ? [{ raw, lineNumber: index + 1 }] : [];
  });
  if (!entries.length) throw new Error('请先粘贴至少一条代理分享链接');

  const nodes = entries.map(({ raw, lineNumber }, index): ProxyLinkInspectionNode => {
    try {
      return { index, lineNumber, raw, parsed: parseProxyLink(raw) };
    } catch (error) {
      return {
        index,
        lineNumber,
        raw,
        warning: error instanceof Error ? error.message : '未知错误',
      };
    }
  });

  return {
    nodes,
    proxies: nodes.flatMap((node) => node.parsed ? [node.parsed] : []),
    base64: decoded !== undefined,
  };
}

/** Mihomo and sing-box both reject duplicate node names, so number repeats. */
export function withUniqueNames(proxies: ParsedProxy[]): ParsedProxy[] {
  const used = new Set<string>();
  return proxies.map((proxy) => {
    let name = proxy.name;
    for (let suffix = 2; used.has(name); suffix += 1) name = `${proxy.name} ${suffix}`;
    used.add(name);
    return name === proxy.name ? proxy : { ...proxy, name };
  });
}

export function parseProxyLinks(input: string): ParsedProxy[] {
  const inspection = inspectProxyLinks(input);
  const invalid = inspection.nodes.find((node) => !node.parsed);
  if (invalid) {
    throw new Error(inspection.nodes.length > 1
      ? `第 ${invalid.lineNumber} 行：${invalid.warning}`
      : invalid.warning);
  }
  return inspection.proxies;
}

function compact<T extends UnknownRecord>(record: T): T {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined && value !== '')) as T;
}

function transportOptions(proxy: ParsedProxy): UnknownRecord {
  if (proxy.transport === 'ws' || proxy.transport === 'httpupgrade') {
    return {
      network: 'ws',
      'ws-opts': compact({
        path: proxy.path,
        headers: proxy.host ? { Host: proxy.host } : undefined,
        'v2ray-http-upgrade': proxy.transport === 'httpupgrade' || undefined,
      }),
    };
  }
  if (proxy.transport === 'h2') {
    return { network: 'h2', 'h2-opts': compact({ host: splitList(proxy.host), path: proxy.path }) };
  }
  if (proxy.transport === 'grpc') {
    return { network: 'grpc', 'grpc-opts': compact({ 'grpc-service-name': proxy.serviceName }) };
  }
  return { network: proxy.transport };
}

function toMihomoPlugin(proxy: ParsedProxy): UnknownRecord {
  if (!proxy.plugin) return {};
  const options = pluginOptions(proxy.pluginOpts);
  if (proxy.plugin === 'obfs-local') {
    return { plugin: 'obfs', 'plugin-opts': compact({ mode: options.obfs, host: options['obfs-host'] }) };
  }
  return {
    plugin: 'v2ray-plugin',
    'plugin-opts': compact({
      mode: options.mode || 'websocket',
      tls: options.tls === 'true' || undefined,
      host: options.host,
      path: options.path,
    }),
  };
}

function toMihomoProxy(proxy: ParsedProxy): UnknownRecord {
  const base = {
    name: proxy.name,
    type: proxy.protocol,
    server: proxy.server,
    port: proxy.port,
    udp: true,
  };

  if (proxy.protocol === 'ss') {
    return compact({ ...base, cipher: proxy.encryption, password: proxy.password, ...toMihomoPlugin(proxy) });
  }

  const tlsEnabled = proxy.security !== 'none';
  // Mihomo trojan is always TLS and names its SNI option `sni`.
  const isTrojan = proxy.protocol === 'trojan';
  return compact({
    ...base,
    ...(isTrojan ? { password: proxy.password } : { uuid: proxy.uuid }),
    ...(proxy.protocol === 'vmess' ? { alterId: proxy.alterId || 0, cipher: proxy.encryption || 'auto' } : {}),
    tls: isTrojan ? undefined : tlsEnabled || undefined,
    ...(isTrojan ? { sni: proxy.sni } : { servername: proxy.sni }),
    alpn: tlsEnabled ? proxy.alpn : undefined,
    'skip-cert-verify': tlsEnabled ? proxy.skipCertVerify : undefined,
    flow: proxy.flow,
    'client-fingerprint': proxy.fingerprint,
    'reality-opts': proxy.security === 'reality' ? compact({
      'public-key': proxy.publicKey,
      'short-id': proxy.shortId,
    }) : undefined,
    ...transportOptions(proxy),
  });
}

export function toMihomoYaml(input: ParsedProxy[]): string {
  const proxies = withUniqueNames(input);
  const names = proxies.map((proxy) => proxy.name);
  return stringifyYaml({
    proxies: proxies.map(toMihomoProxy),
    'proxy-groups': [{ name: '节点选择', type: 'select', proxies: names }],
  }, { lineWidth: 0 });
}

function toSingBoxTransport(proxy: ParsedProxy): UnknownRecord | undefined {
  if (proxy.transport === 'ws') {
    return compact({ type: 'ws', path: proxy.path, headers: proxy.host ? { Host: proxy.host } : undefined });
  }
  if (proxy.transport === 'httpupgrade') {
    return compact({ type: 'httpupgrade', path: proxy.path, host: proxy.host });
  }
  if (proxy.transport === 'h2') {
    return compact({ type: 'http', path: proxy.path, host: splitList(proxy.host) });
  }
  if (proxy.transport === 'grpc') {
    return compact({ type: 'grpc', service_name: proxy.serviceName });
  }
  return undefined;
}

function toSingBoxOutbound(proxy: ParsedProxy): UnknownRecord {
  const tlsEnabled = proxy.security !== 'none';
  const tls = tlsEnabled ? compact({
    enabled: true,
    server_name: proxy.sni,
    insecure: proxy.skipCertVerify,
    alpn: proxy.alpn,
    utls: proxy.fingerprint ? { enabled: true, fingerprint: proxy.fingerprint } : undefined,
    reality: proxy.security === 'reality' ? compact({
      enabled: true,
      public_key: proxy.publicKey,
      short_id: proxy.shortId,
    }) : undefined,
  }) : undefined;

  return compact({
    type: proxy.protocol === 'ss' ? 'shadowsocks' : proxy.protocol,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    uuid: proxy.uuid,
    password: proxy.password,
    method: proxy.protocol === 'ss' ? proxy.encryption : undefined,
    plugin: proxy.plugin,
    plugin_opts: proxy.pluginOpts,
    security: proxy.protocol === 'vmess' ? proxy.encryption || 'auto' : undefined,
    alter_id: proxy.protocol === 'vmess' ? proxy.alterId || 0 : undefined,
    flow: proxy.flow,
    tls,
    transport: toSingBoxTransport(proxy),
  });
}

export function toSingBoxJson(proxies: ParsedProxy[]): string {
  return JSON.stringify({ outbounds: withUniqueNames(proxies).map(toSingBoxOutbound) }, null, 2);
}

function formatHost(host: string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function buildUrlProxy(proxy: ParsedProxy): string {
  const credential = proxy.protocol === 'vless' ? proxy.uuid : proxy.password;
  if (!credential) throw new Error(`${proxy.name} 缺少认证信息`);
  const params = new URLSearchParams();

  if (proxy.protocol === 'vless') params.set('encryption', proxy.encryption || 'none');
  if (proxy.transport) params.set('type', proxy.transport);
  if (proxy.security) params.set('security', proxy.security);
  if (proxy.sni) params.set('sni', proxy.sni);
  if (proxy.flow) params.set('flow', proxy.flow);
  if (proxy.publicKey) params.set('pbk', proxy.publicKey);
  if (proxy.shortId) params.set('sid', proxy.shortId);
  if (proxy.fingerprint) params.set('fp', proxy.fingerprint);
  if (proxy.path) params.set('path', proxy.path);
  if (proxy.host) params.set('host', proxy.host);
  if (proxy.serviceName) params.set('serviceName', proxy.serviceName);
  if (proxy.alpn) params.set('alpn', proxy.alpn.join(','));
  if (proxy.skipCertVerify) params.set('allowInsecure', '1');

  const query = params.toString();
  return `${proxy.protocol}://${encodeURIComponent(credential)}@${formatHost(proxy.server)}:${proxy.port}${query ? `?${query}` : ''}#${encodeURIComponent(proxy.name)}`;
}

function buildVmess(proxy: ParsedProxy): string {
  return `vmess://${encodeBase64(JSON.stringify({
    v: '2',
    ps: proxy.name,
    add: proxy.server,
    port: String(proxy.port),
    id: proxy.uuid,
    aid: String(proxy.alterId || 0),
    scy: proxy.encryption || 'auto',
    net: proxy.transport || 'tcp',
    type: 'none',
    host: proxy.host || '',
    path: (proxy.transport === 'grpc' ? proxy.serviceName : proxy.path) || '',
    tls: proxy.security === 'none' ? '' : proxy.security,
    sni: proxy.sni || '',
    fp: proxy.fingerprint || '',
    alpn: proxy.alpn?.join(',') || '',
  }))}`;
}

function buildShadowsocks(proxy: ParsedProxy): string {
  if (!proxy.encryption || !proxy.password) throw new Error(`${proxy.name} 缺少 cipher 或 password`);
  const credentials = encodeBase64(`${proxy.encryption}:${proxy.password}`).replace(/=+$/, '');
  const plugin = proxy.plugin
    ? `/?plugin=${encodeURIComponent([proxy.plugin, proxy.pluginOpts].filter(Boolean).join(';'))}`
    : '';
  return `ss://${credentials}@${formatHost(proxy.server)}:${proxy.port}${plugin}#${encodeURIComponent(proxy.name)}`;
}

export function toShareLink(proxy: ParsedProxy): string {
  if (proxy.protocol === 'vmess') return buildVmess(proxy);
  if (proxy.protocol === 'ss') return buildShadowsocks(proxy);
  return buildUrlProxy(proxy);
}

function fromMihomoProxy(input: unknown, index: number): ParsedProxy {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error(`第 ${index + 1} 个 proxy 不是对象`);
  const proxy = input as UnknownRecord;
  const protocol = asString(proxy.type)?.toLowerCase() as ProxyProtocol | undefined;
  if (!protocol || !SUPPORTED_PROTOCOLS.has(protocol)) throw new Error(`第 ${index + 1} 个 proxy 的 type 暂不支持`);

  const server = asString(proxy.server);
  const name = asString(proxy.name) || `${protocol.toUpperCase()} ${index + 1}`;
  if (!server) throw new Error(`${name} 缺少 server`);

  const reality = read(proxy, 'reality-opts', 'realityOpts') as UnknownRecord | undefined;
  const ws = read(proxy, 'ws-opts', 'wsOpts') as UnknownRecord | undefined;
  const wsHeaders = ws?.headers as UnknownRecord | undefined;
  const h2 = read(proxy, 'h2-opts', 'h2Opts') as UnknownRecord | undefined;
  const grpc = read(proxy, 'grpc-opts', 'grpcOpts') as UnknownRecord | undefined;
  const network = asString(read(proxy, 'network'))?.toLowerCase() || 'tcp';
  // Mihomo `http` is a TCP header disguise, not the share-link HTTP/2 transport.
  if (network === 'http' || network === 'httpupgrade' || !SUPPORTED_TRANSPORTS.has(network)) {
    throw new Error(`${name} 的 network「${network}」暂不支持转换`);
  }
  const transport = network === 'ws' && ws?.['v2ray-http-upgrade'] === true ? 'httpupgrade' : network;
  const security = reality ? 'reality' : proxy.tls === true || protocol === 'trojan' ? 'tls' : 'none';

  return {
    protocol,
    name,
    server,
    port: parsePort(asNumber(proxy.port)),
    uuid: asString(proxy.uuid),
    password: asString(proxy.password),
    encryption: asString(read(proxy, 'cipher', 'encryption')) || (protocol === 'vless' ? 'none' : undefined),
    transport,
    security,
    sni: asString(read(proxy, 'servername', 'sni')),
    flow: asString(proxy.flow),
    publicKey: reality ? asString(read(reality, 'public-key', 'publicKey')) : undefined,
    shortId: reality ? asString(read(reality, 'short-id', 'shortId')) : undefined,
    fingerprint: asString(read(proxy, 'client-fingerprint', 'clientFingerprint')),
    path: asString(ws?.path ?? h2?.path),
    host: wsHeaders ? asString(read(wsHeaders, 'Host', 'host')) : splitList(h2?.host)?.join(','),
    serviceName: grpc ? asString(read(grpc, 'grpc-service-name', 'serviceName')) : undefined,
    alpn: security === 'none' ? undefined : splitList(proxy.alpn),
    skipCertVerify: security !== 'none' && proxy['skip-cert-verify'] === true ? true : undefined,
    ...(protocol === 'ss' ? fromMihomoPlugin(proxy, name) : {}),
    alterId: asNumber(read(proxy, 'alterId', 'alter-id')),
    raw: '',
  };
}

function fromMihomoPlugin(proxy: UnknownRecord, name: string): Pick<ParsedProxy, 'plugin' | 'pluginOpts'> {
  const plugin = asString(proxy.plugin);
  if (!plugin) return {};
  const options = (read(proxy, 'plugin-opts', 'pluginOpts') || {}) as UnknownRecord;
  const join = (entries: Array<string | undefined>) => entries.filter(Boolean).join(';') || undefined;
  if (plugin === 'obfs') {
    return {
      plugin: 'obfs-local',
      pluginOpts: join([
        asString(options.mode) && `obfs=${asString(options.mode)}`,
        asString(options.host) && `obfs-host=${asString(options.host)}`,
      ]),
    };
  }
  if (plugin === 'v2ray-plugin') {
    return {
      plugin: 'v2ray-plugin',
      pluginOpts: join([
        `mode=${asString(options.mode) || 'websocket'}`,
        options.tls === true ? 'tls' : undefined,
        asString(options.host) && `host=${asString(options.host)}`,
        asString(options.path) && `path=${asString(options.path)}`,
      ]),
    };
  }
  throw new Error(`${name} 的插件「${plugin}」暂不支持转换`);
}

function displayMihomoValue(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  try { return JSON.stringify(value); }
  catch { return String(value); }
}

function inspectMihomoProxy(input: unknown, index: number): MihomoProxyNode {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {
      index,
      name: `Proxy ${index + 1}`,
      protocol: 'unknown',
      convertible: false,
      warning: `第 ${index + 1} 个 proxy 不是对象`,
      fields: [],
    };
  }

  const raw = input as UnknownRecord;
  const protocol = asString(raw.type)?.toLowerCase() || 'unknown';
  const name = asString(raw.name) || `${protocol.toUpperCase()} ${index + 1}`;
  const server = asString(raw.server);
  const port = asNumber(raw.port);
  const fields = Object.entries(raw)
    .filter(([key]) => !['name', 'type', 'server', 'port'].includes(key))
    .map(([label, value]) => ({ label, value: displayMihomoValue(value) }))
    .filter((field): field is { label: string; value: string } => field.value !== undefined);

  if (!SUPPORTED_PROTOCOLS.has(protocol as ProxyProtocol)) {
    return {
      index,
      name,
      protocol,
      server,
      port,
      convertible: false,
      warning: `节点「${name}」的 type「${protocol}」暂不支持转换`,
      fields,
    };
  }

  try {
    const parsed = fromMihomoProxy(raw, index);
    return {
      index,
      name,
      protocol,
      server,
      port,
      convertible: true,
      fields,
      parsed,
      shareLink: toShareLink(parsed),
    };
  } catch (error) {
    return {
      index,
      name,
      protocol,
      server,
      port,
      convertible: false,
      warning: error instanceof Error ? error.message : `${name} 无法转换`,
      fields,
    };
  }
}

export function inspectMihomoYaml(input: string): MihomoYamlInspection {
  let document: unknown;
  try { document = parseYaml(input); }
  catch (error) {
    throw new Error(`YAML 无法解析：${error instanceof Error ? error.message.split('\n')[0] : '未知错误'}`);
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('YAML 根节点必须是对象');
  const proxies = (document as UnknownRecord).proxies;
  if (!Array.isArray(proxies) || !proxies.length) throw new Error('YAML 中没有找到 proxies 列表');
  const nodes = proxies.map(inspectMihomoProxy);
  return {
    nodes,
    shareLinks: nodes.flatMap((node) => node.shareLink ? [node.shareLink] : []).join('\n'),
  };
}

export function mihomoYamlToShareLinks(input: string): string {
  return inspectMihomoYaml(input).shareLinks;
}
