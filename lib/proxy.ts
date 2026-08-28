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
  alterId?: number;
  raw: string;
}

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

type UnknownRecord = Record<string, unknown>;

const SUPPORTED_PROTOCOLS = new Set<ProxyProtocol>(['vless', 'vmess', 'trojan', 'ss']);

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

  const transport = url.searchParams.get('type') || url.searchParams.get('network') || 'tcp';
  const security = url.searchParams.get('security') || (protocol === 'trojan' ? 'tls' : 'none');
  const publicKey = url.searchParams.get('pbk') || url.searchParams.get('publicKey') || undefined;
  if (security === 'reality' && !publicKey) throw new Error('Reality 链接缺少 PublicKey（pbk）');

  return {
    protocol,
    name: decodeName(url.hash, `${protocol.toUpperCase()} · ${url.hostname}`),
    server: url.hostname,
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

  return {
    protocol: 'vmess',
    name: asString(read(config, 'ps', 'name')) || `VMess · ${server}`,
    server,
    port: parsePort(asString(read(config, 'port'))),
    uuid,
    alterId: asNumber(read(config, 'aid', 'alterId')) || 0,
    encryption: asString(read(config, 'scy', 'cipher')) || 'auto',
    transport: asString(read(config, 'net', 'network')) || 'tcp',
    security: asString(read(config, 'tls', 'security')) || 'none',
    sni: asString(read(config, 'sni', 'servername')),
    path: asString(read(config, 'path')),
    host: asString(read(config, 'host')),
    fingerprint: asString(read(config, 'fp')),
    raw,
  };
}

function parseShadowsocks(raw: string): ParsedProxy {
  const withoutScheme = raw.slice('ss://'.length);
  const [mainPart, fragment = ''] = withoutScheme.split('#', 2);
  const queryless = mainPart.split('?')[0];
  let authority = queryless;

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

export function parseProxyLinks(input: string): ParsedProxy[] {
  const links = input.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  if (!links.length) throw new Error('请先粘贴至少一条代理分享链接');
  return links.map((link, index) => {
    try { return parseProxyLink(link); }
    catch (error) {
      const message = error instanceof Error ? error.message : '未知错误';
      throw new Error(links.length > 1 ? `第 ${index + 1} 条链接：${message}` : message);
    }
  });
}

function compact<T extends UnknownRecord>(record: T): T {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined && value !== '')) as T;
}

function transportOptions(proxy: ParsedProxy): UnknownRecord {
  if (proxy.transport === 'ws') {
    return {
      'ws-opts': compact({
        path: proxy.path,
        headers: proxy.host ? { Host: proxy.host } : undefined,
      }),
    };
  }
  if (proxy.transport === 'grpc') {
    return { 'grpc-opts': compact({ 'grpc-service-name': proxy.serviceName }) };
  }
  return {};
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
    return compact({ ...base, cipher: proxy.encryption, password: proxy.password });
  }

  const tlsEnabled = proxy.security !== 'none';
  return compact({
    ...base,
    ...(proxy.protocol === 'trojan' ? { password: proxy.password } : { uuid: proxy.uuid }),
    ...(proxy.protocol === 'vmess' ? { alterId: proxy.alterId || 0, cipher: proxy.encryption || 'auto' } : {}),
    tls: tlsEnabled || undefined,
    network: proxy.transport,
    servername: proxy.sni,
    flow: proxy.flow,
    'client-fingerprint': proxy.fingerprint,
    'reality-opts': proxy.security === 'reality' ? compact({
      'public-key': proxy.publicKey,
      'short-id': proxy.shortId,
    }) : undefined,
    ...transportOptions(proxy),
  });
}

export function toMihomoYaml(proxies: ParsedProxy[]): string {
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
    security: proxy.protocol === 'vmess' ? proxy.encryption || 'auto' : undefined,
    alter_id: proxy.protocol === 'vmess' ? proxy.alterId || 0 : undefined,
    flow: proxy.flow,
    network: proxy.transport === 'tcp' ? 'tcp' : undefined,
    tls,
    transport: toSingBoxTransport(proxy),
  });
}

export function toSingBoxJson(proxies: ParsedProxy[]): string {
  return JSON.stringify({ outbounds: proxies.map(toSingBoxOutbound) }, null, 2);
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
    path: proxy.path || '',
    tls: proxy.security === 'none' ? '' : proxy.security,
    sni: proxy.sni || '',
    fp: proxy.fingerprint || '',
  }))}`;
}

function buildShadowsocks(proxy: ParsedProxy): string {
  if (!proxy.encryption || !proxy.password) throw new Error(`${proxy.name} 缺少 cipher 或 password`);
  const credentials = encodeBase64(`${proxy.encryption}:${proxy.password}`).replace(/=+$/, '');
  return `ss://${credentials}@${formatHost(proxy.server)}:${proxy.port}#${encodeURIComponent(proxy.name)}`;
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
  const grpc = read(proxy, 'grpc-opts', 'grpcOpts') as UnknownRecord | undefined;
  const network = asString(read(proxy, 'network')) || 'tcp';

  return {
    protocol,
    name,
    server,
    port: parsePort(asNumber(proxy.port)),
    uuid: asString(proxy.uuid),
    password: asString(proxy.password),
    encryption: asString(read(proxy, 'cipher', 'encryption')) || (protocol === 'vless' ? 'none' : undefined),
    transport: network,
    security: reality ? 'reality' : proxy.tls ? 'tls' : 'none',
    sni: asString(read(proxy, 'servername', 'sni')),
    flow: asString(proxy.flow),
    publicKey: reality ? asString(read(reality, 'public-key', 'publicKey')) : undefined,
    shortId: reality ? asString(read(reality, 'short-id', 'shortId')) : undefined,
    fingerprint: asString(read(proxy, 'client-fingerprint', 'clientFingerprint')),
    path: ws ? asString(ws.path) : undefined,
    host: wsHeaders ? asString(read(wsHeaders, 'Host', 'host')) : undefined,
    serviceName: grpc ? asString(read(grpc, 'grpc-service-name', 'serviceName')) : undefined,
    alterId: asNumber(read(proxy, 'alterId', 'alter-id')),
    raw: '',
  };
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
