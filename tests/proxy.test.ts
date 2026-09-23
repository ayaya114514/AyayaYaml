import assert from 'node:assert/strict';
import test from 'node:test';
import { parse as parseYaml } from 'yaml';
import {
  inspectMihomoYaml,
  inspectProxyLinks,
  mihomoYamlToShareLinks,
  parseProxyLink,
  parseProxyLinks,
  toMihomoYaml,
  toSingBoxJson,
} from '../lib/proxy.ts';

const realityLink = 'vless\\://8133d14c-a942-4ce3-9424-13b9395fbf1d@82.139.194.56:443?encryption=none&security=reality&type=tcp&sni=elaon.de&fp=chrome&pbk=XSw3PublicKey&sid=f7d552&flow=xtls-rprx-vision#Reality%20Demo';

test('parses all important VLESS Reality fields', () => {
  const proxy = parseProxyLink(realityLink);
  assert.deepEqual({
    protocol: proxy.protocol,
    server: proxy.server,
    port: proxy.port,
    uuid: proxy.uuid,
    transport: proxy.transport,
    security: proxy.security,
    sni: proxy.sni,
    flow: proxy.flow,
    publicKey: proxy.publicKey,
    shortId: proxy.shortId,
    fingerprint: proxy.fingerprint,
  }, {
    protocol: 'vless',
    server: '82.139.194.56',
    port: 443,
    uuid: '8133d14c-a942-4ce3-9424-13b9395fbf1d',
    transport: 'tcp',
    security: 'reality',
    sni: 'elaon.de',
    flow: 'xtls-rprx-vision',
    publicKey: 'XSw3PublicKey',
    shortId: 'f7d552',
    fingerprint: 'chrome',
  });
});

test('creates Mihomo Reality options without dropping fields', () => {
  const yaml = toMihomoYaml(parseProxyLinks(realityLink));
  const document = parseYaml(yaml) as { proxies: Array<Record<string, unknown>> };
  const proxy = document.proxies[0];
  assert.equal(proxy.type, 'vless');
  assert.equal(proxy.servername, 'elaon.de');
  assert.equal(proxy.flow, 'xtls-rprx-vision');
  assert.equal(proxy['client-fingerprint'], 'chrome');
  assert.deepEqual(proxy['reality-opts'], { 'public-key': 'XSw3PublicKey', 'short-id': 'f7d552' });
});

test('creates sing-box Reality TLS structure', () => {
  const output = JSON.parse(toSingBoxJson(parseProxyLinks(realityLink))) as {
    outbounds: Array<{
      type: string;
      tls: {
        server_name: string;
        utls: { fingerprint: string };
        reality: Record<string, unknown>;
      };
    }>;
  };
  const outbound = output.outbounds[0];
  assert.equal(outbound.type, 'vless');
  assert.equal(outbound.tls.server_name, 'elaon.de');
  assert.equal(outbound.tls.utls.fingerprint, 'chrome');
  assert.deepEqual(outbound.tls.reality, { enabled: true, public_key: 'XSw3PublicKey', short_id: 'f7d552' });
});

test('round-trips Mihomo YAML back to a VLESS share link', () => {
  const yaml = toMihomoYaml(parseProxyLinks(realityLink));
  const rebuilt = mihomoYamlToShareLinks(yaml);
  const proxy = parseProxyLink(rebuilt);
  assert.equal(proxy.uuid, '8133d14c-a942-4ce3-9424-13b9395fbf1d');
  assert.equal(proxy.security, 'reality');
  assert.equal(proxy.publicKey, 'XSw3PublicKey');
  assert.equal(proxy.shortId, 'f7d552');
  assert.equal(proxy.flow, 'xtls-rprx-vision');
});

test('keeps unsupported Mihomo nodes visible without blocking supported conversions', () => {
  const yaml = `proxies:
  - name: Supported Reality
    type: vless
    server: supported.example.com
    port: 443
    uuid: demo-uuid
    tls: true
  - name: Unsupported Hysteria
    type: hysteria2
    server: unsupported.example.com
    port: 8443
    password: demo-password`;
  const inspection = inspectMihomoYaml(yaml);

  assert.equal(inspection.nodes.length, 2);
  assert.equal(inspection.nodes[0].convertible, true);
  assert.equal(inspection.nodes[1].convertible, false);
  assert.equal(inspection.nodes[1].protocol, 'hysteria2');
  assert.match(inspection.nodes[1].warning || '', /Unsupported Hysteria.*hysteria2.*暂不支持/);
  assert.match(inspection.shareLinks, /^vless:\/\//);
  assert.doesNotMatch(inspection.shareLinks, /hysteria2/);
  assert.equal(mihomoYamlToShareLinks(yaml), inspection.shareLinks);
});

test('keeps valid share links when another line cannot be parsed', () => {
  const input = `# comments and blank lines are ignored

${realityLink}
hysteria2://secret@unsupported.example.com:443
trojan://secret@trojan.example.com:443?security=tls&sni=cdn.example.com#Trojan`;
  const inspection = inspectProxyLinks(input);

  assert.equal(inspection.nodes.length, 3);
  assert.equal(inspection.proxies.length, 2);
  assert.equal(inspection.nodes[0].lineNumber, 3);
  assert.equal(inspection.nodes[1].lineNumber, 4);
  assert.equal(inspection.nodes[1].parsed, undefined);
  assert.match(inspection.nodes[1].warning || '', /暂不支持/);
  assert.equal(inspection.nodes[2].parsed?.protocol, 'trojan');
  assert.match(toMihomoYaml(inspection.proxies), /Reality Demo/);
  assert.match(toMihomoYaml(inspection.proxies), /Trojan/);
  assert.throws(() => parseProxyLinks(input), /第 4 行.*暂不支持/);
});

test('parses VMess, Trojan and Shadowsocks formats', () => {
  const vmessPayload = Buffer.from(JSON.stringify({
    v: '2', ps: 'VMess Demo', add: 'vmess.example.com', port: '443', id: 'demo-uuid', aid: '0', net: 'ws', tls: 'tls', path: '/ws', host: 'cdn.example.com',
  })).toString('base64');
  const vmess = parseProxyLink(`vmess://${vmessPayload}`);
  assert.equal(vmess.transport, 'ws');
  assert.equal(vmess.host, 'cdn.example.com');

  const trojan = parseProxyLink('trojan://secret@trojan.example.com:443?security=tls&sni=cdn.example.com#Trojan');
  assert.equal(trojan.password, 'secret');
  assert.equal(trojan.sni, 'cdn.example.com');

  const credentials = Buffer.from('aes-256-gcm:password').toString('base64').replace(/=+$/, '');
  const shadowsocks = parseProxyLink(`ss://${credentials}@ss.example.com:8388#SS`);
  assert.equal(shadowsocks.encryption, 'aes-256-gcm');
  assert.equal(shadowsocks.password, 'password');
});

test('rejects incomplete ports and unsupported protocols', () => {
  assert.throws(() => parseProxyLink('vless://uuid@example.com'), /端口/);
  assert.throws(() => parseProxyLink('vless://uuid@example.com:443?security=reality'), /PublicKey/);
  assert.throws(() => parseProxyLink('hysteria2://secret@example.com:443'), /暂不支持/);
});

test('keeps TLS for Mihomo trojan nodes and writes trojan sni', () => {
  const links = mihomoYamlToShareLinks(`proxies:
  - {name: T, type: trojan, server: t.example.com, port: 443, password: p, sni: cdn.example.com}`);
  const trojan = parseProxyLink(links);
  assert.equal(trojan.security, 'tls');
  assert.equal(trojan.sni, 'cdn.example.com');

  const proxy = (parseYaml(toMihomoYaml([trojan])) as { proxies: Array<Record<string, unknown>> }).proxies[0];
  assert.equal(proxy.sni, 'cdn.example.com');
  assert.equal(proxy.servername, undefined);
});

test('does not restrict sing-box outbounds to TCP', () => {
  const output = JSON.parse(toSingBoxJson(parseProxyLinks(realityLink))) as { outbounds: Array<Record<string, unknown>> };
  assert.equal(output.outbounds[0].network, undefined);
});

test('strips IPv6 brackets from share link hosts', () => {
  const proxy = parseProxyLink('vless://uuid@[2001:db8::1]:443?security=tls#v6');
  assert.equal(proxy.server, '2001:db8::1');
  assert.match(toMihomoYaml([proxy]), /server: 2001:db8::1/);
  assert.match(mihomoYamlToShareLinks(toMihomoYaml([proxy])), /@\[2001:db8::1\]:443/);
});

test('numbers duplicate node names for Mihomo and sing-box', () => {
  const proxies = parseProxyLinks('trojan://p@a.example.com:443#HK\ntrojan://p@b.example.com:443#HK');
  const yaml = parseYaml(toMihomoYaml(proxies)) as { proxies: Array<{ name: string }>; 'proxy-groups': Array<{ proxies: string[] }> };
  assert.deepEqual(yaml.proxies.map((proxy) => proxy.name), ['HK', 'HK 2']);
  assert.deepEqual(yaml['proxy-groups'][0].proxies, ['HK', 'HK 2']);
  const singbox = JSON.parse(toSingBoxJson(proxies)) as { outbounds: Array<{ tag: string }> };
  assert.deepEqual(singbox.outbounds.map((outbound) => outbound.tag), ['HK', 'HK 2']);
});

test('converts httpupgrade, h2 and VMess gRPC transports', () => {
  const upgrade = parseProxyLink('vless://u@a.example.com:443?type=httpupgrade&path=%2Fup&host=cdn.example.com&security=tls#Up');
  const upgradeYaml = (parseYaml(toMihomoYaml([upgrade])) as { proxies: Array<Record<string, unknown>> }).proxies[0];
  assert.equal(upgradeYaml.network, 'ws');
  assert.deepEqual(upgradeYaml['ws-opts'], { path: '/up', headers: { Host: 'cdn.example.com' }, 'v2ray-http-upgrade': true });
  const upgradeBox = JSON.parse(toSingBoxJson([upgrade])) as { outbounds: Array<{ transport: unknown }> };
  assert.deepEqual(upgradeBox.outbounds[0].transport, { type: 'httpupgrade', path: '/up', host: 'cdn.example.com' });
  assert.equal(parseProxyLink(mihomoYamlToShareLinks(toMihomoYaml([upgrade]))).transport, 'httpupgrade');

  const h2 = parseProxyLink('vless://u@a.example.com:443?type=http&path=%2Fh2&host=cdn.example.com&security=tls#H2');
  assert.equal(h2.transport, 'h2');
  const h2Box = JSON.parse(toSingBoxJson([h2])) as { outbounds: Array<{ transport: unknown }> };
  assert.deepEqual(h2Box.outbounds[0].transport, { type: 'http', path: '/h2', host: ['cdn.example.com'] });

  const vmessPayload = Buffer.from(JSON.stringify({ add: 'a.example.com', port: 443, id: 'u', net: 'grpc', path: 'svc', tls: 'tls' })).toString('base64');
  const vmess = parseProxyLink(`vmess://${vmessPayload}`);
  assert.equal(vmess.serviceName, 'svc');
  assert.match(toMihomoYaml([vmess]), /grpc-service-name: svc/);
});

test('keeps alpn and allowInsecure', () => {
  const proxy = parseProxyLink('trojan://p@a.example.com:443?alpn=h2,http%2F1.1&allowInsecure=1#T');
  const yaml = (parseYaml(toMihomoYaml([proxy])) as { proxies: Array<Record<string, unknown>> }).proxies[0];
  assert.deepEqual(yaml.alpn, ['h2', 'http/1.1']);
  assert.equal(yaml['skip-cert-verify'], true);
  const box = JSON.parse(toSingBoxJson([proxy])) as { outbounds: Array<{ tls: Record<string, unknown> }> };
  assert.equal(box.outbounds[0].tls.insecure, true);
  assert.deepEqual(box.outbounds[0].tls.alpn, ['h2', 'http/1.1']);
});

test('rejects transports and plugins that cannot be converted', () => {
  assert.throws(() => parseProxyLink('vless://u@a.example.com:443?type=xhttp&security=tls'), /暂不支持 xhttp 传输/);
  assert.throws(() => parseProxyLink('ss://YWVzLTI1Ni1nY206cGFzcw@a.example.com:8388/?plugin=kcptun#K'), /暂不支持 SS 插件/);
  const inspection = inspectMihomoYaml(`proxies:
  - {name: X, type: vless, server: a.example.com, port: 443, uuid: u, network: xhttp}`);
  assert.equal(inspection.nodes[0].convertible, false);
  assert.match(inspection.nodes[0].warning || '', /xhttp.*暂不支持/);
});

test('parses SIP002 plugin links and names containing #', () => {
  const proxy = parseProxyLink('ss://YWVzLTI1Ni1nY206cGFzcw@a.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#A%23B');
  assert.equal(proxy.name, 'A#B');
  assert.equal(proxy.plugin, 'obfs-local');
  const yaml = (parseYaml(toMihomoYaml([proxy])) as { proxies: Array<Record<string, unknown>> }).proxies[0];
  assert.equal(yaml.plugin, 'obfs');
  assert.deepEqual(yaml['plugin-opts'], { mode: 'http', host: 'cdn.example.com' });
  const box = JSON.parse(toSingBoxJson([proxy])) as { outbounds: Array<Record<string, unknown>> };
  assert.equal(box.outbounds[0].plugin, 'obfs-local');
  assert.equal(box.outbounds[0].plugin_opts, 'obfs=http;obfs-host=cdn.example.com');
  const rebuilt = parseProxyLink(mihomoYamlToShareLinks(toMihomoYaml([proxy])));
  assert.equal(rebuilt.pluginOpts, 'obfs=http;obfs-host=cdn.example.com');
});

test('decodes Base64 subscriptions', () => {
  const subscription = Buffer.from(`${realityLink.replace('\\:', ':')}\ntrojan://p@a.example.com:443#T\n`).toString('base64');
  const inspection = inspectProxyLinks(`${subscription.slice(0, 40)}\n${subscription.slice(40)}`);
  assert.equal(inspection.base64, true);
  assert.equal(inspection.proxies.length, 2);
  assert.equal(inspectProxyLinks(realityLink).base64, false);
});
