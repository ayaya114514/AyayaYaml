import assert from 'node:assert/strict';
import test from 'node:test';
import { parse as parseYaml } from 'yaml';
import {
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
