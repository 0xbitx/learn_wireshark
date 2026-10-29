
(function () {
    'use strict';

    var MAX_PACKETS = 5000;            
    var MAX_BYTES = 128 * 1024 * 1024; 
    var MAX_HEX_BYTES = 2048;
    var HEX = [];
    for (var hi = 0; hi < 256; hi++) HEX[hi] = (hi < 16 ? '0' : '') + hi.toString(16);

    var SERVICES = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        67: 'dhcp', 68: 'dhcp', 69: 'tftp', 80: 'http', 110: 'pop3', 111: 'rpcbind',
        123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn',
        143: 'imap', 161: 'snmp', 162: 'snmptrap', 179: 'bgp', 194: 'irc', 389: 'ldap',
        443: 'https', 445: 'smb', 465: 'smtps', 514: 'syslog', 515: 'lpd', 587: 'submission',
        631: 'ipp', 636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1080: 'socks',
        1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs', 3306: 'mysql',
        3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
        8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb'
    };

    var IP_PROTOS = {
        1: 'ICMP', 2: 'IGMP', 4: 'IPIP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE',
        50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP'
    };

    var ETHERTYPES = {
        0x0800: 'IPv4', 0x0806: 'ARP', 0x8035: 'RARP', 0x8100: '802.1Q VLAN',
        0x86dd: 'IPv6', 0x8847: 'MPLS', 0x8863: 'PPPoE Discovery', 0x8864: 'PPPoE Session',
        0x88a8: '802.1ad QinQ', 0x88cc: 'LLDP', 0x888e: '802.1X'
    };

    var DNS_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 13: 'HINFO', 15: 'MX',
        16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 39: 'DNAME', 41: 'OPT',
        43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS',
        99: 'SPF', 255: 'ANY'
    };

    var DNS_RCODES = {
        0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name',
        4: 'Not implemented', 5: 'Refused'
    };

    var TLS_CONTENT = {
        20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data',
        24: 'Heartbeat'
    };

    var TLS_HANDSHAKE = {
        0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket',
        8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange',
        13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify',
        16: 'Client Key Exchange', 20: 'Finished'
    };

    var TLS_VERSIONS = {
        0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'
    };

    var ICMP_TYPES = {
        0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench',
        5: 'Redirect', 8: 'Echo (ping) request', 9: 'Router advertisement',
        10: 'Router solicitation', 11: 'Time-to-live exceeded', 13: 'Timestamp request',
        14: 'Timestamp reply'
    };

    var ICMPV6_TYPES = {
        1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded',
        4: 'Parameter problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply',
        133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation',
        136: 'Neighbor advertisement'
    };

    function hex(v, width) {
        return (v >>> 0).toString(16).toUpperCase().padStart(width || 2, '0');
    }

    function be16(b, o) {
        return (b[o] << 8) | b[o + 1];
    }

    function be32(b, o) {
        return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
    }

    function mac(b, o) {
        return HEX[b[o]] + ':' + HEX[b[o + 1]] + ':' + HEX[b[o + 2]] + ':' +
            HEX[b[o + 3]] + ':' + HEX[b[o + 4]] + ':' + HEX[b[o + 5]];
    }

    function ipv4(b, o) {
        return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3];
    }

    function ipv6(b, o) {
        var parts = [];
        for (var i = 0; i < 8; i++) parts.push(be16(b, o + i * 2).toString(16));
        var best = -1, bestLen = 1;
        for (var j = 0; j < 8;) {
            if (parts[j] === '0') {
                var k = j;
                while (k < 8 && parts[k] === '0') k++;
                if (k - j > bestLen) { best = j; bestLen = k - j; }
                j = k;
            } else {
                j++;
            }
        }
        if (best >= 0) {
            return parts.slice(0, best).join(':') + '::' + parts.slice(best + bestLen).join(':');
        }
        return parts.join(':');
    }

    function latin1(b, start, end) {
        var out = '';
        var step = 4096;
        for (var i = start; i < end; i += step) {
            out += String.fromCharCode.apply(null, b.subarray(i, Math.min(i + step, end)));
        }
        return out;
    }

    function isMostlyText(b, start, end) {
        var n = end - start;
        if (n <= 0) return false;
        var printable = 0;
        for (var i = start; i < end; i++) {
            var c = b[i];
            if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
        }
        return printable / n > 0.85;
    }

    function fmtBytes(n) {
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
        if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
        return (n / 1073741824).toFixed(2) + ' GB';
    }

    function esc(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function clip(str, max) {
        str = String(str || '');
        return str.length > max ? str.slice(0, max) + '…' : str;
    }

    function parseCapture(buffer) {
        if (!buffer || buffer.byteLength < 12) return null;
        var dv = new DataView(buffer);
        var magic = dv.getUint32(0, false);
        if (magic === 0x0a0d0d0a) return parsePcapng(buffer);
        return parsePcap(buffer);
    }

    function parsePcap(buffer) {
        var dv = new DataView(buffer);
        var magic = dv.getUint32(0, false);
        var little, nano = false;
        if (magic === 0xa1b2c3d4) { little = false; }
        else if (magic === 0xd4c3b2a1) { little = true; }
        else if (magic === 0xa1b23c4d) { little = false; nano = true; }
        else if (magic === 0x4d3cb2a1) { little = true; nano = true; }
        else return null;
        if (buffer.byteLength < 24) return null;

        var linkType = dv.getUint32(20, little);
        var packets = [];
        var off = 24;
        var truncated = false;

        while (off + 16 <= buffer.byteLength) {
            var tsSec = dv.getUint32(off, little);
            var tsFrac = dv.getUint32(off + 4, little);
            var inclLen = dv.getUint32(off + 8, little);
            var origLen = dv.getUint32(off + 12, little);
            off += 16;
            if (inclLen === 0 || off + inclLen > buffer.byteLength) { truncated = true; break; }
            packets.push({
                time: tsSec + tsFrac / (nano ? 1e9 : 1e6),
                len: origLen || inclLen,
                cap: inclLen,
                bytes: new Uint8Array(buffer, off, inclLen),
                linkType: linkType
            });
            off += inclLen;
            if (packets.length >= MAX_PACKETS) { truncated = off < buffer.byteLength; break; }
        }

        return { format: 'pcap', linkType: linkType, packets: packets, truncated: truncated };
    }

    function parsePcapng(buffer) {
        var dv = new DataView(buffer);
        var byteOrder = buffer.byteLength >= 12 ? dv.getUint32(8, false) : 0x4d3c2b1a;
        var little = byteOrder !== 0x1a2b3c4d;
        var interfaces = [];
        var packets = [];
        var off = 0;
        var truncated = false;

        while (off + 12 <= buffer.byteLength) {
            var type = dv.getUint32(off, little);
            var len = dv.getUint32(off + 4, little);
            if (len < 12 || off + len > buffer.byteLength) { truncated = true; break; }

            if (type === 1) {
                var iface = { linkType: dv.getUint16(off + 8, little), tsresol: 6 };
                var opt = off + 16;
                var optEnd = off + len - 4;
                while (opt + 4 <= optEnd) {
                    var code = dv.getUint16(opt, little);
                    var olen = dv.getUint16(opt + 2, little);
                    if (code === 0) break;
                    if (code === 9 && olen >= 1) {
                        var rawRes = dv.getUint8(opt + 4);
                        iface.tsresol = (rawRes & 0x80) ? -(rawRes & 0x7f) : (rawRes & 0x7f);
                    }
                    opt += 4 + ((olen + 3) & ~3);
                }
                interfaces.push(iface);
            } else if (type === 6) {
                var ifid = dv.getUint32(off + 8, little);
                var tsHigh = dv.getUint32(off + 12, little);
                var tsLow = dv.getUint32(off + 16, little);
                var capLen = dv.getUint32(off + 20, little);
                var origLen = dv.getUint32(off + 24, little);
                var ifaceDef = interfaces[ifid] || { linkType: 1, tsresol: 6 };
                var dataStart = off + 28;
                if (dataStart + capLen > off + len) { truncated = true; break; }
                var denom = ifaceDef.tsresol >= 0
                    ? Math.pow(10, ifaceDef.tsresol)
                    : Math.pow(2, -ifaceDef.tsresol);
                packets.push({
                    time: (tsHigh * 4294967296 + tsLow) / denom,
                    len: origLen || capLen,
                    cap: capLen,
                    bytes: new Uint8Array(buffer, dataStart, capLen),
                    linkType: ifaceDef.linkType
                });
            } else if (type === 3) {
                var spbLen = dv.getUint32(off + 8, little);
                var spbStart = off + 12;
                var spbCap = Math.min(spbLen, len - 16);
                if (spbStart + spbCap > off + len) { truncated = true; break; }
                var spbIface = interfaces[0] || { linkType: 1 };
                packets.push({
                    time: null,
                    len: spbLen,
                    cap: spbCap,
                    bytes: new Uint8Array(buffer, spbStart, spbCap),
                    linkType: spbIface.linkType
                });
            }

            if (type === 3 || type === 6) {
                if (packets.length >= MAX_PACKETS) { truncated = off + len < buffer.byteLength; break; }
            }
            off += len;
        }

        return {
            format: 'pcapng',
            linkType: interfaces[0] ? interfaces[0].linkType : 1,
            packets: packets,
            truncated: truncated
        };
    }

    function newContext() {
        return {
            src: '', dst: '', proto: 'DATA', info: '', cls: 'other',
            transport: '', ports: [], chain: [], fields: {}, payload: null
        };
    }

    function layer(tree, name, fields) {
        tree.push({ name: name, fields: fields || [] });
    }

    function mergeFields(ctx, obj) {
        if (!obj) return;
        for (var key in obj) {
            if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
            var value = obj[key];
            if (value === undefined || value === null || value === '') continue;
            ctx.fields[key] = value;
        }
    }

    function decodeFrame(bytes, linkType) {
        var tree = [];
        var ctx = newContext();
        try {
            if (linkType === 1) {
                decodeEthernet(bytes, tree, ctx);
            } else if (linkType === 113) {
                decodeLinuxSll(bytes, tree, ctx);
            } else if (linkType === 276) {
                decodeLinuxSll2(bytes, tree, ctx);
            } else if (linkType === 0 || linkType === 108) {
                decodeNullLoopback(bytes, tree, ctx);
            } else if (linkType === 101 || linkType === 12 || linkType === 14 || linkType === 228 || linkType === 229) {
                decodeRawIp(bytes, tree, ctx);
            } else {
                layer(tree, 'Data', [['Length', bytes.length]]);
                ctx.proto = 'DATA';
                ctx.info = 'Unsupported link type ' + linkType;
            }
        } catch (err) {
            ctx.proto = ctx.proto || 'DATA';
            ctx.info = 'Malformed packet: ' + (err && err.message ? err.message : err);
            ctx.cls = 'other';
            layer(tree, 'Malformed Packet', [['Error', String(err && err.message || err)]]);
        }
        return {
            tree: tree, src: ctx.src, dst: ctx.dst, proto: ctx.proto, info: ctx.info,
            cls: ctx.cls, transport: ctx.transport, ports: ctx.ports,
            chain: ctx.chain, fields: ctx.fields, payload: ctx.payload
        };
    }

    function etherTypeName(type) {
        return ETHERTYPES[type] || ('0x' + hex(type, 4));
    }

    function protoName(num) {
        return IP_PROTOS[num] || ('IP protocol ' + num);
    }

    function decodeEthernet(b, tree, ctx) {
        if (b.length < 14) return;
        var dst = mac(b, 0);
        var src = mac(b, 6);
        var type = be16(b, 12);
        var ethType = type;
        var off = 14;
        var fields = [['Destination', dst], ['Source', src]];

        while ((type === 0x8100 || type === 0x88a8) && off + 4 <= b.length) {
            var tci = be16(b, off);
            var vlanId = tci & 0x0fff;
            fields.push(['VLAN', vlanId + ' (priority ' + ((tci >> 13) & 7) + ')']);
            ctx.fields['vlan.id'] = (ctx.fields['vlan.id'] || []).concat([vlanId]);
            ctx.chain.push('vlan');
            type = be16(b, off + 2);
            off += 4;
        }

        fields.push(['Type', etherTypeName(ethType) + ' (0x' + hex(ethType, 4) + ')']);
        if (type !== ethType) {
            fields.push(['VLAN Type', etherTypeName(type) + ' (0x' + hex(type, 4) + ')']);
            ctx.fields['vlan.etype'] = type;
        }
        layer(tree, 'Ethernet II, Src: ' + src + ', Dst: ' + dst, fields);
        ctx.fields['eth.src'] = src;
        ctx.fields['eth.dst'] = dst;
        ctx.fields['eth.type'] = ethType;
        ctx.chain.push('eth');
        dispatchEtherType(b, off, type, tree, ctx);
    }

    function decodeLinuxSll(b, tree, ctx) {
        if (b.length < 16) return;
        var pktType = be16(b, 0);
        var proto = be16(b, 14);
        var addrLen = be16(b, 4);
        layer(tree, 'Linux cooked capture', [
            ['Packet Type', pktType], ['Link-layer address length', addrLen],
            ['Link-layer address', mac(b, 6)], ['Protocol', etherTypeName(proto) + ' (0x' + hex(proto, 4) + ')']
        ]);
        ctx.chain.push('sll');
        dispatchEtherType(b, 16, proto, tree, ctx);
    }

    function decodeLinuxSll2(b, tree, ctx) {
        if (b.length < 20) return;
        var proto = be16(b, 0);
        layer(tree, 'Linux cooked capture v2', [
            ['Protocol', etherTypeName(proto) + ' (0x' + hex(proto, 4) + ')'],
            ['Interface index', be32(b, 4)],
            ['Packet Type', b[10]],
            ['Link-layer address length', b[11]]
        ]);
        ctx.chain.push('sll2');
        dispatchEtherType(b, 20, proto, tree, ctx);
    }

    function decodeNullLoopback(b, tree, ctx) {
        if (b.length < 4) return;
        layer(tree, 'Null/Loopback', [['Family', be32(b, 0) === 2 ? 'IPv4 (2)' : String(be32(b, 0))]]);
        decodeRawIp(b.subarray(4), tree, ctx);
    }

    function decodeRawIp(b, tree, ctx) {
        if (!b.length) return;
        var version = b[0] >>> 4;
        if (version === 4) decodeIPv4(b, 0, tree, ctx);
        else if (version === 6) decodeIPv6(b, 0, tree, ctx);
        else {
            layer(tree, 'Data', [['Length', b.length]]);
            ctx.proto = 'DATA';
            ctx.info = 'Raw data (' + b.length + ' bytes)';
        }
    }

    function dispatchEtherType(b, off, type, tree, ctx) {
        if (type === 0x0800) {
            decodeIPv4(b, off, tree, ctx);
        } else if (type === 0x86dd) {
            decodeIPv6(b, off, tree, ctx);
        } else if (type === 0x0806 || type === 0x8035) {
            decodeARP(b, off, tree, ctx, type === 0x8035);
        } else if (type <= 0x05dc) {
            layer(tree, 'IEEE 802.3 LLC', [['Length', type]]);
            ctx.proto = 'LLC';
            ctx.info = '802.3 frame, length ' + type;
        } else {
            layer(tree, 'Data', [['Ethertype', '0x' + hex(type, 4)], ['Length', Math.max(0, b.length - off)]]);
            ctx.proto = 'ETH';
            ctx.info = 'Ethertype 0x' + hex(type, 4);
        }
    }

    function decodeIPv4(b, off, tree, ctx) {
        if (off + 20 > b.length) return;
        var vihl = b[off];
        var version = vihl >>> 4;
        var ihl = (vihl & 0x0f) * 4;
        if (ihl < 20) ihl = 20;
        if (off + ihl > b.length) return;

        var total = be16(b, off + 2) || (b.length - off);
        var id = be16(b, off + 4);
        var flagsFrag = be16(b, off + 6);
        var ttl = b[off + 8];
        var proto = b[off + 9];
        var src = ipv4(b, off + 12);
        var dst = ipv4(b, off + 16);
        var fragOffset = flagsFrag & 0x1fff;
        var df = (flagsFrag & 0x4000) ? "Don't fragment" : '';
        var mf = (flagsFrag & 0x2000) ? 'More fragments' : '';
        var flagText = [df, mf].filter(Boolean).join(', ') || 'None';

        ctx.src = src;
        ctx.dst = dst;
        ctx.fields['ip.src'] = src;
        ctx.fields['ip.dst'] = dst;
        ctx.fields['ip.addr'] = [src, dst];
        ctx.fields['ip.ttl'] = ttl;
        ctx.fields['ip.proto'] = proto;
        ctx.fields['ip.len'] = total;
        ctx.fields['ip.id'] = id;
        ctx.fields['ip.flags'] = flagsFrag >>> 13;
        ctx.fields['ip.frag_offset'] = fragOffset;

        layer(tree, 'Internet Protocol Version 4, Src: ' + src + ', Dst: ' + dst, [
            ['Version', version],
            ['Header Length', ihl + ' bytes'],
            ['Differentiated Services', '0x' + hex(b[off + 1], 2)],
            ['Total Length', total],
            ['Identification', '0x' + hex(id, 4)],
            ['Flags', flagText],
            ['Fragment Offset', fragOffset],
            ['Time to Live', ttl],
            ['Protocol', protoName(proto) + ' (' + proto + ')'],
            ['Header Checksum', '0x' + hex(be16(b, off + 10), 4)],
            ['Source Address', src],
            ['Destination Address', dst]
        ]);
        ctx.chain.push('ip');

        var end = Math.min(b.length, off + total);
        if (fragOffset !== 0) {
            ctx.proto = protoName(proto);
            ctx.info = 'Fragmented IP packet (offset ' + fragOffset + ')';
            ctx.cls = 'other';
            return;
        }
        dispatchTransport(b, off + ihl, end, proto, tree, ctx);
    }

    function decodeIPv6(b, off, tree, ctx) {
        if (off + 40 > b.length) return;
        var first = be32(b, off);
        var payloadLen = be16(b, off + 4);
        var next = b[off + 6];
        var hop = b[off + 7];
        var src = ipv6(b, off + 8);
        var dst = ipv6(b, off + 24);

        ctx.src = src;
        ctx.dst = dst;
        ctx.fields['ipv6.src'] = src;
        ctx.fields['ipv6.dst'] = dst;
        ctx.fields['ipv6.addr'] = [src, dst];
        ctx.fields['ipv6.nxt'] = next;
        ctx.fields['ipv6.hlim'] = hop;
        ctx.fields['ipv6.plen'] = payloadLen;

        layer(tree, 'Internet Protocol Version 6, Src: ' + src + ', Dst: ' + dst, [
            ['Version', first >>> 28],
            ['Traffic Class', '0x' + hex((first >>> 20) & 0xff, 2)],
            ['Flow Label', '0x' + hex(first & 0xfffff, 5)],
            ['Payload Length', payloadLen],
            ['Next Header', protoName(next) + ' (' + next + ')'],
            ['Hop Limit', hop],
            ['Source Address', src],
            ['Destination Address', dst]
        ]);
        ctx.chain.push('ipv6');

        var pos = off + 40;
        var end = Math.min(b.length, off + 40 + payloadLen);
        var guard = 0;
        while ((next === 0 || next === 43 || next === 60) && guard++ < 8) {
            if (pos + 2 > end) return;
            var extNext = b[pos];
            var extLen = (b[pos + 1] + 1) * 8;
            layer(tree, 'IPv6 Extension Header (' + protoName(next) + ')', [
                ['Next Header', protoName(extNext) + ' (' + extNext + ')'],
                ['Length', extLen + ' bytes']
            ]);
            pos += extLen;
            next = extNext;
        }
        if (next === 44) {
            if (pos + 8 > end) return;
            next = b[pos];
            pos += 8;
        }
        dispatchTransport(b, pos, end, next, tree, ctx);
    }

    function dispatchTransport(b, off, end, proto, tree, ctx) {
        if (off >= end) {
            ctx.proto = protoName(proto);
            ctx.info = 'No payload';
            ctx.cls = 'other';
            return;
        }
        if (proto === 6) {
            decodeTCP(b, off, end, tree, ctx);
        } else if (proto === 17) {
            decodeUDP(b, off, end, tree, ctx);
        } else if (proto === 1) {
            decodeICMP(b, off, end, tree, ctx, false);
        } else if (proto === 58) {
            decodeICMP(b, off, end, tree, ctx, true);
        } else {
            layer(tree, protoName(proto), [['Length', end - off]]);
            ctx.chain.push('data');
            ctx.proto = protoName(proto);
            ctx.cls = 'other';
            ctx.info = protoName(proto) + ' payload (' + (end - off) + ' bytes)';
        }
    }

    function decodeTCP(b, off, end, tree, ctx) {
        if (off + 20 > end) return;
        var sport = be16(b, off);
        var dport = be16(b, off + 2);
        var seq = be32(b, off + 4);
        var ack = be32(b, off + 8);
        var offflags = be16(b, off + 12);
        var dataOff = ((offflags >>> 12) & 0x0f) * 4;
        if (dataOff < 20) dataOff = 20;
        var flags = offflags & 0x1ff;
        var win = be16(b, off + 14);
        var flagsText = tcpFlags(flags);
        var headerEnd = Math.min(end, off + dataOff);
        var payloadLen = Math.max(0, end - headerEnd);

        var fields = [
            ['Source Port', sport + (SERVICES[sport] ? ' (' + SERVICES[sport] + ')' : '')],
            ['Destination Port', dport + (SERVICES[dport] ? ' (' + SERVICES[dport] + ')' : '')],
            ['Sequence Number', seq],
            ['Acknowledgment Number', ack],
            ['Header Length', dataOff + ' bytes'],
            ['Flags', '0x' + hex(flags, 3) + ' (' + (flagsText || 'None') + ')'],
            ['Window', win],
            ['Checksum', '0x' + hex(be16(b, off + 16), 4)],
            ['Urgent Pointer', be16(b, off + 18)],
            ['Payload Length', payloadLen]
        ];

        var options = tcpOptions(b, off + 20, Math.min(off + dataOff, end));
        if (options.length) fields.push(['Options', options.join(', ')]);

        layer(tree, 'Transmission Control Protocol, Src Port: ' + sport + ', Dst Port: ' + dport +
            ', Seq: ' + seq + ', Ack: ' + ack + ', Len: ' + payloadLen, fields);

        ctx.chain.push('tcp');
        ctx.transport = 'tcp';
        ctx.ports = [sport, dport];
        ctx.fields['tcp.srcport'] = sport;
        ctx.fields['tcp.dstport'] = dport;
        ctx.fields['tcp.port'] = [sport, dport];
        ctx.fields['tcp.seq'] = seq;
        ctx.fields['tcp.ack'] = ack;
        ctx.fields['tcp.flags'] = flags;
        ctx.fields['tcp.flags.fin'] = (flags & 0x001) ? 1 : 0;
        ctx.fields['tcp.flags.syn'] = (flags & 0x002) ? 1 : 0;
        ctx.fields['tcp.flags.rst'] = (flags & 0x004) ? 1 : 0;
        ctx.fields['tcp.flags.psh'] = (flags & 0x008) ? 1 : 0;
        ctx.fields['tcp.flags.ack'] = (flags & 0x010) ? 1 : 0;
        ctx.fields['tcp.flags.urg'] = (flags & 0x020) ? 1 : 0;
        ctx.fields['tcp.flags.ece'] = (flags & 0x040) ? 1 : 0;
        ctx.fields['tcp.flags.cwr'] = (flags & 0x080) ? 1 : 0;
        ctx.fields['tcp.window'] = win;
        ctx.fields['tcp.len'] = payloadLen;
        ctx.fields['tcp.hdr_len'] = dataOff;

        var app = dissectPayload(b, headerEnd, end, tree, ctx, sport, dport, 'tcp');
        if (app) {
            ctx.proto = app.proto;
            ctx.cls = app.cls;
            ctx.info = app.info;
        } else {
            ctx.proto = 'TCP';
            ctx.cls = 'tcp';
            ctx.info = sport + ' → ' + dport + ' [' + (flagsText || 'None') + '] Seq=' + seq +
                ' Ack=' + ack + ' Win=' + win + ' Len=' + payloadLen;
        }
    }

    function decodeUDP(b, off, end, tree, ctx) {
        if (off + 8 > end) return;
        var sport = be16(b, off);
        var dport = be16(b, off + 2);
        var len = be16(b, off + 4);
        var payloadStart = off + 8;
        var payloadEnd = Math.min(end, off + (len || (end - off)));

        layer(tree, 'User Datagram Protocol, Src Port: ' + sport + ', Dst Port: ' + dport, [
            ['Source Port', sport + (SERVICES[sport] ? ' (' + SERVICES[sport] + ')' : '')],
            ['Destination Port', dport + (SERVICES[dport] ? ' (' + SERVICES[dport] + ')' : '')],
            ['Length', len],
            ['Checksum', '0x' + hex(be16(b, off + 6), 4)]
        ]);

        ctx.chain.push('udp');
        ctx.transport = 'udp';
        ctx.ports = [sport, dport];
        ctx.fields['udp.srcport'] = sport;
        ctx.fields['udp.dstport'] = dport;
        ctx.fields['udp.port'] = [sport, dport];
        ctx.fields['udp.length'] = len;

        var app = dissectPayload(b, payloadStart, payloadEnd, tree, ctx, sport, dport, 'udp');
        if (app) {
            ctx.proto = app.proto;
            ctx.cls = app.cls;
            ctx.info = app.info;
        } else {
            ctx.proto = 'UDP';
            ctx.cls = 'udp';
            ctx.info = sport + ' → ' + dport + ' Len=' + (payloadEnd - payloadStart);
        }
    }

    function decodeICMP(b, off, end, tree, ctx, v6) {
        if (off + 4 > end) return;
        var type = b[off];
        var code = b[off + 1];
        var names = v6 ? ICMPV6_TYPES : ICMP_TYPES;
        var info = names[type] || ('Type ' + type);
        var fields = [
            ['Type', type + ' (' + (names[type] || 'Unknown') + ')'],
            ['Code', code],
            ['Checksum', '0x' + hex(be16(b, off + 2), 4)]
        ];
        if ((type === 0 || type === 8 || type === 128 || type === 129) && off + 8 <= end) {
            var id = be16(b, off + 4);
            var seq = be16(b, off + 6);
            fields.push(['Identifier', id]);
            fields.push(['Sequence Number', seq]);
            info += ' id=' + id + ' seq=' + seq;
        }
        var prefix = v6 ? 'icmpv6' : 'icmp';
        ctx.fields[prefix + '.type'] = type;
        ctx.fields[prefix + '.code'] = code;
        if (id !== undefined) {
            ctx.fields[prefix + '.ident'] = id;
            ctx.fields[prefix + '.seq'] = seq;
        }

        layer(tree, (v6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol'), fields);
        ctx.chain.push(v6 ? 'icmpv6' : 'icmp');
        ctx.transport = v6 ? 'icmpv6' : 'icmp';
        ctx.proto = v6 ? 'ICMPv6' : 'ICMP';
        ctx.cls = 'icmp';
        ctx.info = info;
    }

    function decodeARP(b, off, tree, ctx, isRarp) {
        if (off + 28 > b.length) return;
        var op = be16(b, off + 6);
        var sha = mac(b, off + 8);
        var spa = ipv4(b, off + 14);
        var tha = mac(b, off + 18);
        var tpa = ipv4(b, off + 24);
        var opName = isRarp
            ? (op === 3 ? 'RARP request' : op === 4 ? 'RARP reply' : 'RARP ' + op)
            : (op === 1 ? 'ARP request' : op === 2 ? 'ARP reply' : 'ARP ' + op);
        var info = op === 1
            ? 'Who has ' + tpa + '? Tell ' + spa
            : op === 2
                ? spa + ' is at ' + sha
                : opName;

        layer(tree, 'Address Resolution Protocol (' + opName + ')', [
            ['Hardware type', be16(b, off)],
            ['Protocol type', '0x' + hex(be16(b, off + 2), 4)],
            ['Hardware size', b[off + 4]],
            ['Protocol size', b[off + 5]],
            ['Opcode', op + ' (' + opName + ')'],
            ['Sender MAC address', sha],
            ['Sender IP address', spa],
            ['Target MAC address', tha],
            ['Target IP address', tpa]
        ]);

        ctx.chain.push('arp');
        ctx.src = spa;
        ctx.dst = tpa;
        ctx.proto = isRarp ? 'RARP' : 'ARP';
        ctx.cls = 'arp';
        ctx.info = info;
        ctx.fields['arp.opcode'] = op;
        ctx.fields['arp.src.hw_mac'] = sha;
        ctx.fields['arp.dst.hw_mac'] = tha;
        ctx.fields['arp.src.proto_ipv4'] = spa;
        ctx.fields['arp.dst.proto_ipv4'] = tpa;
    }

    function tcpFlags(flags) {
        var names = [];
        if (flags & 0x100) names.push('NS');
        if (flags & 0x080) names.push('CWR');
        if (flags & 0x040) names.push('ECE');
        if (flags & 0x020) names.push('URG');
        if (flags & 0x010) names.push('ACK');
        if (flags & 0x008) names.push('PSH');
        if (flags & 0x004) names.push('RST');
        if (flags & 0x002) names.push('SYN');
        if (flags & 0x001) names.push('FIN');
        return names.join(', ');
    }

    function tcpOptions(b, start, end) {
        var out = [];
        var i = start;
        while (i < end) {
            var kind = b[i];
            if (kind === 0) break;
            if (kind === 1) { i++; continue; }
            if (i + 1 >= end) break;
            var len = b[i + 1];
            if (len < 2 || i + len > end) break;
            if (kind === 2 && len === 4) out.push('MSS=' + be16(b, i + 2));
            else if (kind === 3 && len === 3) out.push('Window Scale=' + b[i + 2]);
            else if (kind === 4) out.push('SACK permitted');
            else if (kind === 5) out.push('SACK');
            else if (kind === 8 && len === 10) out.push('TSval=' + be32(b, i + 2) + ' TSecr=' + be32(b, i + 6));
            i += len;
        }
        return out;
    }

    function dissectPayload(b, off, end, tree, ctx, sport, dport, baseCls) {
        var len = end - off;
        if (len <= 0) return null;
        ctx.payload = { off: off, end: end };
        ctx.fields['data.len'] = len;

        if (len >= 5 && b[off] >= 20 && b[off] <= 24 && b[off + 1] === 0x03 && b[off + 2] <= 0x04) {
            var tls = tlsDissect(b, off, end);
            if (tls) {
                layer(tree, tls.layer.name, tls.layer.fields);
                ctx.chain.push('tls');
                mergeFields(ctx, tls.wsFields);
                return { proto: tls.proto, cls: tls.cls, info: tls.info };
            }
        }

        if (sport === 53 || dport === 53) {
            var dns = dnsDissect(b, off, end);
            if (dns) {
                layer(tree, dns.layer.name, dns.layer.fields);
                ctx.chain.push('dns');
                mergeFields(ctx, dns.wsFields);
                return { proto: dns.proto, cls: dns.cls, info: dns.info };
            }
        }

        if (isMostlyText(b, off, Math.min(end, off + 2048))) {
            var head = latin1(b, off, Math.min(end, off + 8192));
            var http = httpDissect(head);
            if (http) {
                layer(tree, http.layer.name, http.layer.fields);
                ctx.chain.push('http');
                mergeFields(ctx, http.wsFields);
                return { proto: http.proto, cls: http.cls, info: http.info };
            }
            if (/^SSH-/.test(head)) {
                var sshLine = head.split(/\r?\n/)[0].trim();
                layer(tree, 'SSH Protocol', [['Identification', sshLine]]);
                ctx.chain.push('ssh');
                mergeFields(ctx, { 'ssh.protocol': sshLine });
                return { proto: 'SSH', cls: baseCls || 'tcp', info: sshLine };
            }
        }

        var service = SERVICES[sport] || SERVICES[dport];
        if (service) {
            var first = '';
            if (isMostlyText(b, off, Math.min(end, off + 512))) {
                first = latin1(b, off, Math.min(end, off + 512)).split(/\r?\n/)[0].trim();
            }
            layer(tree, service.toUpperCase() + ' (port ' + (SERVICES[dport] ? dport : sport) + ')', [
                ['Payload Length', len],
                ['First bytes', clip(first, 160) || '—']
            ]);
            ctx.chain.push('data');
            return {
                proto: service.toUpperCase(),
                cls: baseCls || 'other',
                info: clip(first, 120) || (service + ' data (' + len + ' bytes)')
            };        }

        return null;
    }

    function parseHeaderLines(lines) {
        var map = {};
        for (var i = 0; i < lines.length; i++) {
            var idx = lines[i].indexOf(':');
            if (idx > 0) map[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
        }
        return map;
    }

    function httpDissect(head) {
        var lines = head.split(/\r?\n/);
        var first = (lines[0] || '').trim();

        var req = /^([A-Z]+) (\S+) HTTP\/(\d\.\d)$/.exec(first);
        if (req) {
            var rh = parseHeaderLines(lines.slice(1));
            var host = rh['host'] || '';
            var fields = [
                ['Request Method', req[1]],
                ['Request URI', req[2]],
                ['Request Version', 'HTTP/' + req[3]],
                ['Host', host || '—']
            ];
            if (rh['user-agent']) fields.push(['User-Agent', clip(rh['user-agent'], 160)]);
            if (rh['content-type']) fields.push(['Content-Type', rh['content-type']]);
            if (rh['content-length']) fields.push(['Content-Length', rh['content-length']]);
            if (rh['cookie']) fields.push(['Cookie', clip(rh['cookie'], 160)]);
            if (rh['referer']) fields.push(['Referer', clip(rh['referer'], 160)]);
            return {
                proto: 'HTTP',
                cls: 'http',
                info: req[1] + ' ' + req[2] + (host ? ' (' + host + ')' : ''),
                wsFields: {
                    'http.request': 1,
                    'http.request.method': req[1],
                    'http.request.uri': req[2],
                    'http.request.version': 'HTTP/' + req[3],
                    'http.host': host,
                    'http.user_agent': rh['user-agent'],
                    'http.content_type': rh['content-type'],
                    'http.content_length': rh['content-length'],
                    'http.cookie': rh['cookie'],
                    'http.referer': rh['referer']
                },
                layer: { name: 'Hypertext Transfer Protocol', fields: fields }
            };
        }

        var res = /^HTTP\/(\d\.\d) (\d{3})(?: (.*))?$/.exec(first);
        if (res) {
            var sh = parseHeaderLines(lines.slice(1));
            var rfields = [
                ['Response Version', 'HTTP/' + res[1]],
                ['Status Code', res[2]],
                ['Response Phrase', res[3] || '—']
            ];
            if (sh['content-type']) rfields.push(['Content-Type', sh['content-type']]);
            if (sh['content-length']) rfields.push(['Content-Length', sh['content-length']]);
            if (sh['server']) rfields.push(['Server', clip(sh['server'], 120)]);
            if (sh['location']) rfields.push(['Location', clip(sh['location'], 160)]);
            if (sh['set-cookie']) rfields.push(['Set-Cookie', clip(sh['set-cookie'], 160)]);
            if (sh['content-encoding']) rfields.push(['Content-Encoding', sh['content-encoding']]);
            return {
                proto: 'HTTP',
                cls: 'http',
                info: 'HTTP/' + res[1] + ' ' + res[2] + (res[3] ? ' ' + res[3] : ''),
                wsFields: {
                    'http.response': 1,
                    'http.response.version': 'HTTP/' + res[1],
                    'http.response.code': parseInt(res[2], 10),
                    'http.response.phrase': res[3] || '',
                    'http.content_type': sh['content-type'],
                    'http.content_length': sh['content-length'],
                    'http.server': sh['server'],
                    'http.location': sh['location'],
                    'http.set_cookie': sh['set-cookie'],
                    'http.content_encoding': sh['content-encoding']
                },
                layer: { name: 'Hypertext Transfer Protocol', fields: rfields }
            };
        }

        return null;
    }

    function readDnsName(b, p, end) {
        var labels = [];
        var next = -1;
        var guard = 0;
        while (p < end && guard++ < 128) {
            var len = b[p];
            if (len === 0) { p++; if (next < 0) next = p; break; }
            if ((len & 0xc0) === 0xc0) {
                if (p + 1 >= end) break;
                var ptr = ((len & 0x3f) << 8) | b[p + 1];
                if (next < 0) next = p + 2;
                p = ptr;
                continue;
            }
            if (len > 63 || p + 1 + len > end) break;
            labels.push(latin1(b, p + 1, p + 1 + len));
            p += 1 + len;
        }
        if (next < 0) next = p;
        return { name: labels.join('.'), next: next };
    }

    function dnsDissect(b, off, end) {
        if (end - off < 12) return null;
        var id = be16(b, off);
        var flags = be16(b, off + 2);
        var qd = be16(b, off + 4);
        var an = be16(b, off + 6);
        var ns = be16(b, off + 8);
        var ar = be16(b, off + 10);
        var qr = flags >>> 15;
        var opcode = (flags >>> 11) & 0xf;
        var rcode = flags & 0xf;
        var tc = (flags >>> 9) & 1;
        var rd = (flags >>> 8) & 1;
        var ra = (flags >>> 7) & 1;

        var p = off + 12;
        var names = [];
        var qtype = 0;
        var qclass = 0;
        for (var q = 0; q < Math.min(qd, 8); q++) {
            var r = readDnsName(b, p, end);
            if (!r || r.next <= p) break;
            names.push(r.name);
            p = r.next;
            if (p + 4 <= end) {
                qtype = be16(b, p);
                qclass = be16(b, p + 2);
                p += 4;
            }
        }

        var qt = DNS_TYPES[qtype] || String(qtype);
        var kind = qr ? 'Standard query response' : 'Standard query';
        var info = kind + ' 0x' + hex(id, 4) + ' ' + qt + (names.length ? ' ' + names[0] : '');

        var flagText = '0x' + hex(flags, 4) + ' (' + (qr ? 'Response' : 'Query') +
            (tc ? ', Truncated' : '') + (rd ? ', Recursion desired' : '') +
            (ra ? ', Recursion available' : '') +
            (rcode ? ', RCODE ' + rcode + ' ' + (DNS_RCODES[rcode] || '') : '') + ')';

        var fields = [
            ['Transaction ID', '0x' + hex(id, 4)],
            ['Flags', flagText],
            ['Questions', qd],
            ['Answer RRs', an],
            ['Authority RRs', ns],
            ['Additional RRs', ar]
        ];
        for (var i = 0; i < names.length; i++) {
            fields.push([names.length > 1 ? 'Query Name ' + (i + 1) : 'Query Name', names[i] || '<root>']);
        }
        if (qtype) fields.push(['Query Type', qt + ' (' + qtype + ')']);
        if (qclass) fields.push(['Query Class', qclass === 1 ? 'IN (1)' : String(qclass)]);

        return {
            proto: 'DNS',
            cls: 'dns',
            info: info,
            wsFields: {
                'dns.id': id,
                'dns.flags.response': qr,
                'dns.flags.truncated': tc,
                'dns.flags.rcode': rcode,
                'dns.qry.name': names.length === 1 ? names[0] : names,
                'dns.qry.type': qtype,
                'dns.qry.class': qclass,
                'dns.count.queries': qd,
                'dns.count.answers': an
            },
            layer: { name: 'Domain Name System (' + (qr ? 'response' : 'query') + ')', fields: fields }
        };
    }

    function tlsDissect(b, off, end) {
        if (off + 5 > end) return null;
        var ct = b[off];
        var ver = be16(b, off + 1);
        var len = be16(b, off + 3);
        var ctName = TLS_CONTENT[ct] || ('Content Type ' + ct);
        var verName = TLS_VERSIONS[ver] || ('0x' + hex(ver, 4));
        var fields = [
            ['Content Type', ctName + ' (' + ct + ')'],
            ['Version', verName],
            ['Length', len]
        ];
        var wsFields = { 'tls.record.content_type': ct, 'tls.record.version': ver };
        var info = ctName + ' (' + verName + ')';

        if (ct === 22 && end - off >= 6) {
            var hs = b[off + 5];
            var hsName = TLS_HANDSHAKE[hs] || ('Handshake ' + hs);
            fields.push(['Handshake Type', hsName + ' (' + hs + ')']);
            wsFields['tls.handshake.type'] = hs;
            info = hsName + ' (' + verName + ')';
            if (hs === 1) {
                var sni = tlsSni(b, off + 5, Math.min(end, off + 5 + len));
                if (sni) {
                    fields.push(['Server Name Indication', sni]);
                    wsFields['tls.handshake.extensions_server_name'] = sni;
                    info = 'Client Hello (SNI=' + sni + ')';
                }
            } else if (hs === 11) {
                info = 'Certificate (' + verName + ')';
            }
        } else if (ct === 21 && end - off >= 7) {
            fields.push(['Alert Level', b[off + 5]]);
            fields.push(['Alert Description', b[off + 6]]);
            wsFields['tls.alert.severity'] = b[off + 5];
            wsFields['tls.alert.description'] = b[off + 6];
            info = 'Alert (' + verName + ')';
        }

        return {
            proto: 'TLS',
            cls: 'tls',
            info: info,
            wsFields: wsFields,
            layer: { name: 'Transport Layer Security', fields: fields }
        };
    }

    function tlsSni(b, hsOff, end) {
        if (b[hsOff] !== 1) return '';
        var p = hsOff + 4;
        if (p + 34 > end) return '';
        p += 34; 
        if (p >= end) return '';
        p += 1 + b[p]; 
        if (p + 2 > end) return '';
        var csLen = be16(b, p);
        p += 2 + csLen;
        if (p + 1 > end) return '';
        p += 1 + b[p]; 
        if (p + 2 > end) return '';
        var extLen = be16(b, p);
        p += 2;
        var extEnd = Math.min(end, p + extLen);
        while (p + 4 <= extEnd) {
            var type = be16(b, p);
            var elen = be16(b, p + 2);
            p += 4;
            if (type === 0 && p + 2 <= extEnd) {
                var listLen = be16(b, p);
                var q = p + 2;
                var qEnd = Math.min(extEnd, q + listLen);
                while (q + 3 <= qEnd) {
                    var ntype = b[q];
                    var nlen = be16(b, q + 1);
                    q += 3;
                    if (ntype === 0 && q + nlen <= qEnd) {
                        return latin1(b, q, q + nlen);
                    }
                    q += nlen;
                }
            }
            p += elen;
        }
        return '';
    }

    var activeViewer = null;

    function academyEmit(type, detail) {
        try {
            document.dispatchEvent(new CustomEvent('bw:pcap', {
                detail: { type: type, detail: detail || {} }
            }));
        } catch (e) { }
    }

    function packetSnapshot(p) {
        return {
            no: p.no,
            index: p.no - 1,
            len: p.len,
            cap: p.cap,
            proto: p.dec.proto,
            cls: p.dec.cls,
            src: p.dec.src,
            dst: p.dec.dst,
            info: p.dec.info,
            transport: p.transport,
            srcport: p.srcport,
            dstport: p.dstport,
            protocols: p.protocols,
            fields: p.fields
        };
    }

    var COLUMN_DEFS = [
        { key: 'no', label: 'No.', cls: 'pc-no', width: 58, numeric: true,
          text: function (p) { return p.no; }, sortValue: function (p) { return p.no; } },
        { key: 'time', label: 'Time', cls: 'pc-time', width: 96, numeric: true,
          text: function (p, v) { return formatTime(v, p); }, sortValue: function (p) { return p.time == null ? p.rel : p.time; } },
        { key: 'src', label: 'Source', cls: 'pc-src', width: 165,
          text: function (p) { return p.dec.src || ''; }, sortValue: function (p) { return String(p.dec.src || '').toLowerCase(); } },
        { key: 'srcport', label: 'Src port', cls: 'pc-sport', width: 76, numeric: true, hidden: true,
          text: function (p) { return p.srcport === '' ? '' : p.srcport; }, sortValue: function (p) { return p.srcport === '' ? '' : Number(p.srcport); } },
        { key: 'dst', label: 'Destination', cls: 'pc-dst', width: 165,
          text: function (p) { return p.dec.dst || ''; }, sortValue: function (p) { return String(p.dec.dst || '').toLowerCase(); } },
        { key: 'dstport', label: 'Dst port', cls: 'pc-dport', width: 76, numeric: true, hidden: true,
          text: function (p) { return p.dstport === '' ? '' : p.dstport; }, sortValue: function (p) { return p.dstport === '' ? '' : Number(p.dstport); } },
        { key: 'proto', label: 'Protocol', cls: 'pc-proto', width: 92,
          text: function (p) { return p.dec.proto; }, sortValue: function (p) { return String(p.dec.proto).toLowerCase(); } },
        { key: 'len', label: 'Length', cls: 'pc-len', width: 68, numeric: true,
          text: function (p) { return p.len; }, sortValue: function (p) { return p.len; } },
        { key: 'info', label: 'Info', cls: 'pc-info', width: 0,
          text: function (p) { return p.dec.info; }, sortValue: function (p) { return String(p.dec.info).toLowerCase(); } }
    ];

    var TIME_FORMATS = [
        { key: 'relative', label: 'Seconds Since Beginning of Capture' },
        { key: 'delta', label: 'Seconds Since Previous Captured Packet' },
        { key: 'abs-local', label: 'Absolute Date and Time (local)' },
        { key: 'abs-utc', label: 'Absolute Date and Time (UTC)' }
    ];

    var DEFAULT_COLOR_RULES = [
        { id: 1, name: 'Connection reset', filter: 'tcp.flags.rst == 1', fg: '#ffffff', bg: '#7a1f1f', enabled: true },
        { id: 2, name: 'HTTP', filter: 'http', fg: '#b6e8a0', bg: '#17301a', enabled: true },
        { id: 3, name: 'TLS', filter: 'tls', fg: '#a0e8c0', bg: '#14322a', enabled: true },
        { id: 4, name: 'DNS', filter: 'dns', fg: '#a8c8f0', bg: '#17233d', enabled: true },
        { id: 5, name: 'ICMP errors', filter: 'icmp.type == 3 || icmp.type == 11 || icmpv6.type == 1', fg: '#ffffff', bg: '#5a2a14', enabled: true },
        { id: 6, name: 'ICMP', filter: 'icmp || icmpv6', fg: '#f0a0a0', bg: '#3a2020', enabled: true },
        { id: 7, name: 'ARP', filter: 'arp', fg: '#e0e0a0', bg: '#2f2f18', enabled: true },
        { id: 8, name: 'UDP', filter: 'udp', fg: '#a0c8e0', bg: '#14252e', enabled: true },
        { id: 9, name: 'TCP', filter: 'tcp', fg: '#a8c8e0', bg: '#11242f', enabled: true }
    ];

    var PROTO_LABELS = {
        frame: 'Frame', eth: 'Ethernet', sll: 'Linux cooked capture', sll2: 'Linux cooked v2',
        vlan: '802.1Q VLAN', ip: 'IPv4', ipv6: 'IPv6', arp: 'ARP', rarp: 'RARP',
        llc: 'LLC', tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', icmpv6: 'ICMPv6',
        http: 'HTTP', dns: 'DNS', tls: 'TLS', ssl: 'TLS', ssh: 'SSH', ntp: 'NTP', data: 'Data',
        mdns: 'MDNS', dhcp: 'DHCP', smtp: 'SMTP', ftp: 'FTP', telnet: 'Telnet', snmp: 'SNMP'
    };

    var STORE_COLS = 'bw-pcap-columns';
    var STORE_TIME = 'bw-pcap-timefmt';
    var STORE_COLORS = 'bw-pcap-colorrules';

    function readStore(key, fallback) {
        try {
            var raw = localStorage.getItem(key);
            if (!raw) return fallback;
            return JSON.parse(raw);
        } catch (e) { return fallback; }
    }

    function writeStore(key, value) {
        try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { }
    }

    function defaultColumns() {
        return COLUMN_DEFS.map(function (c) {
            return { key: c.key, visible: !c.hidden };
        });
    }

    function loadColumns() {
        var saved = readStore(STORE_COLS, null);
        if (!Array.isArray(saved)) return defaultColumns();
        var out = [];
        for (var i = 0; i < saved.length; i++) {
            var item = saved[i];
            if (!item || !item.key) continue;
            out.push({ key: String(item.key), visible: item.visible !== false, width: item.width, abbrev: item.abbrev, label: item.label });
        }
        COLUMN_DEFS.forEach(function (def, i) {
            for (var j = 0; j < out.length; j++) if (out[j].key === def.key) return;
            var prev = i > 0 ? COLUMN_DEFS[i - 1].key : null;
            var at = -1;
            if (prev) for (var k = 0; k < out.length; k++) if (out[k].key === prev) { at = k; break; }
            var entry = { key: def.key, visible: !def.hidden };
            if (at >= 0) out.splice(at + 1, 0, entry); else out.push(entry);
        });
        return out.length ? out : defaultColumns();
    }

    function loadTimeFormat() {
        var fmt = readStore(STORE_TIME, 'relative');
        for (var i = 0; i < TIME_FORMATS.length; i++) if (TIME_FORMATS[i].key === fmt) return fmt;
        return 'relative';
    }

    function loadColorRules() {
        var saved = readStore(STORE_COLORS, null);
        if (!Array.isArray(saved) || !saved.length) return DEFAULT_COLOR_RULES.map(function (r) { return { id: r.id, name: r.name, filter: r.filter, fg: r.fg, bg: r.bg, enabled: r.enabled }; });
        return saved.map(function (r, i) {
            return {
                id: r.id == null ? i + 1 : r.id,
                name: r.name || ('Rule ' + (i + 1)),
                filter: r.filter || '',
                fg: r.fg || '#ffffff',
                bg: r.bg || '#333333',
                enabled: r.enabled !== false
            };
        });
    }

    function columnDef(key) {
        for (var i = 0; i < COLUMN_DEFS.length; i++) if (COLUMN_DEFS[i].key === key) return COLUMN_DEFS[i];
        return null;
    }

    function columnLabel(config) {
        if (config.key.indexOf('custom:') === 0) return config.label || config.abbrev || config.key.slice(7);
        var def = columnDef(config.key);
        return def ? def.label : config.key;
    }

    function columnClass(config) {
        if (config.key.indexOf('custom:') === 0) return 'pc-custom';
        var def = columnDef(config.key);
        return def ? def.cls : 'pc-custom';
    }

    function visibleColumns(viewer) {
        var out = [];
        for (var i = 0; i < viewer.columns.length; i++) {
            var c = viewer.columns[i];
            if (c.visible === false) continue;
            if (c.key.indexOf('custom:') !== 0 && !columnDef(c.key)) continue;
            out.push(c);
        }
        return out;
    }

    function columnWidth(config) {
        if (config.width) return config.width;
        if (config.key.indexOf('custom:') === 0) return 130;
        var def = columnDef(config.key);
        return def ? def.width : 120;
    }

    function pad2(n) { return (n < 10 ? '0' : '') + n; }

    function formatAbsolute(ms, utc) {
        var d = new Date(ms);
        var date = utc
            ? d.getUTCFullYear() + '-' + pad2(d.getUTCMonth() + 1) + '-' + pad2(d.getUTCDate())
            : d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
        var time = utc
            ? pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds())
            : pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
        return date + ' ' + time + '.' + String(d.getMilliseconds()).padStart(3, '0') + '000';
    }

    function formatTime(viewer, packet) {
        if (packet.time == null) return packet.rel.toFixed(6);
        if (viewer.timeFormat === 'delta') {
            var prev = packet.no > 1 ? viewer.packets[packet.no - 2] : null;
            if (prev && prev.time != null) return (packet.time - prev.time).toFixed(6);
            return '0.000000';
        }
        if (viewer.timeFormat === 'abs-local') return formatAbsolute(packet.time * 1000, false);
        if (viewer.timeFormat === 'abs-utc') return formatAbsolute(packet.time * 1000, true);
        return packet.rel.toFixed(6);
    }

    function packetColumnText(viewer, packet, config) {
        if (config.key.indexOf('custom:') === 0) {
            var value = resolveField(packet, config.abbrev || config.key.slice(7));
            if (value == null) return '';
            return Array.isArray(value) ? value.join(', ') : String(value);
        }
        var def = columnDef(config.key);
        return def ? String(def.text(packet, viewer)) : '';
    }

    function packetColumnSortValue(viewer, packet, config) {
        if (config.key.indexOf('custom:') === 0) {
            var value = resolveField(packet, config.abbrev || config.key.slice(7));
            if (value == null) return '';
            return (Array.isArray(value) ? value.join(', ') : String(value)).toLowerCase();
        }
        var def = columnDef(config.key);
        return def ? def.sortValue(packet, viewer) : '';
    }

    function computeRowColors(viewer) {
        var rules = [];
        for (var i = 0; i < viewer.colorRules.length; i++) {
            var rule = viewer.colorRules[i];
            if (!rule.enabled || !rule.filter.trim()) continue;
            var ast = null;
            try { ast = parseFilter(rule.filter); } catch (e) { continue; }
            if (ast) rules.push({ rule: rule, ast: ast });
        }
        var out = new Array(viewer.packets.length);
        for (var p = 0; p < viewer.packets.length; p++) {
            out[p] = null;
            for (var r = 0; r < rules.length; r++) {
                if (evalFilter(rules[r].ast, viewer.packets[p])) {
                    out[p] = { fg: rules[r].rule.fg, bg: rules[r].rule.bg, rule: rules[r].rule.name };
                    break;
                }
            }
        }
        viewer.rowColors = out;
        return out;
    }

    function copyText(text) {
        var value = String(text == null ? '' : text);
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(value).catch(function () { fallbackCopy(value); });
        } else {
            fallbackCopy(value);
        }
    }

    function fallbackCopy(text) {
        var area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try { document.execCommand('copy'); } catch (e) { }
        area.remove();
    }

    function plural(n, one, many) {
        return n + ' ' + (n === 1 ? one : (many || one + 's'));
    }

    function showToast(viewer, text) {
        if (!viewer.els.toast) return;
        viewer.els.toast.textContent = text;
        viewer.els.toast.classList.add('show');
        clearTimeout(viewer.toastTimer);
        viewer.toastTimer = setTimeout(function () {
            viewer.els.toast.classList.remove('show');
        }, 2200);
    }

    function closeViewer() {
        if (!activeViewer) return;
        closeDialog(activeViewer);
        closeMenus(activeViewer);
        closeContextMenu(activeViewer);
        document.removeEventListener('keydown', activeViewer.onKey, true);
        document.body.classList.remove('pcap-open');
        academyEmit('closed', {});
        activeViewer.overlay.remove();
        activeViewer = null;
        var terminalInput = document.getElementById('interact-input');
        if (terminalInput && !terminalInput.disabled) terminalInput.focus();
    }

    var ZOOM_LEVELS = [0.7, 0.8, 0.9, 1, 1.15, 1.3, 1.5, 1.75, 2];

    var FILTER_EXAMPLES = [
        'tcp',
        'tcp.port == 443',
        'ip.addr == 192.168.1.0/24',
        'ip.src == 10.0.0.5 and tcp.dstport == 80',
        'http.response.code >= 400',
        'dns.qry.name contains example',
        'tls.handshake.extensions_server_name == "example.com"',
        'tcp.flags.syn == 1 and tcp.flags.ack == 0',
        '!(arp or icmp)',
        'frame.len > 1000',
        '_ws.col.info contains "GET"'
    ];

    function buildHelpPanel() {
        var examples = '';
        for (var i = 0; i < FILTER_EXAMPLES.length; i++) {
            examples += '<button type="button" class="pcap-help-ex" data-expr="' +
                esc(FILTER_EXAMPLES[i]) + '">' + esc(FILTER_EXAMPLES[i]) + '</button>';
        }

        return '<div class="pcap-help" role="dialog" aria-label="Display filter help" hidden>' +
            '<div class="pcap-help-head">' +
                '<span>Display filter help</span>' +
                '<button type="button" class="pcap-help-close" aria-label="Close help">✕</button>' +
            '</div>' +
            '<div class="pcap-help-body">' +
                '<p class="pcap-help-intro">Wireshark-style syntax. Combine terms with ' +
                '<code>and</code>/<code>&amp;&amp;</code>, <code>or</code>/<code>||</code>, ' +
                '<code>not</code>/<code>!</code> and parentheses. Adjacent terms are ANDed.</p>' +
                '<h4>Comparison</h4>' +
                '<p><code>==</code> <code>!=</code> <code>&gt;</code> <code>&gt;=</code> <code>&lt;</code> ' +
                '<code>&lt;=</code> <code>contains</code> <code>matches</code> <code>~</code> &middot; ' +
                'aliases <code>eq</code> <code>ne</code> <code>gt</code> <code>ge</code> <code>lt</code> <code>le</code> &middot; ' +
                'quoted values <code>"text"</code> &middot; hex <code>0x0800</code> &middot; IPv4 CIDR <code>192.168.0.0/16</code></p>' +
                '<h4>Protocols</h4>' +
                '<p><code>eth</code> <code>vlan</code> <code>ip</code> <code>ipv6</code> <code>arp</code> ' +
                '<code>tcp</code> <code>udp</code> <code>icmp</code> <code>icmpv6</code> <code>http</code> ' +
                '<code>dns</code> <code>tls</code>/<code>ssl</code> <code>ssh</code> <code>ntp</code> <code>data</code></p>' +
                '<h4>Common fields</h4>' +
                '<p><code>ip.src</code> <code>ip.dst</code> <code>ip.addr</code> <code>ip.ttl</code> ' +
                '<code>ip.proto</code> <code>ipv6.src</code> <code>ipv6.dst</code> <code>eth.src</code> ' +
                '<code>eth.dst</code> <code>vlan.id</code> <code>tcp.srcport</code> <code>tcp.dstport</code> ' +
                '<code>tcp.port</code> <code>tcp.len</code> <code>tcp.window</code> <code>tcp.flags.syn</code> ' +
                '<code>tcp.flags.ack</code> <code>tcp.flags.rst</code> <code>udp.srcport</code> ' +
                '<code>udp.dstport</code> <code>udp.port</code> <code>udp.length</code> <code>icmp.type</code> ' +
                '<code>arp.opcode</code> <code>frame.number</code> <code>frame.len</code> ' +
                '<code>frame.protocols</code> <code>data.len</code> <code>_ws.col.info</code> ' +
                '<code>_ws.col.protocol</code></p>' +
                '<h4>Application fields</h4>' +
                '<p><code>http.request</code> <code>http.request.method</code> <code>http.request.uri</code> <code>http.host</code> ' +
                '<code>http.user_agent</code> <code>http.response</code> <code>http.response.code</code> <code>http.content_type</code> ' +
                '<code>dns.qry.name</code> <code>dns.qry.type</code> <code>dns.flags.response</code> ' +
                '<code>dns.count.answers</code> <code>tls.handshake.type</code> ' +
                '<code>tls.handshake.extensions_server_name</code></p>' +
                '<h4>Examples</h4>' +
                '<div class="pcap-help-examples">' + examples + '</div>' +
                '<p class="pcap-help-tip">Click an example to apply it. <kbd>Esc</kbd> closes this help.</p>' +
            '</div>' +
        '</div>';
    }

    function setZoom(viewer, value) {
        value = Math.min(2, Math.max(0.7, Math.round(value * 100) / 100));
        viewer.zoom = value;
        viewer.els.window.style.setProperty('--pcap-fs', String(value));
        var pct = Math.round(value * 100) + '%';
        viewer.els.zoomLevel.textContent = pct;
        viewer.els.zoomLevel.setAttribute('aria-label', 'Zoom ' + pct + '. Click to reset.');
        try { localStorage.setItem('bw-pcap-zoom', String(value)); } catch (e) { }
    }

    function toggleHelp(viewer, show) {
        viewer.helpOpen = !!show;
        if (viewer.helpOpen) viewer.els.help.removeAttribute('hidden');
        else viewer.els.help.setAttribute('hidden', '');
        viewer.els.helpBtn.setAttribute('aria-expanded', viewer.helpOpen ? 'true' : 'false');
        viewer.els.helpBtn.classList.toggle('active', viewer.helpOpen);
        if (viewer.helpOpen) viewer.els.help.scrollTop = 0;
    }

    function menuMarkup(key, label) {
        return '<div class="pcap-menu" data-menu="' + key + '">' +
            '<button class="pcap-menu-btn" type="button" aria-haspopup="true" aria-expanded="false">' +
            esc(label) + ' <span class="pcap-menu-caret">▾</span></button>' +
            '<div class="pcap-menu-drop" hidden></div>' +
        '</div>';
    }

    function menuItems(viewer, key) {
        var selected = viewer.selected;
        var hasSelection = selected >= 0;
        var packet = hasSelection ? viewer.packets[selected] : null;
        var isTcp = packet && packet.transport === 'tcp';
        var isUdp = packet && packet.transport === 'udp';
        var marked = hasSelection && viewer.marked.has(selected);

        if (key === 'file') {
            var fileItems = [];
            if (typeof window.pcapOpenFileRequest === 'function') {
                fileItems.push({ label: 'Open Capture…', shortcut: 'Ctrl+O', action: function () { window.pcapOpenFileRequest(); } });
                fileItems.push({ separator: true });
            }
            fileItems.push({ label: 'Capture File Properties', action: function () { showCaptureProperties(viewer); } });
            fileItems.push({ label: 'Reload Capture', shortcut: 'Ctrl+R', action: function () { loadCapture(viewer, viewer.source); } });
            fileItems.push({ separator: true });
            fileItems.push({ label: 'Close', shortcut: 'Ctrl+W', action: closeViewer });
            return fileItems;
        }
        if (key === 'edit') {
            return [
                { label: 'Find Packet…', shortcut: 'Ctrl+F', action: function () { openFindDialog(viewer); } },
                { label: 'Find Next', shortcut: 'Ctrl+N', disabled: !viewer.find.text, action: function () { findAgain(viewer, 1); } },
                { label: 'Find Previous', shortcut: 'Ctrl+Shift+N', disabled: !viewer.find.text, action: function () { findAgain(viewer, -1); } },
                { separator: true },
                {
                    label: (marked ? 'Unmark' : 'Mark') + ' Packet', shortcut: 'Ctrl+M', disabled: !hasSelection,
                    action: function () { toggleMark(viewer, viewer.selected); }
                },
                { label: 'Mark All Displayed', disabled: !viewer.rows.length, action: function () { markAllDisplayed(viewer); } },
                { label: 'Unmark All', disabled: !viewer.marked.size, action: function () { unmarkAll(viewer); } },
                { separator: true },
                { label: 'Packet Comment…', shortcut: 'Ctrl+Alt+C', disabled: !hasSelection, action: function () { openCommentDialog(viewer, viewer.selected); } },
                { separator: true },
                { label: 'Clear Display Filter', disabled: !viewer.els.filter.value.trim(), action: function () { clearFilter(viewer); } }
            ];
        }
        if (key === 'view') {
            var items = [{ header: 'Time Display Format' }];
            TIME_FORMATS.forEach(function (fmt) {
                items.push({
                    label: fmt.label,
                    checked: viewer.timeFormat === fmt.key,
                    action: function () { setTimeFormat(viewer, fmt.key); }
                });
            });
            items.push({ separator: true });
            items.push({ label: 'Coloring Rules…', action: function () { openColoringRules(viewer); } });
            items.push({ label: 'Columns…', action: function () { openColumnsDialog(viewer); } });
            items.push({ separator: true });
            items.push({ label: 'Expand All', action: function () { expandAll(viewer, true); } });
            items.push({ label: 'Collapse All', action: function () { expandAll(viewer, false); } });
            items.push({ separator: true });
            items.push({ label: 'Zoom In', shortcut: 'Ctrl+=', action: function () { stepZoom(viewer, 1); } });
            items.push({ label: 'Zoom Out', shortcut: 'Ctrl+-', action: function () { stepZoom(viewer, -1); } });
            items.push({ label: 'Reset Zoom', shortcut: 'Ctrl+0', action: function () { setZoom(viewer, 1); } });
            return items;
        }
        if (key === 'go') {
            return [
                { label: 'Go to Packet…', shortcut: 'Ctrl+G', action: function () { openGotoDialog(viewer); } },
                { separator: true },
                { label: 'First Packet', shortcut: 'Home', action: function () { goRelative(viewer, 'first'); } },
                { label: 'Last Packet', shortcut: 'End', action: function () { goRelative(viewer, 'last'); } },
                { label: 'Next Packet', shortcut: 'Down', action: function () { goRelative(viewer, 1); } },
                { label: 'Previous Packet', shortcut: 'Up', action: function () { goRelative(viewer, -1); } },
                { separator: true },
                { label: 'Next Packet in Conversation', disabled: !hasSelection, action: function () { goConversation(viewer, 1); } },
                { label: 'Previous Packet in Conversation', disabled: !hasSelection, action: function () { goConversation(viewer, -1); } }
            ];
        }
        if (key === 'analyze') {
            return [
                { label: 'Apply as Filter: Source', disabled: !hasSelection, action: function () { applyPacketFilter(viewer, 'src'); } },
                { label: 'Apply as Filter: Destination', disabled: !hasSelection, action: function () { applyPacketFilter(viewer, 'dst'); } },
                { label: 'Apply as Filter: Protocol', disabled: !hasSelection, action: function () { applyPacketFilter(viewer, 'proto'); } },
                { separator: true },
                { label: 'Follow TCP Stream', disabled: !isTcp, action: function () { openFollowStream(viewer, viewer.selected); } },
                { label: 'Follow UDP Stream', disabled: !isUdp, action: function () { openFollowStream(viewer, viewer.selected); } },
                { label: 'Follow Stream', disabled: !(isTcp || isUdp), action: function () { openFollowStream(viewer, viewer.selected); } },
                { separator: true },
                { label: 'Expert Information', action: function () { showExpertInfo(viewer); } }
            ];
        }
        if (key === 'statistics') {
            return [
                { label: 'Capture File Properties', action: function () { showCaptureProperties(viewer); } },
                { separator: true },
                { label: 'Protocol Hierarchy', action: function () { showProtocolHierarchy(viewer); } },
                { label: 'Conversations', action: function () { showConversations(viewer); } },
                { label: 'Endpoints', action: function () { showEndpoints(viewer); } },
                { label: 'IO Graph', action: function () { showIOGraph(viewer); } },
                { separator: true },
                { label: 'Expert Information', action: function () { showExpertInfo(viewer); } },
                { label: 'HTTP Objects', action: function () { showHTTPObjects(viewer); } }
            ];
        }
        if (key === 'help') {
            return [
                { label: 'Display Filter Help', shortcut: 'F1', action: function () { toggleHelp(viewer, true); } },
                { label: 'Keyboard Shortcuts', action: function () { showShortcuts(viewer); } },
                { separator: true },
                { label: 'About This Packet Viewer', action: function () { showAbout(viewer); } }
            ];
        }
        return [];
    }

    function openMenu(viewer, menuEl) {
        var already = menuEl.classList.contains('open');
        closeMenus(viewer);
        if (already) return;
        var key = menuEl.getAttribute('data-menu');
        var items = menuItems(viewer, key);
        var drop = menuEl.querySelector('.pcap-menu-drop');
        var html = '';
        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            if (item.separator) { html += '<div class="pcap-menu-sep"></div>'; continue; }
            if (item.header) { html += '<div class="pcap-menu-head">' + esc(item.header) + '</div>'; continue; }
            html += '<button type="button" class="pcap-menu-item' + (item.checked ? ' checked' : '') + '" data-idx="' + i + '"' +
                (item.disabled ? ' disabled' : '') + '>' +
                '<span class="pcap-menu-check">' + (item.checked ? '✓' : '') + '</span>' +
                '<span class="pcap-menu-label">' + esc(item.label) + '</span>' +
                (item.shortcut ? '<span class="pcap-menu-shortcut">' + esc(item.shortcut) + '</span>' : '') +
            '</button>';
        }
        drop.innerHTML = html || '<div class="pcap-menu-head">No actions</div>';
        drop._items = items;
        drop.hidden = false;
        drop.style.transform = '';
        menuEl.classList.add('open');
        menuEl.querySelector('.pcap-menu-btn').setAttribute('aria-expanded', 'true');
        viewer.openMenuEl = menuEl;

        var wr = viewer.els.window.getBoundingClientRect();
        var dr = drop.getBoundingClientRect();
        var dx = 0;
        var dy = 0;
        if (dr.right > wr.right - 6) dx = wr.right - 6 - dr.right;
        if (dr.left + dx < wr.left + 6) dx = wr.left + 6 - dr.left;
        if (dr.bottom > wr.bottom - 6) dy = wr.bottom - 6 - dr.bottom;
        if (dr.top + dy < wr.top + 6) dy = wr.top + 6 - dr.top;
        if (dx || dy) drop.style.transform = 'translate(' + Math.round(dx) + 'px,' + Math.round(dy) + 'px)';

        viewer.onMenuOutside = function (e) {
            if (!menuEl.contains(e.target)) closeMenus(viewer);
        };
        setTimeout(function () {
            document.addEventListener('mousedown', viewer.onMenuOutside, true);
        }, 0);
    }

    function closeMenus(viewer) {
        if (!viewer) return;
        var menus = viewer.els.menubar ? viewer.els.menubar.querySelectorAll('.pcap-menu') : [];
        for (var i = 0; i < menus.length; i++) {
            menus[i].classList.remove('open');
            var drop = menus[i].querySelector('.pcap-menu-drop');
            if (drop) drop.hidden = true;
            var btn = menus[i].querySelector('.pcap-menu-btn');
            if (btn) btn.setAttribute('aria-expanded', 'false');
        }
        viewer.openMenuEl = null;
        if (viewer.onMenuOutside) {
            document.removeEventListener('mousedown', viewer.onMenuOutside, true);
            viewer.onMenuOutside = null;
        }
    }

    function showModal(viewer, title, bodyHtml, opts) {
        closeDialog(viewer);
        closeMenus(viewer);
        opts = opts || {};
        var back = document.createElement('div');
        back.className = 'pcap-modal-backdrop';
        back.innerHTML =
            '<div class="pcap-modal' + (opts.wide ? ' wide' : '') + '" role="dialog" aria-modal="true" aria-label="' + esc(title) + '">' +
                '<div class="pcap-modal-head">' +
                    '<h2>' + esc(title) + '</h2>' +
                    '<button type="button" class="pcap-modal-close" aria-label="Close dialog">✕</button>' +
                '</div>' +
                '<div class="pcap-modal-body">' + bodyHtml + '</div>' +
            '</div>';
        viewer.els.window.appendChild(back);
        viewer.dialog = back;
        back.querySelector('.pcap-modal-close').addEventListener('click', function () { closeDialog(viewer); });
        back.addEventListener('mousedown', function (e) {
            if (e.target === back && opts.dismissable !== false) closeDialog(viewer);
        });
        back.addEventListener('click', function (e) {
            var row = e.target.closest('[data-packet]');
            if (!row) return;
            var idx = parseInt(row.getAttribute('data-packet'), 10);
            if (!isFinite(idx) || idx < 0 || idx >= viewer.packets.length) return;
            selectPacket(viewer, idx);
            showToast(viewer, 'Selected packet ' + viewer.packets[idx].no);
        });
        academyEmit('dialog', { title: title });
        return back;
    }

    function closeDialog(viewer) {
        if (!viewer || !viewer.dialog) return;
        viewer.dialog.remove();
        viewer.dialog = null;
    }

    function modalBody(viewer) {
        return viewer.dialog ? viewer.dialog.querySelector('.pcap-modal-body') : null;
    }

    function showMessageDialog(viewer, title, message) {
        showModal(viewer, title, '<p class="pcap-dim">' + esc(message) + '</p>' +
            '<div class="pcap-dialog-actions"><button type="button" class="pcap-btn primary" data-close>OK</button></div>');
        var body = modalBody(viewer);
        body.querySelector('[data-close]').addEventListener('click', function () { closeDialog(viewer); });
    }

    function tableHtml(headers, rows, bodyAttrs) {
        var html = '<div class="pcap-table-wrap"><table class="pcap-data-table"' + (bodyAttrs || '') + '><thead><tr>';
        for (var i = 0; i < headers.length; i++) {
            var h = headers[i];
            if (typeof h === 'string') html += '<th>' + esc(h) + '</th>';
            else html += '<th class="' + (h.cls || '') + '">' + esc(h.label) + '</th>';
        }
        html += '</tr></thead><tbody>';
        for (var r = 0; r < rows.length; r++) html += rows[r];
        html += '</tbody></table></div>';
        return html;
    }

    function buildViewer(source, name) {
        var overlay = document.createElement('div');
        overlay.className = 'pcap-overlay';

        overlay.innerHTML =
            '<div class="pcap-window" role="dialog" aria-modal="true" aria-label="Packet capture viewer">' +
                '<div class="pcap-head">' +
                    '<div class="pcap-title">' +
                        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
                            '<path d="M3 12h4l3 8 4-16 3 8h4"/>' +
                        '</svg>' +
                        '<span class="pcap-fname"></span>' +
                    '</div>' +
                    '<span class="pcap-stats">—</span>' +
                    '<input class="pcap-filter" type="text" spellcheck="false" ' +
                        'placeholder="Apply a display filter … &lt;Ctrl-/&gt;" aria-label="Display filter">' +
                    '<button class="pcap-help-btn" type="button" aria-label="Display filter help" aria-expanded="false" title="Display filter help">?</button>' +
                    '<div class="pcap-zoom" role="group" aria-label="Zoom">' +
                        '<button class="pcap-zoom-btn" type="button" data-zoom="-1" aria-label="Zoom out" title="Zoom out">−</button>' +
                        '<button class="pcap-zoom-reset" type="button" title="Reset zoom to 100%">100%</button>' +
                        '<button class="pcap-zoom-btn" type="button" data-zoom="1" aria-label="Zoom in" title="Zoom in">+</button>' +
                    '</div>' +
                    '<button class="pcap-close" type="button" aria-label="Close viewer">✕</button>' +
                '</div>' +
                '<div class="pcap-menubar">' +
                    '<div class="pcap-menus">' +
                        menuMarkup('file', 'File') +
                        menuMarkup('edit', 'Edit') +
                        menuMarkup('view', 'View') +
                        menuMarkup('go', 'Go') +
                        menuMarkup('analyze', 'Analyze') +
                        menuMarkup('statistics', 'Statistics') +
                        menuMarkup('help', 'Help') +
                    '</div>' +
                    '<div class="pcap-actions">' +
                        '<button type="button" class="pcap-act" data-act="find" title="Find a packet (Ctrl+F)">Find</button>' +
                        '<button type="button" class="pcap-act" data-act="go" title="Go to packet (Ctrl+G)">Go to</button>' +
                        '<button type="button" class="pcap-act" data-act="mark" title="Mark/unmark packet (Ctrl+M)">Mark</button>' +
                        '<button type="button" class="pcap-act" data-act="follow" title="Follow TCP/UDP stream">Follow</button>' +
                    '</div>' +
                '</div>' +
                buildHelpPanel() +
                '<div class="pcap-body">' +
                    '<div class="pcap-list">' +
                        '<table>' +
                            '<colgroup></colgroup>' +
                            '<thead><tr></tr></thead>' +
                            '<tbody></tbody>' +
                        '</table>' +
                    '</div>' +
                    '<div class="pcap-detail">' +
                        '<div class="pcap-tree"><div class="pcap-hint">Select a packet to inspect its layers.</div></div>' +
                        '<div class="pcap-hex"></div>' +
                    '</div>' +
                '</div>' +
                '<div class="pcap-foot">' +
                    '<span class="pcap-status">Loading…</span>' +
                    '<span class="pcap-toast" role="status"></span>' +
                    '<input class="pcap-pcomment" type="text" spellcheck="false" placeholder="Packet comment…" aria-label="Packet comment" disabled>' +
                '</div>' +
            '</div>';

        var fallbackName = (typeof source === 'string' ? source.split('/').pop() : '') ||
            (source && source.name) || 'capture';
        var displayName = name || fallbackName || 'capture';
        overlay.querySelector('.pcap-fname').textContent = displayName;

        var viewer = {
            overlay: overlay,
            source: source,
            url: typeof source === 'string' ? source : null,
            blob: (typeof Blob !== 'undefined' && source instanceof Blob) ? source : null,
            name: displayName,
            packets: [],
            view: [],
            rows: [],
            rowColors: [],
            columns: loadColumns(),
            timeFormat: loadTimeFormat(),
            colorRules: loadColorRules(),
            sort: null,
            selected: -1,
            selectedField: null,
            marked: new Set(),
            comments: {},
            filterAst: null,
            filterError: null,
            helpOpen: false,
            dialog: null,
            contextMenu: null,
            openMenuEl: null,
            dragCol: null,
            suppressSort: false,
            find: { type: 'string', scope: 'info', caseSensitive: false, text: '' },
            findStatus: '',
            zoom: 1,
            onKey: null,
            els: {
                window: overlay.querySelector('.pcap-window'),
                fname: overlay.querySelector('.pcap-fname'),
                menubar: overlay.querySelector('.pcap-menubar'),
                stats: overlay.querySelector('.pcap-stats'),
                filter: overlay.querySelector('.pcap-filter'),
                tbody: overlay.querySelector('.pcap-list tbody'),
                colgroup: overlay.querySelector('.pcap-list colgroup'),
                thead: overlay.querySelector('.pcap-list thead'),
                list: overlay.querySelector('.pcap-list'),
                tree: overlay.querySelector('.pcap-tree'),
                hex: overlay.querySelector('.pcap-hex'),
                status: overlay.querySelector('.pcap-status'),
                toast: overlay.querySelector('.pcap-toast'),
                comment: overlay.querySelector('.pcap-pcomment'),
                help: overlay.querySelector('.pcap-help'),
                helpBtn: overlay.querySelector('.pcap-help-btn'),
                zoomLevel: overlay.querySelector('.pcap-zoom-reset'),
                markBtn: overlay.querySelector('[data-act="mark"]')
            }
        };

        overlay.querySelector('.pcap-close').addEventListener('click', closeViewer);

        viewer.els.helpBtn.addEventListener('click', function () {
            toggleHelp(viewer, !viewer.helpOpen);
        });

        overlay.querySelector('.pcap-help-close').addEventListener('click', function () {
            toggleHelp(viewer, false);
            viewer.els.filter.focus();
        });

        viewer.els.help.addEventListener('click', function (e) {
            var ex = e.target.closest('.pcap-help-ex');
            if (!ex) return;
            viewer.els.filter.value = ex.getAttribute('data-expr') || '';
            toggleHelp(viewer, false);
            applyFilter(viewer);
            viewer.els.filter.focus();
        });

        var zoomButtons = overlay.querySelectorAll('[data-zoom]');
        for (var zb = 0; zb < zoomButtons.length; zb++) {
            zoomButtons[zb].addEventListener('click', function () {
                stepZoom(viewer, parseInt(this.getAttribute('data-zoom'), 10));
            });
        }
        viewer.els.zoomLevel.addEventListener('click', function () {
            setZoom(viewer, 1);
        });

        var filterTimer = null;
        viewer.els.filter.addEventListener('input', function () {
            clearTimeout(filterTimer);
            filterTimer = setTimeout(function () { applyFilter(viewer); }, 120);
        });
        viewer.els.filter.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                clearTimeout(filterTimer);
                applyFilter(viewer);
            } else if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                if (viewer.els.filter.value) {
                    clearFilter(viewer);
                } else {
                    viewer.els.filter.blur();
                }
            }
        });

        viewer.els.menubar.addEventListener('click', function (e) {
            var menuBtn = e.target.closest('.pcap-menu-btn');
            if (menuBtn) {
                e.preventDefault();
                e.stopPropagation();
                openMenu(viewer, menuBtn.closest('.pcap-menu'));
                return;
            }
            var item = e.target.closest('.pcap-menu-item');
            if (item) {
                e.preventDefault();
                var menuEl = item.closest('.pcap-menu');
                var drop = menuEl.querySelector('.pcap-menu-drop');
                var idx = parseInt(item.getAttribute('data-idx'), 10);
                var entry = drop && drop._items ? drop._items[idx] : null;
                closeMenus(viewer);
                if (entry && !entry.disabled && entry.action) {
                    academyEmit('action', { label: entry.label, source: 'menu', menu: menuEl.getAttribute('data-menu') });
                    entry.action();
                }
                return;
            }
            var act = e.target.closest('.pcap-act');
            if (!act) return;
            var action = act.getAttribute('data-act');
            academyEmit('action', { label: act.textContent.trim(), source: 'toolbar', action: action });
            if (action === 'find') openFindDialog(viewer);
            else if (action === 'go') openGotoDialog(viewer);
            else if (action === 'mark') {
                if (viewer.selected >= 0) toggleMark(viewer, viewer.selected);
            } else if (action === 'follow') {
                openFollowStream(viewer, viewer.selected);
            }
        });

        viewer.els.thead.addEventListener('click', function (e) {
            if (viewer.suppressSort) return;
            if (e.target.closest('.pcap-resize')) return;
            var th = e.target.closest('th[data-col]');
            if (!th) return;
            sortByColumn(viewer, th.getAttribute('data-col'));
        });

        viewer.els.thead.addEventListener('mousedown', function (e) {
            var handle = e.target.closest('.pcap-resize');
            if (!handle) return;
            e.preventDefault();
            e.stopPropagation();
            startColumnResize(viewer, handle.getAttribute('data-col'), e.clientX, handle.closest('th'));
        });

        viewer.els.thead.addEventListener('dragstart', function (e) {
            var th = e.target.closest('th[data-col]');
            if (!th || e.target.closest('.pcap-resize')) return;
            viewer.dragCol = th.getAttribute('data-col');
            try { e.dataTransfer.effectAllowed = 'move'; } catch (err) { }
        });

        viewer.els.thead.addEventListener('dragover', function (e) {
            var th = e.target.closest('th[data-col]');
            if (!th || !viewer.dragCol || viewer.dragCol === th.getAttribute('data-col')) return;
            e.preventDefault();
            th.classList.add('dragover');
        });

        viewer.els.thead.addEventListener('dragleave', function (e) {
            var th = e.target.closest('th[data-col]');
            if (th) th.classList.remove('dragover');
        });

        viewer.els.thead.addEventListener('drop', function (e) {
            var th = e.target.closest('th[data-col]');
            if (!th || !viewer.dragCol) return;
            e.preventDefault();
            th.classList.remove('dragover');
            moveColumn(viewer, viewer.dragCol, th.getAttribute('data-col'));
            viewer.dragCol = null;
        });

        viewer.els.thead.addEventListener('dragend', function () {
            viewer.dragCol = null;
            var over = viewer.els.thead.querySelectorAll('.dragover');
            for (var i = 0; i < over.length; i++) over[i].classList.remove('dragover');
        });

        viewer.els.tbody.addEventListener('click', function (e) {
            var tr = e.target.closest('tr[data-i]');
            if (!tr) return;
            var idx = parseInt(tr.dataset.i, 10);
            if (e.target.closest('.pc-mark')) {
                selectPacket(viewer, idx);
                toggleMark(viewer, idx);
                return;
            }
            selectPacket(viewer, idx);
        });

        viewer.els.tbody.addEventListener('contextmenu', function (e) {
            var tr = e.target.closest('tr[data-i]');
            if (!tr) return;
            e.preventDefault();
            var idx = parseInt(tr.dataset.i, 10);
            selectPacket(viewer, idx);
            openPacketContextMenu(viewer, e.clientX, e.clientY, idx);
        });

        viewer.els.tree.addEventListener('click', function (e) {
            var field = e.target.closest('.pcap-field');
            if (field) {
                var selected = viewer.els.tree.querySelector('.pcap-field.selected');
                if (selected) selected.classList.remove('selected');
                field.classList.add('selected');
                viewer.selectedField = field;
                academyEmit('field', {
                    label: field.getAttribute('data-label') || '',
                    value: field.getAttribute('data-value') || '',
                    abbrev: field.getAttribute('data-abbrev') || ''
                });
                return;
            }
            var head = e.target.closest('.pcap-layer-head');
            if (!head) return;
            head.parentElement.classList.toggle('collapsed');
        });

        viewer.els.tree.addEventListener('contextmenu', function (e) {
            var field = e.target.closest('.pcap-field');
            var head = e.target.closest('.pcap-layer-head');
            if (!field && !head) return;
            e.preventDefault();
            openTreeContextMenu(viewer, e.clientX, e.clientY, field, head);
        });

        viewer.els.hex.addEventListener('contextmenu', function (e) {
            if (viewer.selected < 0) return;
            e.preventDefault();
            openContextMenu(viewer, e.clientX, e.clientY, [
                { label: 'Copy Bytes as Hex Dump', action: function () { copyText(hexDump(viewer.packets[viewer.selected].bytes)); showToast(viewer, 'Bytes copied'); } },
                { label: 'Copy Packet Summary', action: function () { copyText(packetSummary(viewer, viewer.packets[viewer.selected])); showToast(viewer, 'Summary copied'); } }
            ]);
        });

        viewer.els.comment.addEventListener('input', function () {
            if (viewer.selected < 0) return;
            var text = viewer.els.comment.value;
            if (text.trim()) viewer.comments[viewer.selected] = text;
            else delete viewer.comments[viewer.selected];
            updateRowCommentFlag(viewer, viewer.selected);
        });

        viewer.els.comment.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') viewer.els.comment.blur();
        });

        renderTableHead(viewer);
        updateActionButtons(viewer);
        return viewer;
    }

    function setStatus(viewer, text) {
        viewer.els.status.textContent = text;
    }

    function showListMessage(viewer, text, isError) {
        var cols = visibleColumns(viewer).length + 1;
        viewer.els.tbody.innerHTML = '<tr><td colspan="' + Math.max(1, cols) + '" class="pcap-empty' +
            (isError ? ' pcap-empty-error' : '') + '">' + esc(text) + '</td></tr>';
    }

    function decodeAll(cap) {
        var packets = [];
        for (var i = 0; i < cap.packets.length; i++) {
            var raw = cap.packets[i];
            var dec = decodeFrame(raw.bytes, raw.linkType);

            var protocols = {};
            for (var c = 0; c < dec.chain.length; c++) protocols[dec.chain[c]] = true;
            if (dec.transport) protocols[dec.transport] = true;
            protocols[String(dec.proto || '').toLowerCase()] = true;
            if (protocols.tls) protocols.ssl = true;
            protocols.frame = true;

            var fields = {};
            for (var fk in dec.fields) {
                if (Object.prototype.hasOwnProperty.call(dec.fields, fk)) fields[fk] = dec.fields[fk];
            }
            fields['frame.number'] = i + 1;
            fields['frame.len'] = raw.len;
            fields['frame.cap_len'] = raw.cap;
            fields['frame.protocols'] = dec.chain.join(':');
            fields['_ws.col.protocol'] = dec.proto;
            fields['_ws.col.info'] = dec.info;

            var hay = [
                dec.proto, dec.src, dec.dst, dec.info, dec.cls, dec.transport,
                dec.chain.join(' '), dec.ports.join(' ')
            ].join(' ').toLowerCase();

            packets.push({
                no: i + 1,
                time: raw.time,
                len: raw.len,
                cap: raw.cap,
                bytes: raw.bytes,
                linkType: raw.linkType,
                dec: dec,
                rel: 0,
                hay: hay,
                fields: fields,
                protocols: protocols,
                srcport: dec.ports.length > 0 ? dec.ports[0] : '',
                dstport: dec.ports.length > 1 ? dec.ports[1] : '',
                transport: dec.transport,
                payload: dec.payload
            });
        }
        var base = null;
        for (var j = 0; j < packets.length; j++) {
            if (packets[j].time != null) { base = packets[j].time; break; }
        }
        for (var k = 0; k < packets.length; k++) {
            var p = packets[k];
            p.rel = (base != null && p.time != null) ? Math.max(0, p.time - base) : k / 1000;
            p.fields['frame.time_relative'] = p.rel;
        }
        return packets;
    }

    var PROTOCOL_NAMES = {
        eth: 1, sll: 1, sll2: 1, vlan: 1, ip: 1, ipv6: 1, arp: 1, rarp: 1,
        tcp: 1, udp: 1, icmp: 1, icmpv6: 1, http: 1, dns: 1, tls: 1, ssl: 1,
        ssh: 1, ntp: 1, llc: 1, data: 1, frame: 1
    };

    var FIELD_ALIASES = {
        'src': ['ip.src', 'ipv6.src', 'arp.src.proto_ipv4'],
        'dst': ['ip.dst', 'ipv6.dst', 'arp.dst.proto_ipv4'],
        'port': ['tcp.port', 'udp.port'],
        'addr': ['ip.addr', 'ipv6.addr']
    };

    var WORD_OPERATORS = {
        'eq': '==', 'ne': '!=', 'gt': '>', 'ge': '>=', 'lt': '<', 'le': '<='
    };

    var FILTER_OPERATORS = ['==', '!=', '>=', '<=', '>', '<', 'contains', 'matches', '~'];

    function tokenizeFilter(text) {
        var tokens = [];
        var i = 0;
        while (i < text.length) {
            var ch = text.charAt(i);
            if (/\s/.test(ch)) { i++; continue; }
            if (ch === '(' || ch === ')') { tokens.push(ch); i++; continue; }
            if (ch === '"' || ch === "'") {
                var quote = ch;
                var j = i + 1;
                var str = '';
                while (j < text.length && text.charAt(j) !== quote) {
                    if (text.charAt(j) === '\\' && j + 1 < text.length) {
                        str += text.charAt(j + 1);
                        j += 2;
                    } else {
                        str += text.charAt(j);
                        j++;
                    }
                }
                if (j >= text.length) throw new Error('Unterminated string');
                tokens.push({ type: 'string', value: str });
                i = j + 1;
                continue;
            }
            if (text.substr(i, 2) === '&&' || text.substr(i, 2) === '||') {
                tokens.push(text.substr(i, 2));
                i += 2;
                continue;
            }
            if (ch === '&' || ch === '|') {
                throw new Error('Unexpected "' + ch + '"');
            }
            var word = /^[^\s()&|]+/.exec(text.slice(i))[0];
            i += word.length;
            var lower = word.toLowerCase();
            if (FILTER_OPERATORS.indexOf(word) !== -1) {
                tokens.push(word);
            } else if (lower === 'and' || lower === 'or' || lower === 'not') {
                tokens.push(lower);
            } else if (Object.prototype.hasOwnProperty.call(WORD_OPERATORS, lower)) {
                tokens.push(WORD_OPERATORS[lower]);
            } else if (word === '!') {
                tokens.push('not');
            } else if (word.charAt(0) === '!' && word.length > 1) {
                tokens.push('not');
                tokens.push(word.slice(1));
            } else if (word.charAt(0) === '-' && word.length > 1 && !/^-\d/.test(word)) {
                tokens.push('not');
                tokens.push(word.slice(1));
            } else {
                tokens.push(word);
            }
        }
        return tokens;
    }

    function splitAttachedOperator(word) {
        for (var i = 1; i < word.length - 1; i++) {
            for (var o = 0; o < FILTER_OPERATORS.length; o++) {
                var op = FILTER_OPERATORS[o];
                if (word.substr(i, op.length) !== op) continue;
                if (i + op.length >= word.length) continue;
                return {
                    field: word.slice(0, i),
                    op: op,
                    value: word.slice(i + op.length)
                };
            }
        }
        return null;
    }

    function parseFilter(text) {
        var tokens = tokenizeFilter(text);
        var pos = 0;

        function peek() { return tokens[pos]; }
        function next() { return tokens[pos++]; }

        function parseExpression() {
            var node = parseAnd();
            while (peek() === 'or' || peek() === '||') {
                next();
                node = { type: 'or', left: node, right: parseAnd() };
            }
            return node;
        }

        function parseAnd() {
            var node = parseUnary();
            while (true) {
                var token = peek();
                if (token === 'and' || token === '&&') {
                    next();
                    node = { type: 'and', left: node, right: parseUnary() };
                    continue;
                }
                if (token === undefined || token === ')' || token === 'or' || token === '||') break;
                node = { type: 'and', left: node, right: parseUnary() };
            }
            return node;
        }

        function parseUnary() {
            var token = peek();
            if (token === 'not' || token === '!') {
                next();
                return { type: 'not', expr: parseUnary() };
            }
            if (token === '(') {
                next();
                var expr = parseExpression();
                if (peek() !== ')') throw new Error('Missing closing parenthesis');
                next();
                return expr;
            }
            return parseComparison();
        }

        function parseComparison() {
            var token = next();
            if (token === undefined) throw new Error('Unexpected end of filter');
            if (token === ')' || token === 'or' || token === '||' || token === 'and' || token === '&&') {
                throw new Error('Unexpected "' + token + '"');
            }
            var word = String(token && token.value !== undefined ? token.value : token);

            var attached = splitAttachedOperator(word);
            if (attached) return { type: 'cmp', field: attached.field, op: attached.op, value: attached.value };

            var op = peek();
            if (typeof op === 'string' && FILTER_OPERATORS.indexOf(op) !== -1) {
                next();
                var valueToken = next();
                if (valueToken === undefined) throw new Error('Missing value after "' + op + '"');
                var value = (valueToken && typeof valueToken === 'object')
                    ? valueToken.value
                    : String(valueToken);
                return { type: 'cmp', field: word, op: op, value: value };
            }
            return { type: 'term', value: word };
        }

        var ast = parseExpression();
        if (pos < tokens.length) throw new Error('Unexpected "' + tokens[pos] + '"');
        return ast;
    }

    function asNumber(value) {
        if (typeof value === 'number') return isFinite(value) ? value : null;
        var text = String(value).trim();
        if (/^0x[0-9a-f]+$/i.test(text)) {
            var hexValue = parseInt(text, 16);
            return isFinite(hexValue) ? hexValue : null;
        }
        if (!text || !/^-?(?:\d+|\d*\.\d+)$/.test(text)) return null;
        var n = Number(text);
        return isFinite(n) ? n : null;
    }

    function ipv4ToInt(value) {
        var parts = String(value).trim().split('.');
        if (parts.length !== 4) return null;
        var n = 0;
        for (var i = 0; i < 4; i++) {
            if (!/^\d{1,3}$/.test(parts[i])) return null;
            var part = Number(parts[i]);
            if (part > 255) return null;
            n = n * 256 + part;
        }
        return n;
    }

    function ipv4InCidr(value, network, bits) {
        var a = ipv4ToInt(value);
        var b = ipv4ToInt(network);
        if (a === null || b === null || bits < 0 || bits > 32) return false;
        var mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
        return ((a & mask) >>> 0) === ((b & mask) >>> 0);
    }

    function compareOne(value, op, operand) {
        if (op === 'contains') {
            return String(value).toLowerCase().indexOf(String(operand).toLowerCase()) !== -1;
        }
        if (op === 'matches' || op === '~') {
            try {
                return new RegExp(String(operand), 'i').test(String(value));
            } catch (e) {
                return false;
            }
        }

        var cidr = /^([0-9.]+)\/([0-9]{1,2})$/.exec(String(operand));
        if (cidr && (op === '==' || op === '!=')) {
            var hit = ipv4InCidr(value, cidr[1], parseInt(cidr[2], 10));
            return op === '==' ? hit : !hit;
        }

        var left = asNumber(value);
        var right = asNumber(operand);
        if (left !== null && right !== null) {
            switch (op) {
                case '==': return left === right;
                case '!=': return left !== right;
                case '>': return left > right;
                case '>=': return left >= right;
                case '<': return left < right;
                case '<=': return left <= right;
            }
        }

        var a = String(value).toLowerCase();
        var b = String(operand).toLowerCase();
        switch (op) {
            case '==': return a === b;
            case '!=': return a !== b;
            case '>': return a > b;
            case '>=': return a >= b;
            case '<': return a < b;
            case '<=': return a <= b;
        }
        return false;
    }

    function fieldTruthy(value) {
        if (value === undefined || value === null) return false;
        if (Array.isArray(value)) return value.length > 0;
        if (typeof value === 'number') return value !== 0;
        return String(value) !== '';
    }

    function resolveField(packet, name) {
        name = String(name).toLowerCase();
        var aliases = FIELD_ALIASES[name];
        if (aliases) {
            var values = [];
            for (var i = 0; i < aliases.length; i++) {
                var value = packet.fields[aliases[i]];
                if (value === undefined || value === null) continue;
                values = values.concat(value);
            }
            return values.length ? values : undefined;
        }
        return packet.fields[name];
    }

    function evalTerm(packet, word) {
        var w = String(word).toLowerCase();
        if (w === 'frame') return true;
        if (w === 'ssl') w = 'tls';
        if (PROTOCOL_NAMES[w]) return !!packet.protocols[w];
        if (FIELD_ALIASES[w] || packet.fields[w] !== undefined) {
            return fieldTruthy(resolveField(packet, w));
        }
        return packet.hay.indexOf(w) !== -1;
    }

    function evalComparison(packet, node) {
        var value = resolveField(packet, node.field);
        var exists = value !== undefined && value !== null &&
            !(Array.isArray(value) && value.length === 0);
 
        if (!exists) return false;
        var list = Array.isArray(value) ? value : [value];
        if (node.op === '!=') {

            for (var n = 0; n < list.length; n++) {
                if (compareOne(list[n], '==', node.value)) return false;
            }
            return true;
        }
        for (var i = 0; i < list.length; i++) {
            if (compareOne(list[i], node.op, node.value)) return true;
        }
        return false;
    }

    function evalFilter(node, packet) {
        if (!node) return true;
        switch (node.type) {
            case 'and': return evalFilter(node.left, packet) && evalFilter(node.right, packet);
            case 'or': return evalFilter(node.left, packet) || evalFilter(node.right, packet);
            case 'not': return !evalFilter(node.expr, packet);
            case 'cmp': return evalComparison(packet, node);
            case 'term': return evalTerm(packet, node.value);
        }
        return false;
    }

    function applyFilter(viewer) {
        var expr = viewer.els.filter.value.trim();
        var ast = null;
        var error = null;

        if (expr) {
            try {
                ast = parseFilter(expr);
            } catch (err) {
                error = err && err.message ? err.message : String(err);
            }
        }

        viewer.filterError = error;
        viewer.els.filter.classList.toggle('invalid', !!error);
        if (error) {
            computeRowColors(viewer);
            refreshRows(viewer);
            academyEmit('filter', { expr: expr, error: error, matches: 0, nos: [] });
            return;
        }

        viewer.filterAst = ast;
        var indices = [];
        for (var i = 0; i < viewer.packets.length; i++) {
            if (evalFilter(ast, viewer.packets[i])) indices.push(i);
        }
        viewer.view = indices;
        computeRowColors(viewer);
        refreshRows(viewer);
        if (viewer.selected >= 0 && indices.indexOf(viewer.selected) === -1) {
            viewer.selected = -1;
            viewer.selectedField = null;
            viewer.els.tree.innerHTML = '<div class="pcap-hint">Select a packet to inspect its layers.</div>';
            viewer.els.hex.textContent = '';
            viewer.els.comment.value = '';
            viewer.els.comment.disabled = true;
            updateActionButtons(viewer);
        }
        academyEmit('filter', {
            expr: expr,
            error: error,
            matches: indices.length,
            nos: indices.map(function (i) { return viewer.packets[i].no; })
        });
    }

    function clearFilter(viewer) {
        viewer.els.filter.value = '';
        applyFilter(viewer);
        viewer.els.filter.focus();
    }

    function sortViewer(viewer) {
        var rows = viewer.view.slice();
        if (!viewer.sort) {
            viewer.rows = rows;
            return rows;
        }
        var config = null;
        for (var i = 0; i < viewer.columns.length; i++) if (viewer.columns[i].key === viewer.sort.key) config = viewer.columns[i];
        if (!config) { viewer.sort = null; viewer.rows = rows; return rows; }
        var dir = viewer.sort.dir;
        var numeric = config.key.indexOf('custom:') === 0 ? false : (columnDef(config.key) ? !!columnDef(config.key).numeric : false);
        rows.sort(function (ia, ib) {
            var a = packetColumnSortValue(viewer, viewer.packets[ia], config);
            var b = packetColumnSortValue(viewer, viewer.packets[ib], config);
            var ea = a === '' || a == null || (typeof a === 'number' && isNaN(a));
            var eb = b === '' || b == null || (typeof b === 'number' && isNaN(b));
            if (ea && eb) return ia - ib;
            if (ea) return 1;
            if (eb) return -1;
            var cmp;
            if (numeric && typeof a === 'number' && typeof b === 'number') cmp = a - b;
            else cmp = String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
            if (cmp === 0) return ia - ib;
            return dir * cmp;
        });
        viewer.rows = rows;
        return rows;
    }

    function refreshRows(viewer) {
        sortViewer(viewer);
        renderRows(viewer);
        updateStatus(viewer);
        updateActionButtons(viewer);
    }

    function renderTableHead(viewer) {
        var cols = visibleColumns(viewer);
        var colHtml = '<col class="pc-mark" style="width:30px">';
        var thHtml = '<th class="pc-mark" aria-label="Marked"></th>';
        for (var i = 0; i < cols.length; i++) {
            var c = cols[i];
            var width = columnWidth(c);
            var style = width ? ' style="width:' + width + 'px"' : '';
            var sorted = viewer.sort && viewer.sort.key === c.key;
            colHtml += '<col class="' + columnClass(c) + '" data-col="' + esc(c.key) + '"' + style + '>';
            thHtml += '<th class="' + columnClass(c) + (sorted ? ' sorted' : '') + '" data-col="' + esc(c.key) + '"' + style +
                ' draggable="true" title="Click to sort · drag to reorder · drag the edge to resize">' +
                '<span class="pcap-th-label">' + esc(columnLabel(c)) + '</span>' +
                (sorted ? '<span class="pcap-sort-arrow">' + (viewer.sort.dir === 1 ? '▲' : '▼') + '</span>' : '') +
                '<span class="pcap-resize" data-col="' + esc(c.key) + '" title="Resize column"></span>' +
            '</th>';
        }
        viewer.els.colgroup.innerHTML = colHtml;
        viewer.els.thead.querySelector('tr').innerHTML = thHtml;
    }

    function renderRows(viewer) {
        var cols = visibleColumns(viewer);
        var scroll = viewer.els.list.scrollTop;
        var rows = [];
        for (var i = 0; i < viewer.rows.length; i++) {
            var idx = viewer.rows[i];
            var p = viewer.packets[idx];
            if (!p) continue;
            var d = p.dec;
            var color = viewer.rowColors[idx];
            var marked = viewer.marked.has(idx);
            var comment = viewer.comments[idx];
            var cls = 'pcap-row p-' + esc(d.cls) +
                (marked ? ' marked' : '') +
                (color ? ' has-color' : '');
            var style = color ? ' style="background:' + esc(color.bg) + ';color:' + esc(color.fg) + '"' : '';
            var html = '<tr class="' + cls + '" data-i="' + idx + '" data-no="' + p.no + '"' + style + '>' +
                '<td class="pc-mark">' +
                    (marked ? '<span class="pcap-mark" title="Marked packet">◆</span>' : '') +
                    (comment ? '<span class="pcap-comment-flag" title="' + esc(comment) + '">✎</span>' : '') +
                '</td>';
            for (var c = 0; c < cols.length; c++) {
                var cfg = cols[c];
                var text = packetColumnText(viewer, p, cfg);
                var title = cfg.key === 'src' || cfg.key === 'dst' || cfg.key === 'info' ? ' title="' + esc(text) + '"' : '';
                html += '<td class="' + columnClass(cfg) + '"' + title + '>' + esc(text) + '</td>';
            }
            rows.push(html + '</tr>');
        }
        viewer.els.tbody.innerHTML = rows.length
            ? rows.join('')
            : '<tr><td colspan="' + (cols.length + 1) + '" class="pcap-empty">No packets match the current filter.</td></tr>';
        viewer.els.list.scrollTop = scroll;
        var sel = viewer.selected >= 0 ? viewer.els.tbody.querySelector('tr[data-i="' + viewer.selected + '"]') : null;
        if (sel) sel.classList.add('selected');
    }

    function updateStatus(viewer) {
        var total = viewer.packets.length;
        var shown = viewer.view.length;
        var expr = viewer.els.filter.value.trim();
        var parts = [];
        parts.push(expr
            ? 'Showing ' + shown + ' of ' + total + ' packets'
            : total + ' packet' + (total === 1 ? '' : 's'));
        if (viewer.marked.size) parts.push(plural(viewer.marked.size, 'marked packet', 'marked packets'));
        var commentCount = Object.keys(viewer.comments).length;
        if (commentCount) parts.push(plural(commentCount, 'comment'));
        if (viewer.truncated) parts.push('capture truncated to ' + MAX_PACKETS + ' packets');
        if (viewer.filterError) {
            parts.push('filter error: ' + viewer.filterError);
        } else {
            parts.push('filter: ' + (expr || 'none'));
        }
        if (viewer.findStatus) parts.push(viewer.findStatus);
        viewer.els.status.classList.toggle('pcap-status-error', !!viewer.filterError);
        setStatus(viewer, parts.join(' · '));
    }

    function updateActionButtons(viewer) {
        if (!viewer.els.markBtn) return;
        var marked = viewer.selected >= 0 && viewer.marked.has(viewer.selected);
        viewer.els.markBtn.textContent = marked ? 'Unmark' : 'Mark';
        viewer.els.markBtn.classList.toggle('active', marked);
    }

    function fieldAbbrev(layerName, label) {
        var layer = String(layerName || '');
        var name = String(label || '').replace(/:$/, '');
        var v6 = /Version 6/.test(layer);
        var tcp = /Transmission Control/.test(layer);
        var udp = /User Datagram/.test(layer);
        var http = /Hypertext/.test(layer);
        var dns = /Domain Name/.test(layer);
        var icmp = /ICMP/.test(layer);
        var map = {
            'Source Address': v6 ? 'ipv6.src' : 'ip.src',
            'Destination Address': v6 ? 'ipv6.dst' : 'ip.dst',
            'Source Port': tcp ? 'tcp.srcport' : (udp ? 'udp.srcport' : null),
            'Destination Port': tcp ? 'tcp.dstport' : (udp ? 'udp.dstport' : null),
            'Sequence Number': tcp ? 'tcp.seq' : null,
            'Acknowledgment Number': tcp ? 'tcp.ack' : null,
            'Window': tcp ? 'tcp.window' : null,
            'Payload Length': tcp ? 'tcp.len' : null,
            'Time to Live': 'ip.ttl',
            'Hop Limit': 'ipv6.hlim',
            'Protocol': /Internet Protocol/.test(layer) ? 'ip.proto' : null,
            'Header Checksum': 'ip.checksum',
            'Query Name': dns ? 'dns.qry.name' : null,
            'Transaction ID': dns ? 'dns.id' : null,
            'Request Method': http ? 'http.request.method' : null,
            'Request URI': http ? 'http.request.uri' : null,
            'Host': http ? 'http.host' : null,
            'Status Code': http ? 'http.response.code' : null,
            'Content-Type': http ? 'http.content_type' : null,
            'User-Agent': http ? 'http.user_agent' : null,
            'VLAN': 'vlan.id',
            'Type': /Ethernet/.test(layer) ? 'eth.type' : null,
            'Echo Request': null,
            'Checksum': tcp ? 'tcp.checksum' : (udp ? 'udp.checksum' : null),
            'Flags': tcp ? 'tcp.flags' : null,
            'Frame Number': 'frame.number',
            'Frame Length': 'frame.len',
            'Capture Length': 'frame.cap_len'
        };
        return Object.prototype.hasOwnProperty.call(map, name) ? map[name] : null;
    }

    function frameLayer(p) {
        var arrival = p.time != null ? formatAbsolute(p.time * 1000, false) : 'n/a';
        var fields = [
            ['Frame Number', p.no],
            ['Frame Length', p.len + ' bytes'],
            ['Capture Length', p.cap + ' bytes'],
            ['Arrival Time', arrival],
            ['Time Since First Frame', p.rel.toFixed(6) + ' s'],
            ['Protocols', p.dec.chain.join(':') || 'data']
        ];
        if (viewerCommentsFor(p)) fields.push(['Packet Comments', viewerCommentsFor(p)]);
        return {
            abbrev: 'frame',
            name: 'Frame ' + p.no + ': ' + p.len + ' bytes on wire, ' + p.cap + ' bytes captured',
            fields: fields
        };
    }

    function viewerCommentsFor(p) {
        if (!activeViewer) return '';
        return activeViewer.comments[p.no - 1] || '';
    }

    function selectPacket(viewer, index, keepScroll) {
        var p = viewer.packets[index];
        if (!p) return;
        viewer.selected = index;
        viewer.selectedField = null;
        var prev = viewer.els.tbody.querySelector('tr.selected');
        if (prev) prev.classList.remove('selected');
        var row = viewer.els.tbody.querySelector('tr[data-i="' + index + '"]');
        if (row) {
            row.classList.add('selected');
            if (!keepScroll && row.scrollIntoView) {
                try { row.scrollIntoView({ block: 'nearest' }); } catch (e) { }
            }
        }

        var layers = [frameLayer(p)].concat(p.dec.tree);
        var html = '';
        for (var i = 0; i < layers.length; i++) {
            var l = layers[i];
            html += '<div class="pcap-layer" data-layer="' + esc(l.name) + '">' +
                '<div class="pcap-layer-head"><span class="pcap-caret">▾</span><span>' + esc(l.name) + '</span></div>' +
                '<div class="pcap-fields">';
            for (var j = 0; j < l.fields.length; j++) {
                var label = String(l.fields[j][0]);
                var value = String(l.fields[j][1]);
                var abbrev = fieldAbbrev(l.name, label);
                html += '<div class="pcap-field" data-label="' + esc(label) + '" data-value="' + esc(value) + '"' +
                    (abbrev ? ' data-abbrev="' + esc(abbrev) + '"' : '') + '>' +
                    '<span class="pcap-flabel">' + esc(label) + ':</span> ' +
                    '<span class="pcap-fval">' + esc(value) + '</span></div>';
            }
            html += '</div></div>';
        }
        viewer.els.tree.innerHTML = html;
        viewer.els.tree.scrollTop = 0;
        viewer.els.hex.textContent = hexDump(p.bytes);
        viewer.els.hex.scrollTop = 0;
        viewer.els.comment.disabled = false;
        viewer.els.comment.value = viewer.comments[index] || '';
        updateActionButtons(viewer);
        academyEmit('select', packetSnapshot(p));
    }

    function sortByColumn(viewer, key) {
        if (viewer.sort && viewer.sort.key === key) {
            if (viewer.sort.dir === 1) viewer.sort.dir = -1;
            else viewer.sort = null;
        } else {
            viewer.sort = { key: key, dir: 1 };
        }
        sortViewer(viewer);
        renderTableHead(viewer);
        renderRows(viewer);
        updateStatus(viewer);
    }

    function startColumnResize(viewer, key, startX, th) {
        var config = null;
        for (var i = 0; i < viewer.columns.length; i++) if (viewer.columns[i].key === key) config = viewer.columns[i];
        if (!config) return;
        viewer.suppressSort = true;
        var startWidth = th.getBoundingClientRect().width;
        var baseWidth = config.width || startWidth;
        var col = viewer.els.colgroup.querySelector('col[data-col="' + key + '"]');
        function onMove(e) {
            var width = Math.max(40, Math.round(baseWidth + e.clientX - startX));
            config.width = width;
            th.style.width = width + 'px';
            if (col) col.style.width = width + 'px';
        }
        function onUp() {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
            writeStore(STORE_COLS, viewer.columns);
            setTimeout(function () { viewer.suppressSort = false; }, 0);
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    }

    function moveColumn(viewer, fromKey, toKey) {
        var from = -1, to = -1;
        for (var i = 0; i < viewer.columns.length; i++) {
            if (viewer.columns[i].key === fromKey) from = i;
            if (viewer.columns[i].key === toKey) to = i;
        }
        if (from < 0 || to < 0 || from === to) return;
        var moved = viewer.columns.splice(from, 1)[0];
        viewer.columns.splice(to, 0, moved);
        writeStore(STORE_COLS, viewer.columns);
        renderTableHead(viewer);
        renderRows(viewer);
    }

    function setTimeFormat(viewer, fmt) {
        viewer.timeFormat = fmt;
        writeStore(STORE_TIME, fmt);
        var timeCol = null;
        for (var i = 0; i < viewer.columns.length; i++) if (viewer.columns[i].key === 'time') timeCol = viewer.columns[i];
        if (timeCol && (fmt === 'abs-local' || fmt === 'abs-utc') && !timeCol.width) timeCol.width = 190;
        renderTableHead(viewer);
        renderRows(viewer);
        showToast(viewer, 'Time display: ' + fmt);
    }

    function toggleMark(viewer, index) {
        if (index == null || index < 0) return;
        if (viewer.marked.has(index)) viewer.marked.delete(index);
        else viewer.marked.add(index);
        patchRowMark(viewer, index);
        updateStatus(viewer);
        updateActionButtons(viewer);
        var markedNos = [];
        viewer.marked.forEach(function (i) {
            if (viewer.packets[i]) markedNos.push(viewer.packets[i].no);
        });
        markedNos.sort(function (a, b) { return a - b; });
        academyEmit('mark', { nos: markedNos, packet: viewer.packets[index] ? viewer.packets[index].no : null });
    }

    function patchRowMark(viewer, index) {
        var row = viewer.els.tbody.querySelector('tr[data-i="' + index + '"]');
        if (!row) return;
        row.classList.toggle('marked', viewer.marked.has(index));
        var cell = row.querySelector('.pc-mark');
        if (!cell) return;
        var mark = cell.querySelector('.pcap-mark');
        if (viewer.marked.has(index)) {
            if (!mark) {
                mark = document.createElement('span');
                mark.className = 'pcap-mark';
                mark.title = 'Marked packet';
                mark.textContent = '◆';
                cell.insertBefore(mark, cell.firstChild);
            }
        } else if (mark) {
            mark.remove();
        }
    }

    function markAllDisplayed(viewer) {
        for (var i = 0; i < viewer.rows.length; i++) viewer.marked.add(viewer.rows[i]);
        renderRows(viewer);
        updateStatus(viewer);
        updateActionButtons(viewer);
        showToast(viewer, 'Marked ' + plural(viewer.rows.length, 'packet'));
    }

    function unmarkAll(viewer) {
        viewer.marked.clear();
        renderRows(viewer);
        updateStatus(viewer);
        updateActionButtons(viewer);
        showToast(viewer, 'All packet marks cleared');
    }

    function updateRowCommentFlag(viewer, index) {
        var row = viewer.els.tbody.querySelector('tr[data-i="' + index + '"]');
        if (!row) return;
        var cell = row.querySelector('.pc-mark');
        if (!cell) return;
        var flag = cell.querySelector('.pcap-comment-flag');
        var comment = viewer.comments[index];
        if (comment) {
            if (!flag) {
                flag = document.createElement('span');
                flag.className = 'pcap-comment-flag';
                flag.textContent = '✎';
                cell.appendChild(flag);
            }
            flag.title = comment;
        } else if (flag) {
            flag.remove();
        }
        updateStatus(viewer);
    }

    function packetSummary(viewer, p) {
        return p.no + '\t' + formatTime(viewer, p) + '\t' + (p.dec.src || '') + '\t' +
            (p.dec.dst || '') + '\t' + p.dec.proto + '\t' + p.len + '\t' + p.dec.info;
    }

    function openCommentDialog(viewer, index) {
        var p = viewer.packets[index];
        if (!p) return;
        var current = viewer.comments[index] || '';
        var back = showModal(viewer, 'Packet Comment — Frame ' + p.no,
            '<textarea class="pcap-textarea" rows="5" placeholder="Add a comment for this packet…">' + esc(current) + '</textarea>' +
            '<p class="pcap-dim">Comments are kept for this viewer session.</p>' +
            '<div class="pcap-dialog-actions">' +
                '<button type="button" class="pcap-btn" data-remove' + (current ? '' : ' disabled') + '>Remove</button>' +
                '<span class="pcap-spacer"></span>' +
                '<button type="button" class="pcap-btn" data-cancel>Cancel</button>' +
                '<button type="button" class="pcap-btn primary" data-save>Save Comment</button>' +
            '</div>');
        var body = modalBody(viewer);
        var area = body.querySelector('textarea');
        area.focus();
        area.select();
        function save() {
            var text = area.value.trim();
            if (text) viewer.comments[index] = text;
            else delete viewer.comments[index];
            if (viewer.selected === index) {
                viewer.els.comment.value = text;
                var layers = [frameLayer(p)].concat(p.dec.tree);
                if (layers.length) selectPacket(viewer, index, true);
            }
            updateRowCommentFlag(viewer, index);
            closeDialog(viewer);
        }
        body.querySelector('[data-save]').addEventListener('click', save);
        body.querySelector('[data-remove]').addEventListener('click', function () {
            delete viewer.comments[index];
            if (viewer.selected === index) {
                viewer.els.comment.value = '';
                selectPacket(viewer, index, true);
            }
            updateRowCommentFlag(viewer, index);
            closeDialog(viewer);
        });
        body.querySelector('[data-cancel]').addEventListener('click', function () { closeDialog(viewer); });
        area.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) save();
        });
    }

    function parseHexNeedle(text) {
        var clean = String(text).replace(/0x/gi, '').replace(/[\s:]/g, '');
        if (!clean.length || clean.length % 2 || !/^[0-9a-fA-F]+$/.test(clean)) return null;
        var out = new Uint8Array(clean.length / 2);
        for (var i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
        return out;
    }

    function bytesContain(hay, needle) {
        if (!needle || !needle.length) return false;
        outer:
        for (var i = 0; i + needle.length <= hay.length; i++) {
            for (var j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
            return true;
        }
        return false;
    }

    function findMatch(viewer, params, index) {
        var p = viewer.packets[index];
        if (!p) return false;
        if (params.type === 'filter') {
            try { return evalFilter(parseFilter(params.text), p); } catch (e) { return false; }
        }
        if (params.type === 'hex') {
            var needle = parseHexNeedle(params.text);
            return !!(needle && bytesContain(p.bytes, needle));
        }
        var needleText = params.caseSensitive ? params.text : params.text.toLowerCase();
        if (params.scope === 'bytes') {
            var hay = latin1(p.bytes, 0, p.bytes.length);
            if (!params.caseSensitive) hay = hay.toLowerCase();
            return hay.indexOf(needleText) !== -1;
        }
        var info = (p.dec.src || '') + ' ' + (p.dec.dst || '') + ' ' + p.dec.proto + ' ' + p.dec.info;
        if (!params.caseSensitive) info = info.toLowerCase();
        return info.indexOf(needleText) !== -1;
    }

    function findNextIndex(viewer, params, dir) {
        var list = viewer.rows.length ? viewer.rows : viewer.view;
        if (!list.length || !params.text.trim()) return { index: null };
        if (params.type === 'filter') {
            try { parseFilter(params.text); } catch (e) { return { index: null, error: e.message || String(e) }; }
        }
        if (params.type === 'hex' && !parseHexNeedle(params.text)) {
            return { index: null, error: 'Invalid hex value' };
        }
        var current = list.indexOf(viewer.selected);
        for (var step = 1; step <= list.length; step++) {
            var pos = (((current + dir * step) % list.length) + list.length) % list.length;
            if (findMatch(viewer, params, list[pos])) return { index: list[pos] };
        }
        return { index: null };
    }

    function findAgain(viewer, dir) {
        if (!viewer.find.text.trim()) {
            openFindDialog(viewer);
            return;
        }
        var result = findNextIndex(viewer, viewer.find, dir);
        if (result.error) {
            viewer.findStatus = 'find error: ' + result.error;
            updateStatus(viewer);
            showToast(viewer, 'Find error: ' + result.error);
            return;
        }
        if (result.index == null) {
            viewer.findStatus = 'not found: ' + viewer.find.text;
            updateStatus(viewer);
            showToast(viewer, 'No matching packet');
            return;
        }
        viewer.findStatus = 'found packet ' + viewer.packets[result.index].no;
        selectPacket(viewer, result.index);
        updateStatus(viewer);
        showToast(viewer, 'Found packet ' + viewer.packets[result.index].no);
    }

    function openFindDialog(viewer) {
        var f = viewer.find;
        var back = showModal(viewer, 'Find Packet',
            '<div class="pcap-form-grid">' +
                '<label>Search by</label>' +
                '<select class="pcap-select" data-find="type">' +
                    '<option value="filter"' + (f.type === 'filter' ? ' selected' : '') + '>Display filter</option>' +
                    '<option value="string"' + (f.type === 'string' ? ' selected' : '') + '>String</option>' +
                    '<option value="hex"' + (f.type === 'hex' ? ' selected' : '') + '>Hex value</option>' +
                '</select>' +
                '<label>In</label>' +
                '<select class="pcap-select" data-find="scope"' + (f.type === 'filter' ? ' disabled' : '') + '>' +
                    '<option value="info"' + (f.scope === 'info' ? ' selected' : '') + '>Packet list (Info)</option>' +
                    '<option value="bytes"' + (f.scope === 'bytes' ? ' selected' : '') + '>Packet bytes</option>' +
                '</select>' +
                '<label data-find-label>' + (f.type === 'hex' ? 'Hex bytes' : f.type === 'filter' ? 'Filter' : 'String') + '</label>' +
                '<input class="pcap-input mono" data-find="text" spellcheck="false" value="' + esc(f.text) + '" ' +
                    'placeholder="' + (f.type === 'hex' ? 'e.g. 47 45 54 or 474554' : f.type === 'filter' ? 'e.g. http.request' : 'e.g. GET /') + '">' +
            '</div>' +
            '<div class="pcap-dialog-toolbar">' +
                '<label class="pcap-check" data-case-row' + (f.type === 'string' ? '' : ' hidden') + '>' +
                    '<input type="checkbox" data-find="case"' + (f.caseSensitive ? ' checked' : '') + '> Case sensitive' +
                '</label>' +
                '<span class="pcap-find-status pcap-dim" data-find-status></span>' +
                '<span class="pcap-spacer"></span>' +
                '<button type="button" class="pcap-btn" data-find-prev>Find Previous</button>' +
                '<button type="button" class="pcap-btn primary" data-find-next>Find Next</button>' +
            '</div>', { wide: false });
        var body = modalBody(viewer);
        var typeSel = body.querySelector('[data-find="type"]');
        var scopeSel = body.querySelector('[data-find="scope"]');
        var textInput = body.querySelector('[data-find="text"]');
        var caseInput = body.querySelector('[data-find="case"]');
        var status = body.querySelector('[data-find-status]');
        var caseRow = body.querySelector('[data-case-row]');
        var label = body.querySelector('[data-find-label]');
        textInput.focus();
        textInput.select();

        function sync() {
            f.type = typeSel.value;
            f.scope = scopeSel.value;
            f.text = textInput.value;
            f.caseSensitive = caseInput.checked;
            scopeSel.disabled = f.type === 'filter';
            caseRow.hidden = f.type !== 'string';
            label.textContent = f.type === 'hex' ? 'Hex bytes' : f.type === 'filter' ? 'Filter' : 'String';
            textInput.placeholder = f.type === 'hex' ? 'e.g. 47 45 54 or 474554' :
                f.type === 'filter' ? 'e.g. http.request' : 'e.g. GET /';
        }
        function run(dir) {
            sync();
            var result = findNextIndex(viewer, f, dir);
            if (result.error) {
                status.textContent = result.error;
                status.classList.add('pcap-status-error');
                return;
            }
            if (result.index == null) {
                status.textContent = 'No matching packet';
                status.classList.remove('pcap-status-error');
                return;
            }
            status.textContent = 'Packet ' + viewer.packets[result.index].no;
            status.classList.remove('pcap-status-error');
            viewer.findStatus = 'found packet ' + viewer.packets[result.index].no;
            selectPacket(viewer, result.index);
            updateStatus(viewer);
        }
        typeSel.addEventListener('change', sync);
        scopeSel.addEventListener('change', sync);
        textInput.addEventListener('input', sync);
        caseInput.addEventListener('change', sync);
        textInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                run(e.shiftKey ? -1 : 1);
            }
        });
        body.querySelector('[data-find-next]').addEventListener('click', function () { run(1); });
        body.querySelector('[data-find-prev]').addEventListener('click', function () { run(-1); });
        textInput.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') { e.stopPropagation(); closeDialog(viewer); }
        });
    }

    function goToPacket(viewer, no) {
        var index = no - 1;
        if (index < 0 || index >= viewer.packets.length) return false;
        if (viewer.rows.indexOf(index) === -1) {
            var cleared = viewer.els.filter.value.trim();
            if (cleared) {
                viewer.els.filter.value = '';
                applyFilter(viewer);
            }
        }
        selectPacket(viewer, index);
        return true;
    }

    function openGotoDialog(viewer) {
        showModal(viewer, 'Go to Packet',
            '<label class="pcap-field-label">Packet number</label>' +
            '<input class="pcap-input mono" data-goto type="number" min="1" max="' + viewer.packets.length + '" ' +
                'placeholder="1 – ' + viewer.packets.length + '">' +
            '<div class="pcap-dialog-actions">' +
                '<span class="pcap-dim" data-goto-status></span>' +
                '<span class="pcap-spacer"></span>' +
                '<button type="button" class="pcap-btn primary" data-go>Go</button>' +
            '</div>');
        var body = modalBody(viewer);
        var input = body.querySelector('[data-goto]');
        var status = body.querySelector('[data-goto-status]');
        input.focus();
        function go() {
            var n = parseInt(input.value, 10);
            if (!isFinite(n) || n < 1 || n > viewer.packets.length) {
                status.textContent = 'Enter 1 – ' + viewer.packets.length;
                return;
            }
            goToPacket(viewer, n);
            closeDialog(viewer);
        }
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); go(); }
        });
        body.querySelector('[data-go]').addEventListener('click', go);
    }

    function goRelative(viewer, where) {
        var list = viewer.rows;
        if (!list.length) return;
        if (where === 'first') { selectPacket(viewer, list[0]); return; }
        if (where === 'last') { selectPacket(viewer, list[list.length - 1]); return; }
        var pos = list.indexOf(viewer.selected);
        if (pos === -1) pos = where > 0 ? -1 : list.length;
        var next = Math.max(0, Math.min(list.length - 1, pos + where));
        selectPacket(viewer, list[next]);
    }

    function conversationKey(p) {
        if (p.transport && p.srcport !== '' && p.dstport !== '') {
            var a = p.dec.src + ':' + p.srcport;
            var b = p.dec.dst + ':' + p.dstport;
            return p.transport + '|' + (a < b ? a + '|' + b : b + '|' + a);
        }
        return (p.transport || p.dec.proto) + '|' + (p.dec.src || '') + '|' + (p.dec.dst || '');
    }

    function goConversation(viewer, dir) {
        if (viewer.selected < 0) return;
        var key = conversationKey(viewer.packets[viewer.selected]);
        var candidates = [];
        for (var i = 0; i < viewer.rows.length; i++) {
            if (conversationKey(viewer.packets[viewer.rows[i]]) === key) candidates.push(viewer.rows[i]);
        }
        if (candidates.length < 2) return;
        var pos = candidates.indexOf(viewer.selected);
        if (pos === -1) pos = 0;
        var next = (pos + dir + candidates.length) % candidates.length;
        selectPacket(viewer, candidates[next]);
    }

    function applyExprFilter(viewer, expr) {
        viewer.els.filter.value = expr;
        applyFilter(viewer);
        showToast(viewer, 'Filter: ' + expr);
    }

    function applyPacketFilter(viewer, what) {
        if (viewer.selected < 0) return;
        var p = viewer.packets[viewer.selected];
        var expr = '';
        if (what === 'src') {
            expr = p.fields['ipv6.src'] ? 'ipv6.addr == ' + p.fields['ipv6.src'] :
                p.fields['ip.src'] ? 'ip.addr == ' + p.fields['ip.src'] :
                p.fields['eth.src'] ? 'eth.src == ' + p.fields['eth.src'] : '';
        } else if (what === 'dst') {
            expr = p.fields['ipv6.dst'] ? 'ipv6.addr == ' + p.fields['ipv6.dst'] :
                p.fields['ip.dst'] ? 'ip.addr == ' + p.fields['ip.dst'] :
                p.fields['eth.dst'] ? 'eth.dst == ' + p.fields['eth.dst'] : '';
        } else {
            var chain = p.dec.chain;
            var proto = chain.length ? chain[chain.length - 1] : String(p.dec.proto).toLowerCase();
            expr = proto;
        }
        if (expr) applyExprFilter(viewer, expr);
    }

    function expandAll(viewer, open) {
        var layers = viewer.els.tree.querySelectorAll('.pcap-layer');
        for (var i = 0; i < layers.length; i++) layers[i].classList.toggle('collapsed', !open);
    }

    function openContextMenu(viewer, x, y, items) {
        closeContextMenu(viewer);
        var menu = document.createElement('div');
        menu.className = 'pcap-ctx';
        var html = '';
        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            if (!item) continue;
            if (item.separator) { html += '<div class="pcap-menu-sep"></div>'; continue; }
            html += '<button type="button" class="pcap-menu-item" data-ctx="' + i + '"' +
                (item.disabled ? ' disabled' : '') + '>' +
                '<span class="pcap-menu-check">' + (item.checked ? '✓' : '') + '</span>' +
                '<span class="pcap-menu-label">' + esc(item.label) + '</span>' +
                (item.shortcut ? '<span class="pcap-menu-shortcut">' + esc(item.shortcut) + '</span>' : '') +
            '</button>';
        }
        menu.innerHTML = html;
        menu._items = items;
        viewer.els.window.appendChild(menu);
        var win = viewer.els.window.getBoundingClientRect();
        var left = x - win.left;
        var top = y - win.top;
        var mw = menu.offsetWidth;
        var mh = menu.offsetHeight;
        menu.style.left = Math.max(4, Math.min(left, win.width - mw - 6)) + 'px';
        menu.style.top = Math.max(4, Math.min(top, win.height - mh - 6)) + 'px';
        viewer.contextMenu = menu;
        menu.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-ctx]');
            if (!btn) return;
            var idx = parseInt(btn.getAttribute('data-ctx'), 10);
            var entry = menu._items[idx];
            closeContextMenu(viewer);
            if (entry && !entry.disabled && entry.action) entry.action();
        });
        viewer.onCtxOutside = function (e) {
            if (!menu.contains(e.target)) closeContextMenu(viewer);
        };
        setTimeout(function () {
            document.addEventListener('mousedown', viewer.onCtxOutside, true);
        }, 0);
    }

    function closeContextMenu(viewer) {
        if (!viewer) return;
        if (viewer.contextMenu) {
            viewer.contextMenu.remove();
            viewer.contextMenu = null;
        }
        if (viewer.onCtxOutside) {
            document.removeEventListener('mousedown', viewer.onCtxOutside, true);
            viewer.onCtxOutside = null;
        }
    }

    function openPacketContextMenu(viewer, x, y, index) {
        var p = viewer.packets[index];
        if (!p) return;
        var marked = viewer.marked.has(index);
        var items = [
            { label: (marked ? 'Unmark' : 'Mark') + ' Packet', shortcut: 'Ctrl+M', action: function () { toggleMark(viewer, index); } },
            { label: 'Mark All Displayed', action: function () { markAllDisplayed(viewer); } },
            { label: 'Unmark All', disabled: !viewer.marked.size, action: function () { unmarkAll(viewer); } },
            { label: 'Packet Comment…', shortcut: 'Ctrl+Alt+C', action: function () { openCommentDialog(viewer, index); } },
            { separator: true },
            { label: 'Follow Stream', shortcut: 'Ctrl+Alt+Shift+T', disabled: !(p.transport === 'tcp' || p.transport === 'udp'), action: function () { openFollowStream(viewer, index); } },
            { label: 'Apply as Filter: Source', action: function () { applyPacketFilter(viewer, 'src'); } },
            { label: 'Apply as Filter: Destination', action: function () { applyPacketFilter(viewer, 'dst'); } },
            { label: 'Apply as Filter: Protocol', action: function () { applyPacketFilter(viewer, 'proto'); } },
            { separator: true },
            { label: 'Copy Summary as Text', action: function () { copyText(packetSummary(viewer, p)); showToast(viewer, 'Summary copied'); } },
            { label: 'Copy Source', action: function () { copyText(p.dec.src); showToast(viewer, 'Source copied'); } },
            { label: 'Copy Destination', action: function () { copyText(p.dec.dst); showToast(viewer, 'Destination copied'); } },
            { label: 'Copy Info', action: function () { copyText(p.dec.info); showToast(viewer, 'Info copied'); } },
            { label: 'Copy Packet Bytes as Hex', action: function () { copyText(hexDump(p.bytes)); showToast(viewer, 'Bytes copied'); } },
            { separator: true },
            { label: 'Go to First Packet', action: function () { goRelative(viewer, 'first'); } },
            { label: 'Go to Last Packet', action: function () { goRelative(viewer, 'last'); } },
            { label: 'Find Frame (Info)…', action: function () { viewer.find = { type: 'string', scope: 'info', caseSensitive: false, text: p.dec.info }; openFindDialog(viewer); } }
        ];
        openContextMenu(viewer, x, y, items);
    }

    function openTreeContextMenu(viewer, x, y, field, head) {
        var items = [];
        if (field) {
            var label = field.getAttribute('data-label') || '';
            var value = field.getAttribute('data-value') || '';
            var abbrev = field.getAttribute('data-abbrev') || '';
            items.push({ label: 'Copy Value', action: function () { copyText(value); showToast(viewer, 'Value copied'); } });
            items.push({ label: 'Copy Field Name', action: function () { copyText(label); showToast(viewer, 'Field name copied'); } });
            items.push({
                label: 'Apply as Filter: ' + (abbrev || label), disabled: !abbrev,
                action: function () {
                    var literal = /^-?\d+(?:\.\d+)?$/.test(value) || /^0x[0-9a-f]+$/i.test(value) ? value : '"' + value.replace(/"/g, '\\"') + '"';
                    applyExprFilter(viewer, abbrev + ' == ' + literal);
                }
            });
            items.push({ label: 'Find Frame with This Value', action: function () {
                viewer.find = { type: 'string', scope: 'info', caseSensitive: false, text: value };
                openFindDialog(viewer);
            } });
            items.push({ separator: true });
        }
        items.push({ label: 'Expand All', action: function () { expandAll(viewer, true); } });
        items.push({ label: 'Collapse All', action: function () { expandAll(viewer, false); } });
        if (head) {
            items.push({ label: 'Copy Layer Text', action: function () { copyText(head.textContent); showToast(viewer, 'Layer copied'); } });
        }
        openContextMenu(viewer, x, y, items);
    }

    function stepZoom(viewer, dir) {
        var idx = ZOOM_LEVELS.indexOf(viewer.zoom);
        if (idx === -1) {
            idx = 0;
            while (idx < ZOOM_LEVELS.length - 1 && ZOOM_LEVELS[idx] < viewer.zoom) idx++;
            if (ZOOM_LEVELS[idx] > viewer.zoom && idx > 0) idx--;
        }
        setZoom(viewer, ZOOM_LEVELS[Math.min(ZOOM_LEVELS.length - 1, Math.max(0, idx + dir))]);
    }

    function streamText(bytes) {
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
            var v = bytes[i];
            if (v === 10) out += '\n';
            else if (v === 9) out += '    ';
            else if (v === 13) continue;
            else if (v >= 0x20 && v <= 0x7e) out += String.fromCharCode(v);
            else out += '.';
        }
        return out;
    }

    function openFollowStream(viewer, index) {
        var p = viewer.packets[index];
        if (!p) return;
        if (p.transport !== 'tcp' && p.transport !== 'udp') {
            showMessageDialog(viewer, 'Follow Stream', 'This packet is not part of a TCP or UDP conversation.');
            return;
        }

        var key = conversationKey(p);
        var client = { addr: p.dec.src, port: p.srcport };
        var server = { addr: p.dec.dst, port: p.dstport };
        var segments = [];
        var clientBytes = 0;
        var serverBytes = 0;
        var packetCount = 0;

        for (var i = 0; i < viewer.packets.length; i++) {
            var q = viewer.packets[i];
            if (!q.payload || conversationKey(q) !== key) continue;
            var data = q.bytes.subarray(q.payload.off, q.payload.end);
            if (!data.length) continue;
            var dir = (q.dec.src === client.addr && q.srcport === client.port) ? 0 : 1;
            if (dir === 0) clientBytes += data.length; else serverBytes += data.length;
            packetCount++;
            segments.push({ dir: dir, bytes: data, no: q.no });
        }

        if (!segments.length) {
            showMessageDialog(viewer, 'Follow ' + p.transport.toUpperCase() + ' Stream',
                'No payload was captured for this conversation.');
            return;
        }

        var back = showModal(viewer, 'Follow ' + p.transport.toUpperCase() + ' Stream',
            '<div class="pcap-fs-meta">' +
                '<span class="pcap-fs-dir0">' + esc(client.addr) + ':' + esc(client.port) + '</span>' +
                '<span class="pcap-dim"> ↔ </span>' +
                '<span class="pcap-fs-dir1">' + esc(server.addr) + ':' + esc(server.port) + '</span>' +
                '<span class="pcap-dim"> · client → server ' + fmtBytes(clientBytes) +
                    ' · server → client ' + fmtBytes(serverBytes) + ' · ' + plural(packetCount, 'packet') + '</span>' +
            '</div>' +
            '<div class="pcap-dialog-toolbar">' +
                '<select class="pcap-select" data-fs-dir>' +
                    '<option value="both">Entire conversation</option>' +
                    '<option value="client">Client → Server</option>' +
                    '<option value="server">Server → Client</option>' +
                '</select>' +
                '<select class="pcap-select" data-fs-view>' +
                    '<option value="ascii">ASCII</option>' +
                    '<option value="hex">Hex dump</option>' +
                '</select>' +
                '<label class="pcap-check"><input type="checkbox" data-fs-numbers> Show packet numbers</label>' +
                '<span class="pcap-spacer"></span>' +
                '<button type="button" class="pcap-btn" data-fs-copy>Copy</button>' +
            '</div>' +
            '<pre class="pcap-fs-body" data-fs-body></pre>', { wide: true });

        var body = modalBody(viewer);
        var dirSel = body.querySelector('[data-fs-dir]');
        var viewSel = body.querySelector('[data-fs-view]');
        var numbers = body.querySelector('[data-fs-numbers]');
        var pre = body.querySelector('[data-fs-body]');

        function render() {
            var dir = dirSel.value;
            var asHex = viewSel.value === 'hex';
            var html = '';
            for (var s = 0; s < segments.length; s++) {
                var seg = segments[s];
                if (dir === 'client' && seg.dir !== 0) continue;
                if (dir === 'server' && seg.dir !== 1) continue;
                if (numbers.checked) {
                    html += '<span class="pcap-fs-num">' + (seg.dir === 0 ? '→' : '←') + ' #' + seg.no + '</span>\n';
                }
                html += '<span class="' + (seg.dir === 0 ? 'pcap-fs-dir0' : 'pcap-fs-dir1') + '">' +
                    esc(asHex ? hexDump(seg.bytes) : streamText(seg.bytes)) + '</span>' +
                    (asHex ? '\n' : '');
            }
            pre.innerHTML = html || '<span class="pcap-dim">No data in this direction.</span>';
            pre.scrollTop = 0;
        }

        dirSel.addEventListener('change', render);
        viewSel.addEventListener('change', render);
        numbers.addEventListener('change', render);
        body.querySelector('[data-fs-copy]').addEventListener('click', function () {
            copyText(pre.textContent);
            showToast(viewer, 'Stream copied');
        });
        render();
        pre.focus();
    }

    function fmtDuration(seconds) {
        if (!isFinite(seconds) || seconds <= 0) return '0.000 s';
        if (seconds < 1) return (seconds * 1000).toFixed(3) + ' ms';
        if (seconds < 60) return seconds.toFixed(6) + ' s';
        var mins = Math.floor(seconds / 60);
        var rest = seconds - mins * 60;
        if (mins < 60) return mins + ' min ' + rest.toFixed(3) + ' s';
        var hours = Math.floor(mins / 60);
        return hours + ' h ' + (mins - hours * 60) + ' min ' + rest.toFixed(0) + ' s';
    }

    function captureStats(viewer) {
        var bytes = 0;
        var first = null;
        var last = null;
        for (var i = 0; i < viewer.packets.length; i++) {
            var p = viewer.packets[i];
            bytes += p.cap;
            if (p.time != null) {
                if (first == null || p.time < first) first = p.time;
                if (last == null || p.time > last) last = p.time;
            }
        }
        var duration = first != null && last != null ? Math.max(0, last - first) : 0;
        return {
            packets: viewer.packets.length,
            bytes: bytes,
            first: first,
            last: last,
            duration: duration,
            fileSize: viewer.fileSize || 0,
            format: viewer.format || 'unknown',
            linkType: viewer.linkType,
            truncated: !!viewer.truncated
        };
    }

    function showCaptureProperties(viewer) {
        var s = captureStats(viewer);
        var encap = linkTypeName(s.linkType);
        var pps = s.duration > 0 ? s.packets / s.duration : 0;
        var rows = [
            ['File name', viewer.name || (viewer.url ? viewer.url.split('/').pop() : 'capture')],
            ['Format', s.format === 'pcapng' ? 'pcapng' : 'pcap'],
            ['Encapsulation', encap],
            ['File size', s.fileSize ? fmtBytes(s.fileSize) : '—'],
            ['Packets', s.packets + (s.truncated ? ' (truncated)' : '')],
            ['Captured bytes', fmtBytes(s.bytes)],
            ['Average packet size', s.packets ? Math.round(s.bytes / s.packets) + ' bytes' : '—'],
            ['First packet', s.first != null ? formatAbsolute(s.first * 1000, false) : '—'],
            ['Last packet', s.last != null ? formatAbsolute(s.last * 1000, false) : '—'],
            ['Duration', fmtDuration(s.duration)],
            ['Average packets/s', pps ? pps.toFixed(2) : '—'],
            ['Displayed packets', String(viewer.view.length)],
            ['Display filter', viewer.els.filter.value.trim() || '(none)']
        ];
        var html = '<table class="pcap-props">';
        for (var i = 0; i < rows.length; i++) {
            html += '<tr><th>' + esc(rows[i][0]) + '</th><td>' + esc(rows[i][1]) + '</td></tr>';
        }
        html += '</table>';
        showModal(viewer, 'Capture File Properties', html);
    }

    function linkTypeName(linkType) {
        if (linkType === 1) return 'Ethernet';
        if (linkType === 101) return 'Raw IP';
        if (linkType === 113) return 'Linux cooked capture (SLL)';
        if (linkType === 276) return 'Linux cooked capture v2 (SLL2)';
        if (linkType === 0) return 'Null / loopback';
        return linkType == null ? '—' : 'Link type ' + linkType;
    }

    function protoLabel(key) {
        return PROTO_LABELS[key] || key.toUpperCase();
    }

    function buildConversations(viewer, protoFilter) {
        var map = {};
        var list = [];
        for (var i = 0; i < viewer.packets.length; i++) {
            var p = viewer.packets[i];
            if (protoFilter && protoFilter !== 'all' && p.transport !== protoFilter) continue;
            if (!p.dec.src && !p.dec.dst) continue;
            var key = conversationKey(p);
            if (!map[key]) {
                map[key] = {
                    proto: p.transport || p.dec.proto.toLowerCase(),
                    a: p.dec.src || '—', ap: p.srcport === '' ? '—' : p.srcport,
                    b: p.dec.dst || '—', bp: p.dstport === '' ? '—' : p.dstport,
                    packets: 0, bytes: 0, first: null, last: null, indices: []
                };
                list.push(map[key]);
            }
            var c = map[key];
            c.packets++;
            c.bytes += p.len;
            c.indices.push(i);
            if (p.time != null) {
                if (c.first == null || p.time < c.first) c.first = p.time;
                if (c.last == null || p.time > c.last) c.last = p.time;
            }
        }
        list.sort(function (x, y) { return y.packets - x.packets; });
        return list;
    }

    function showConversations(viewer) {
        showModal(viewer, 'Conversations',
            '<div class="pcap-dialog-toolbar">' +
                '<label class="pcap-dim">Protocol</label>' +
                '<select class="pcap-select" data-conv-proto>' +
                    '<option value="all">All</option>' +
                    '<option value="tcp">TCP</option>' +
                    '<option value="udp">UDP</option>' +
                    '<option value="icmp">ICMP</option>' +
                    '<option value="icmpv6">ICMPv6</option>' +
                '</select>' +
                '<span class="pcap-spacer"></span>' +
                '<span class="pcap-dim" data-conv-count></span>' +
            '</div>' +
            '<div data-conv-body></div>', { wide: true });
        var body = modalBody(viewer);
        var sel = body.querySelector('[data-conv-proto]');
        var target = body.querySelector('[data-conv-body]');
        var count = body.querySelector('[data-conv-count]');

        function render() {
            var list = buildConversations(viewer, sel.value);
            var rows = [];
            for (var i = 0; i < list.length; i++) {
                var c = list[i];
                var dur = c.first != null && c.last != null ? Math.max(0, c.last - c.first) : 0;
                var rate = dur > 0 ? (c.bytes * 8 / dur) : 0;
                rows.push('<tr data-packet="' + c.indices[0] + '">' +
                    '<td>' + esc(c.proto.toUpperCase()) + '</td>' +
                    '<td>' + esc(c.a) + '</td><td class="num">' + esc(c.ap) + '</td>' +
                    '<td>' + esc(c.b) + '</td><td class="num">' + esc(c.bp) + '</td>' +
                    '<td class="num">' + c.packets + '</td>' +
                    '<td class="num">' + fmtBytes(c.bytes) + '</td>' +
                    '<td class="num">' + fmtDuration(dur) + '</td>' +
                    '<td class="num">' + (rate ? fmtBits(rate) : '—') + '</td>' +
                '</tr>');
            }
            target.innerHTML = tableHtml(
                ['Protocol', 'Address A', 'Port A', 'Address B', 'Port B', 'Packets', 'Bytes', 'Duration', 'Bits/s'],
                rows.length ? rows : ['<tr><td colspan="9" class="pcap-dim">No conversations.</td></tr>']);
            count.textContent = plural(list.length, 'conversation');
        }
        sel.addEventListener('change', render);
        render();
    }

    function fmtBits(bits) {
        if (bits >= 1e9) return (bits / 1e9).toFixed(2) + ' Gbit/s';
        if (bits >= 1e6) return (bits / 1e6).toFixed(2) + ' Mbit/s';
        if (bits >= 1e3) return (bits / 1e3).toFixed(2) + ' kbit/s';
        return Math.round(bits) + ' bit/s';
    }

    function showEndpoints(viewer) {
        showModal(viewer, 'Endpoints',
            '<div class="pcap-dialog-toolbar">' +
                '<label class="pcap-dim">Show</label>' +
                '<select class="pcap-select" data-ep-proto>' +
                    '<option value="all">All endpoints</option>' +
                    '<option value="tcp">TCP</option>' +
                    '<option value="udp">UDP</option>' +
                '</select>' +
                '<span class="pcap-spacer"></span>' +
                '<span class="pcap-dim" data-ep-count></span>' +
            '</div><div data-ep-body></div>', { wide: true });
        var body = modalBody(viewer);
        var sel = body.querySelector('[data-ep-proto]');
        var target = body.querySelector('[data-ep-body]');
        var count = body.querySelector('[data-ep-count]');

        function render() {
            var map = {};
            var list = [];
            for (var i = 0; i < viewer.packets.length; i++) {
                var p = viewer.packets[i];
                if (sel.value !== 'all' && p.transport !== sel.value) continue;
                var addrs = [];
                if (p.dec.src) addrs.push({ addr: p.dec.src, port: p.srcport, dir: 'tx' });
                if (p.dec.dst) addrs.push({ addr: p.dec.dst, port: p.dstport, dir: 'rx' });
                for (var a = 0; a < addrs.length; a++) {
                    var item = addrs[a];
                    var key = item.addr + (item.port !== '' ? ':' + item.port : '');
                    if (!map[key]) {
                        map[key] = { addr: item.addr, port: item.port, packets: 0, txPackets: 0, txBytes: 0, bytes: 0, first: null, last: null, indices: [] };
                        list.push(map[key]);
                    }
                    var e = map[key];
                    e.packets++;
                    e.bytes += p.len;
                    e.indices.push(i);
                    if (item.dir === 'tx') { e.txPackets++; e.txBytes += p.len; }
                    if (p.time != null) {
                        if (e.first == null || p.time < e.first) e.first = p.time;
                        if (e.last == null || p.time > e.last) e.last = p.time;
                    }
                }
            }
            list.sort(function (x, y) { return y.packets - x.packets; });
            var rows = [];
            for (var r = 0; r < list.length; r++) {
                var ep = list[r];
                rows.push('<tr data-packet="' + ep.indices[0] + '">' +
                    '<td>' + esc(ep.addr) + '</td>' +
                    '<td class="num">' + esc(ep.port === '' ? '—' : ep.port) + '</td>' +
                    '<td class="num">' + ep.packets + '</td>' +
                    '<td class="num">' + fmtBytes(ep.bytes) + '</td>' +
                    '<td class="num">' + ep.txPackets + '</td>' +
                    '<td class="num">' + fmtBytes(ep.txBytes) + '</td>' +
                '</tr>');
            }
            target.innerHTML = tableHtml(
                ['Address', 'Port', 'Packets', 'Bytes', 'Tx Packets', 'Tx Bytes'],
                rows.length ? rows : ['<tr><td colspan="6" class="pcap-dim">No endpoints.</td></tr>']);
            count.textContent = plural(list.length, 'endpoint');
        }
        sel.addEventListener('change', render);
        render();
    }

    function showProtocolHierarchy(viewer) {
        var stats = {};
        var order = [];
        var total = viewer.packets.length;

        function bump(key, depth, p) {
            if (!stats[key]) {
                stats[key] = { key: key, depth: depth, packets: 0, bytes: 0, children: [] };
                order.push(stats[key]);
            }
            stats[key].packets++;
            stats[key].bytes += p.len;
            return stats[key];
        }

        for (var i = 0; i < total; i++) {
            var p = viewer.packets[i];
            var chain = p.dec.chain.slice();
            if (!chain.length) chain = ['data'];
            var parent = null;
            for (var c = 0; c < chain.length; c++) {
                var key = chain[c];
                var node = bump(key, c, p);
                if (parent && parent.children.indexOf(node) === -1) parent.children.push(node);
                parent = node;
            }
        }

        order.sort(function (a, b) {
            if (a.depth !== b.depth) return a.depth - b.depth;
            return b.packets - a.packets;
        });

        var rows = [];
        for (var r = 0; r < order.length; r++) {
            var node = order[r];
            var indent = '';
            for (var d = 0; d < node.depth; d++) indent += '<span class="pcap-tree-indent"></span>';
            rows.push('<tr>' +
                '<td>' + indent + esc(protoLabel(node.key)) + '</td>' +
                '<td class="num">' + (total ? (node.packets / total * 100).toFixed(1) : '0.0') + '%</td>' +
                '<td class="num">' + node.packets + '</td>' +
                '<td class="num">' + fmtBytes(node.bytes) + '</td>' +
            '</tr>');
        }
        showModal(viewer, 'Protocol Hierarchy',
            tableHtml(['Protocol', '% Packets', 'Packets', 'Bytes'], rows, ' data-proto-table') +
            '<p class="pcap-dim">' + plural(total, 'packet') + ' analysed. Layers are counted once per packet.</p>',
            { wide: true });
    }

    function showExpertInfo(viewer) {
        var rules = [
            { severity: 'warn', name: 'Connection reset (RST)', test: function (p) { return p.fields['tcp.flags.rst']; } },
            { severity: 'warn', name: 'TCP zero window', test: function (p) { return p.transport === 'tcp' && p.fields['tcp.window'] === 0; } },
            { severity: 'warn', name: 'ICMP destination unreachable', test: function (p) { return p.fields['icmp.type'] === 3; } },
            { severity: 'warn', name: 'ICMPv6 destination unreachable', test: function (p) { return p.fields['icmpv6.type'] === 1; } },
            { severity: 'note', name: 'Connection attempt (SYN)', test: function (p) { return p.fields['tcp.flags.syn'] === 1 && p.fields['tcp.flags.ack'] === 0; } },
            { severity: 'note', name: 'ICMP echo (ping)', test: function (p) { return p.fields['icmp.type'] === 8 || p.fields['icmp.type'] === 0 || p.fields['icmpv6.type'] === 128 || p.fields['icmpv6.type'] === 129; } },
            { severity: 'note', name: 'TLS alert', test: function (p) { return p.fields['tls.alert.severity'] !== undefined; } },
            { severity: 'chat', name: 'TCP connection finish (FIN)', test: function (p) { return p.fields['tcp.flags.fin'] === 1; } },
            { severity: 'chat', name: 'HTTP request/response', test: function (p) { return !!p.protocols.http; } },
            { severity: 'chat', name: 'DNS query/response', test: function (p) { return !!p.protocols.dns; } },
            { severity: 'chat', name: 'ARP request/reply', test: function (p) { return !!p.protocols.arp; } }
        ];
        var meta = {
            error: { label: 'Error', cls: 'error' },
            warn: { label: 'Warning', cls: 'warn' },
            note: { label: 'Note', cls: 'note' },
            chat: { label: 'Chat', cls: 'chat' }
        };
        var groups = { error: [], warn: [], note: [], chat: [] };
        for (var r = 0; r < rules.length; r++) {
            var rule = rules[r];
            var hits = [];
            for (var i = 0; i < viewer.packets.length; i++) {
                try { if (rule.test(viewer.packets[i])) hits.push(i); } catch (e) { }
            }
            if (hits.length) groups[rule.severity].push({ rule: rule, hits: hits });
        }
        var rows = [];
        ['error', 'warn', 'note', 'chat'].forEach(function (sev) {
            var list = groups[sev];
            if (!list.length) return;
            rows.push('<tr class="pcap-expert-group"><td colspan="3">' + esc(meta[sev].label + ' (' + list.length + ')') + '</td></tr>');
            for (var i = 0; i < list.length; i++) {
                var entry = list[i];
                rows.push('<tr data-packet="' + entry.hits[0] + '" class="pcap-expert-' + meta[sev].cls + '">' +
                    '<td>' + esc(entry.rule.name) + '</td>' +
                    '<td class="num">' + entry.hits.length + '</td>' +
                    '<td>' + packetNoList(viewer, entry.hits) + '</td>' +
                '</tr>');
            }
        });
        if (!rows.length) {
            rows.push('<tr><td colspan="3" class="pcap-dim">No notable events were detected in this capture.</td></tr>');
        }
        showModal(viewer, 'Expert Information',
            tableHtml(['Severity / Message', 'Count', 'Packets'], rows, ' data-expert-table') +
            '<p class="pcap-dim">Click a row to jump to the first matching packet.</p>', { wide: true });
    }

    function packetNoList(viewer, indices) {
        var parts = [];
        var max = Math.min(indices.length, 12);
        for (var i = 0; i < max; i++) parts.push('#' + viewer.packets[indices[i]].no);
        if (indices.length > max) parts.push('… +' + (indices.length - max));
        return esc(parts.join(', '));
    }

    var IO_COLORS = ['#e8a33d', '#5fd35f', '#4a9eff', '#e8776b', '#b98bff', '#3ec9c9', '#f06fb0', '#c7c14a'];

    function showIOGraph(viewer) {
        showModal(viewer, 'IO Graph',
            '<div class="pcap-dialog-toolbar">' +
                '<label class="pcap-dim">Interval</label>' +
                '<select class="pcap-select" data-io-interval>' +
                    '<option value="0.01">0.01 s</option>' +
                    '<option value="0.1">0.1 s</option>' +
                    '<option value="1" selected>1 s</option>' +
                    '<option value="10">10 s</option>' +
                    '<option value="60">60 s</option>' +
                '</select>' +
                '<label class="pcap-dim">Y axis</label>' +
                '<select class="pcap-select" data-io-y>' +
                    '<option value="packets">Packets</option>' +
                    '<option value="bytes">Bytes</option>' +
                '</select>' +
                '<span class="pcap-spacer"></span>' +
                '<button type="button" class="pcap-btn" data-io-add>Add series</button>' +
            '</div>' +
            '<div class="pcap-io-series" data-io-series></div>' +
            '<div class="pcap-io-note pcap-dim" data-io-note></div>' +
            '<div class="pcap-io-canvas-wrap"><canvas class="pcap-io-canvas" data-io-canvas></canvas></div>', { wide: true });

        var body = modalBody(viewer);
        var seriesEl = body.querySelector('[data-io-series]');
        var canvas = body.querySelector('[data-io-canvas]');
        var noteEl = body.querySelector('[data-io-note]');
        var intervalSel = body.querySelector('[data-io-interval]');
        var ySel = body.querySelector('[data-io-y]');
        var series = [];
        var nextId = 1;
        var stats = captureStats(viewer);
        var t0 = stats.first != null ? stats.first : 0;

        function addSeries(filter) {
            var s = {
                id: nextId++,
                filter: filter || '',
                color: IO_COLORS[series.length % IO_COLORS.length],
                enabled: true
            };
            series.push(s);
            renderSeries();
        }

        function renderSeries() {
            var html = '';
            for (var i = 0; i < series.length; i++) {
                var s = series[i];
                html += '<div class="pcap-io-row" data-io-row="' + s.id + '">' +
                    '<input type="checkbox" data-io-enabled' + (s.enabled ? ' checked' : '') + ' title="Enable series">' +
                    '<span class="pcap-io-swatch" style="background:' + s.color + '"></span>' +
                    '<input class="pcap-input mono" data-io-filter spellcheck="false" value="' + esc(s.filter) + '" ' +
                        'placeholder="Display filter — empty = all packets">' +
                    '<button type="button" class="pcap-btn" data-io-remove title="Remove series">✕</button>' +
                '</div>';
            }
            seriesEl.innerHTML = html;
        }

        function seriesById(id) {
            for (var i = 0; i < series.length; i++) if (String(series[i].id) === String(id)) return series[i];
            return null;
        }

        function draw() {
            var interval = parseFloat(intervalSel.value) || 1;
            var yField = ySel.value;
            var buckets = [];
            var maxY = 0;
            var errors = [];

            for (var s = 0; s < series.length; s++) {
                var ser = series[s];
                if (!ser.enabled) continue;
                var ast = null;
                var invalid = false;
                if (ser.filter.trim()) {
                    try { ast = parseFilter(ser.filter.trim()); } catch (e) { invalid = true; ser.error = e.message || String(e); }
                }
                if (!invalid) ser.error = null;
                if (ser.error) errors.push(ser.filter + ': ' + ser.error);
                var values = [];
                for (var i = 0; i < viewer.packets.length; i++) {
                    var p = viewer.packets[i];
                    if (invalid) break;
                    if (ast && !evalFilter(ast, p)) continue;
                    var t = p.time != null ? p.time - t0 : p.rel;
                    var idx = Math.floor(t / interval);
                    if (idx < 0) idx = 0;
                    values[idx] = (values[idx] || 0) + (yField === 'bytes' ? p.len : 1);
                    if (values[idx] > maxY) maxY = values[idx];
                }
                ser.values = values;
            }

            if (noteEl) {
                noteEl.textContent = errors.length ? 'Invalid series filter — ' + errors.join(' · ') : '';
                noteEl.classList.toggle('pcap-status-error', errors.length > 0);
            }

            var dpr = window.devicePixelRatio || 1;
            var width = Math.max(320, canvas.parentElement.clientWidth);
            var height = Math.max(220, Math.min(420, Math.round(window.innerHeight * 0.36)));
            canvas.width = Math.round(width * dpr);
            canvas.height = Math.round(height * dpr);
            canvas.style.width = width + 'px';
            canvas.style.height = height + 'px';

            var ctx = canvas.getContext('2d');
            if (!ctx) return;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.clearRect(0, 0, width, height);

            var pad = { left: 58, right: 14, top: 16, bottom: 26 };
            var plotW = width - pad.left - pad.right;
            var plotH = height - pad.top - pad.bottom;
            var maxLen = 0;
            for (var b = 0; b < series.length; b++) {
                if (series[b].values && series[b].values.length > maxLen) maxLen = series[b].values.length;
            }
            var count = Math.max(1, maxLen);
            var maxValue = Math.max(1, maxY);
            var mag = Math.pow(10, Math.floor(Math.log(maxValue) / Math.LN10));
            var nice = [1, 2, 2.5, 5, 10].map(function (m) { return m * mag; });
            for (var n = 0; n < nice.length; n++) {
                if (nice[n] >= maxValue) { maxValue = nice[n]; break; }
            }

            ctx.strokeStyle = '#232323';
            ctx.fillStyle = '#6f6f6f';
            ctx.font = '10px monospace';
            ctx.lineWidth = 1;
            for (var g = 0; g <= 4; g++) {
                var y = pad.top + plotH * (g / 4);
                ctx.beginPath();
                ctx.moveTo(pad.left, y);
                ctx.lineTo(pad.left + plotW, y);
                ctx.stroke();
                var label = Math.round(maxValue * (1 - g / 4));
                ctx.fillText(String(label), 8, y + 3);
            }
            ctx.strokeStyle = '#333333';
            ctx.beginPath();
            ctx.moveTo(pad.left, pad.top);
            ctx.lineTo(pad.left, pad.top + plotH);
            ctx.lineTo(pad.left + plotW, pad.top + plotH);
            ctx.stroke();

            var xTicks = Math.min(6, count);
            ctx.fillStyle = '#6f6f6f';
            for (var x = 0; x <= xTicks; x++) {
                var px = pad.left + plotW * (x / xTicks);
                var tsec = (x / xTicks) * count * interval;
                ctx.fillText(tsec.toFixed(tsec < 10 ? 2 : 0) + 's', Math.min(px, width - pad.right - 26), height - 8);
            }

            for (var s2 = 0; s2 < series.length; s2++) {
                var ser2 = series[s2];
                if (!ser2.enabled || !ser2.values) continue;
                var vals = ser2.values;
                ctx.strokeStyle = ser2.color;
                ctx.fillStyle = ser2.color;
                ctx.lineWidth = 1.6;
                ctx.beginPath();
                for (var v = 0; v < vals.length; v++) {
                    var vx = pad.left + (vals.length === 1 ? plotW / 2 : plotW * (v / Math.max(1, count - 1)));
                    var vy = pad.top + plotH - (vals[v] || 0) / maxValue * plotH;
                    if (v === 0) ctx.moveTo(vx, vy);
                    else ctx.lineTo(vx, vy);
                }
                ctx.stroke();

                var lx = pad.left + 6;
                var ly = pad.top + 4 + s2 * 13;
                ctx.fillRect(lx, ly - 6, 8, 8);
                ctx.fillStyle = '#c8c8c8';
                ctx.font = '10px monospace';
                var label2 = (ser2.filter || 'All packets');
                ctx.fillText(label2.length > 48 ? label2.slice(0, 47) + '…' : label2, lx + 13, ly + 1);
            }
        }

        seriesEl.addEventListener('change', function (e) {
            var row = e.target.closest('[data-io-row]');
            if (!row) return;
            var item = seriesById(row.getAttribute('data-io-row'));
            if (!item) return;
            if (e.target.hasAttribute('data-io-enabled')) { item.enabled = e.target.checked; draw(); }
            if (e.target.hasAttribute('data-io-filter')) { item.filter = e.target.value; draw(); }
        });
        seriesEl.addEventListener('input', function (e) {
            var row = e.target.closest('[data-io-row]');
            if (!row || !e.target.hasAttribute('data-io-filter')) return;
            var item = seriesById(row.getAttribute('data-io-row'));
            if (item) { item.filter = e.target.value; draw(); }
        });
        seriesEl.addEventListener('click', function (e) {
            var rm = e.target.closest('[data-io-remove]');
            if (!rm) return;
            var row = rm.closest('[data-io-row]');
            var id = row.getAttribute('data-io-row');
            series = series.filter(function (s) { return String(s.id) !== String(id); });
            renderSeries();
            draw();
        });
        body.querySelector('[data-io-add]').addEventListener('click', function () {
            addSeries('');
            draw();
        });
        intervalSel.addEventListener('change', draw);
        ySel.addEventListener('change', draw);
        addSeries('');
        setTimeout(draw, 30);
    }

    function showHTTPObjects(viewer) {
        var rows = [];
        var objects = [];
        for (var i = 0; i < viewer.packets.length; i++) {
            var p = viewer.packets[i];
            var f = p.fields;
            if (f['http.request.method'] !== undefined) {
                objects.push({
                    index: i,
                    kind: 'Request',
                    host: f['http.host'] || '',
                    detail: f['http.request.method'] + ' ' + (f['http.request.uri'] || '/'),
                    type: f['http.content_type'] || '',
                    size: f['http.content_length'] || '',
                    url: (f['http.host'] ? 'http://' + f['http.host'] : '') + (f['http.request.uri'] || '')
                });
            } else if (f['http.response.code'] !== undefined) {
                objects.push({
                    index: i,
                    kind: 'Response',
                    host: f['http.host'] || '',
                    detail: f['http.response.code'] + ' ' + (f['http.response.phrase'] || ''),
                    type: f['http.content_type'] || '',
                    size: f['http.content_length'] || '',
                    url: ''
                });
            }
        }
        for (var o = 0; o < objects.length; o++) {
            var obj = objects[o];
            rows.push('<tr data-packet="' + obj.index + '">' +
                '<td>' + esc(obj.kind) + '</td>' +
                '<td>' + esc(obj.host) + '</td>' +
                '<td class="pcap-ellipsis">' + esc(obj.detail) + '</td>' +
                '<td>' + esc(obj.type) + '</td>' +
                '<td class="num">' + esc(obj.size) + '</td>' +
            '</tr>');
        }
        if (!rows.length) rows.push('<tr><td colspan="5" class="pcap-dim">No HTTP objects were found in this capture.</td></tr>');
        showModal(viewer, 'HTTP Objects',
            '<p class="pcap-dim">The capture file already lives on this host, so objects are not downloaded again. ' +
                'Click a row to inspect the packet.</p>' +
            tableHtml(['Type', 'Host', 'Request / Response', 'Content Type', 'Length'], rows, ' data-http-table'),
            { wide: true });
    }

    function openColoringRules(viewer) {
        showModal(viewer, 'Coloring Rules',
            '<p class="pcap-dim">The first matching rule wins. Rules are stored in this browser.</p>' +
            '<div class="pcap-color-head">' +
                '<span>On</span><span>Name</span><span>Filter</span><span>Text</span><span>Background</span><span></span>' +
            '</div>' +
            '<div class="pcap-color-list" data-color-list></div>' +
            '<div class="pcap-dialog-actions">' +
                '<button type="button" class="pcap-btn" data-color-add>Add Rule</button>' +
                '<button type="button" class="pcap-btn" data-color-reset>Reset Defaults</button>' +
                '<span class="pcap-spacer"></span>' +
                '<button type="button" class="pcap-btn primary" data-color-done>Done</button>' +
            '</div>', { wide: true });

        var body = modalBody(viewer);
        var listEl = body.querySelector('[data-color-list]');

        function render() {
            var html = '';
            for (var i = 0; i < viewer.colorRules.length; i++) {
                var r = viewer.colorRules[i];
                html += '<div class="pcap-color-row" data-color-row="' + i + '">' +
                    '<input type="checkbox" data-color-enabled' + (r.enabled ? ' checked' : '') + ' title="Enable rule">' +
                    '<input class="pcap-input" data-color-name value="' + esc(r.name) + '" aria-label="Rule name">' +
                    '<input class="pcap-input mono" data-color-filter spellcheck="false" value="' + esc(r.filter) + '" aria-label="Display filter">' +
                    '<input type="color" data-color-fg value="' + esc(r.fg) + '" title="Text colour">' +
                    '<input type="color" data-color-bg value="' + esc(r.bg) + '" title="Background colour">' +
                    '<button type="button" class="pcap-btn" data-color-remove title="Delete rule">✕</button>' +
                '</div>';
            }
            listEl.innerHTML = html;
        }

        function commit() {
            writeStore(STORE_COLORS, viewer.colorRules);
            computeRowColors(viewer);
            renderRows(viewer);
        }

        listEl.addEventListener('input', function (e) {
            var row = e.target.closest('[data-color-row]');
            if (!row) return;
            var rule = viewer.colorRules[parseInt(row.getAttribute('data-color-row'), 10)];
            if (!rule) return;
            if (e.target.hasAttribute('data-color-name')) rule.name = e.target.value;
            else if (e.target.hasAttribute('data-color-filter')) rule.filter = e.target.value;
            else if (e.target.hasAttribute('data-color-fg')) rule.fg = e.target.value;
            else if (e.target.hasAttribute('data-color-bg')) rule.bg = e.target.value;
            commit();
        });
        listEl.addEventListener('change', function (e) {
            var row = e.target.closest('[data-color-row]');
            if (!row) return;
            var idx = parseInt(row.getAttribute('data-color-row'), 10);
            var rule = viewer.colorRules[idx];
            if (!rule) return;
            if (e.target.hasAttribute('data-color-enabled')) rule.enabled = e.target.checked;
            commit();
        });
        listEl.addEventListener('click', function (e) {
            var rm = e.target.closest('[data-color-remove]');
            if (!rm) return;
            var row = rm.closest('[data-color-row]');
            viewer.colorRules.splice(parseInt(row.getAttribute('data-color-row'), 10), 1);
            render();
            commit();
        });
        body.querySelector('[data-color-add]').addEventListener('click', function () {
            var id = 1;
            for (var i = 0; i < viewer.colorRules.length; i++) id = Math.max(id, viewer.colorRules[i].id + 1);
            viewer.colorRules.push({ id: id, name: 'New rule', filter: '', fg: '#ffffff', bg: '#333333', enabled: true });
            render();
            commit();
        });
        body.querySelector('[data-color-reset]').addEventListener('click', function () {
            viewer.colorRules = DEFAULT_COLOR_RULES.map(function (r) {
                return { id: r.id, name: r.name, filter: r.filter, fg: r.fg, bg: r.bg, enabled: r.enabled };
            });
            render();
            commit();
        });
        body.querySelector('[data-color-done]').addEventListener('click', function () { closeDialog(viewer); });
        render();
    }

    function openColumnsDialog(viewer) {
        showModal(viewer, 'Column Preferences',
            '<p class="pcap-dim">Choose visible columns, their order, and add custom columns from any display filter field.</p>' +
            '<div class="pcap-col-head"><span>Show</span><span>Column</span><span>Field / label</span><span>Width</span><span></span></div>' +
            '<div class="pcap-column-list" data-col-list></div>' +
            '<div class="pcap-dialog-toolbar">' +
                '<input class="pcap-input mono" data-col-field placeholder="Field, e.g. tcp.window" aria-label="Custom column field">' +
                '<input class="pcap-input" data-col-label placeholder="Label (optional)" aria-label="Custom column label">' +
                '<button type="button" class="pcap-btn" data-col-add>Add Column</button>' +
                '<span class="pcap-spacer"></span>' +
                '<button type="button" class="pcap-btn primary" data-col-done>Done</button>' +
            '</div>', { wide: true });

        var body = modalBody(viewer);
        var listEl = body.querySelector('[data-col-list]');

        function render() {
            var html = '';
            for (var i = 0; i < viewer.columns.length; i++) {
                var c = viewer.columns[i];
                var custom = c.key.indexOf('custom:') === 0;
                var field = custom ? (c.abbrev || c.key.slice(7)) : c.key;
                html += '<div class="pcap-col-row" data-col-row="' + i + '">' +
                    '<input type="checkbox" data-col-visible' + (c.visible !== false ? ' checked' : '') + ' title="Show column">' +
                    '<span class="pcap-col-name">' + esc(columnLabel(c)) + '</span>' +
                    '<input class="pcap-input mono" data-col-field value="' + esc(field) + '" ' + (custom ? '' : 'readonly') + '>' +
                    '<input class="pcap-input num" data-col-width type="number" min="40" max="600" value="' + columnWidth(c) + '">' +
                    '<span class="pcap-col-buttons">' +
                        '<button type="button" class="pcap-btn icon" data-col-up title="Move up"' + (i === 0 ? ' disabled' : '') + '>↑</button>' +
                        '<button type="button" class="pcap-btn icon" data-col-down title="Move down"' + (i === viewer.columns.length - 1 ? ' disabled' : '') + '>↓</button>' +
                        '<button type="button" class="pcap-btn icon" data-col-remove title="Remove column"' + (custom ? '' : ' disabled') + '>✕</button>' +
                    '</span>' +
                '</div>';
            }
            listEl.innerHTML = html;
        }

        function commit() {
            writeStore(STORE_COLS, viewer.columns);
            computeRowColors(viewer);
            renderTableHead(viewer);
            renderRows(viewer);
        }

        listEl.addEventListener('change', function (e) {
            var row = e.target.closest('[data-col-row]');
            if (!row) return;
            var idx = parseInt(row.getAttribute('data-col-row'), 10);
            var col = viewer.columns[idx];
            if (!col) return;
            if (e.target.hasAttribute('data-col-visible')) col.visible = e.target.checked;
            else if (e.target.hasAttribute('data-col-width')) {
                var w = parseInt(e.target.value, 10);
                if (isFinite(w)) col.width = Math.max(40, Math.min(600, w));
            } else if (e.target.hasAttribute('data-col-field') && col.key.indexOf('custom:') === 0) {
                var newField = e.target.value.trim();
                if (!newField) { e.target.value = col.abbrev || ''; return; }
                col.abbrev = newField;
                col.key = 'custom:' + newField;
            } else return;
            commit();
            render();
        });
        listEl.addEventListener('click', function (e) {
            var row = e.target.closest('[data-col-row]');
            if (!row) return;
            var idx = parseInt(row.getAttribute('data-col-row'), 10);
            if (e.target.closest('[data-col-up]') && idx > 0) {
                var moved = viewer.columns.splice(idx, 1)[0];
                viewer.columns.splice(idx - 1, 0, moved);
            } else if (e.target.closest('[data-col-down]') && idx < viewer.columns.length - 1) {
                var moved2 = viewer.columns.splice(idx, 1)[0];
                viewer.columns.splice(idx + 1, 0, moved2);
            } else if (e.target.closest('[data-col-remove]') && viewer.columns[idx].key.indexOf('custom:') === 0) {
                viewer.columns.splice(idx, 1);
            } else return;
            commit();
            render();
        });
        body.querySelector('[data-col-add]').addEventListener('click', function () {
            var field = body.querySelector('[data-col-field]').value.trim();
            if (!field) return;
            var label = body.querySelector('[data-col-label]').value.trim();
            var customKey = 'custom:' + field;
            for (var ci = 0; ci < viewer.columns.length; ci++) {
                if (viewer.columns[ci].key === customKey) {
                    viewer.columns[ci].visible = true;
                    body.querySelector('[data-col-field]').value = '';
                    body.querySelector('[data-col-label]').value = '';
                    commit();
                    render();
                    return;
                }
            }
            viewer.columns.push({
                key: customKey,
                visible: true,
                width: 120,
                abbrev: field,
                label: label || field
            });
            body.querySelector('[data-col-field]').value = '';
            body.querySelector('[data-col-label]').value = '';
            commit();
            render();
        });
        body.querySelector('[data-col-done]').addEventListener('click', function () { closeDialog(viewer); });
        render();
    }

    function showShortcuts(viewer) {
        var rows = [
            ['Ctrl+F', 'Find packet'],
            ['Ctrl+N / Ctrl+Shift+N', 'Find next / previous'],
            ['Ctrl+G', 'Go to packet'],
            ['Ctrl+M', 'Mark or unmark selected packet'],
            ['Ctrl+Alt+C', 'Edit packet comment'],
            ['Ctrl+Alt+Shift+T', 'Follow TCP stream'],
            ['Ctrl+/', 'Focus display filter'],
            ['Ctrl+= / Ctrl+- / Ctrl+0', 'Zoom in / out / reset'],
            ['Ctrl+R', 'Reload capture'],
            ['F1', 'Display filter help'],
            ['Home / End', 'First / last packet'],
            ['↑ / ↓', 'Previous / next packet'],
            ['Esc', 'Close dialog, menu or viewer']
        ];
        var markup = '';
        for (var i = 0; i < rows.length; i++) {
            markup += '<tr><td class="mono">' + esc(rows[i][0]) + '</td><td>' + esc(rows[i][1]) + '</td></tr>';
        }
        showModal(viewer, 'Keyboard Shortcuts',
            tableHtml(['Shortcut', 'Action'], markup, ' data-shortcut-table'));
    }

    function showAbout(viewer) {
        showModal(viewer, 'About Browser Wireshark',
            '<p><strong>Browser Wireshark</strong> is a standalone packet analyzer that runs entirely in ' +
                'this browser tab — capture files are read locally and never uploaded anywhere.</p>' +
            '<p class="pcap-dim">It reads classic pcap and pcapng files (both byte orders) and dissects ' +
                'Ethernet, Linux cooked capture, raw IP, VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMP, HTTP, DNS, ' +
                'TLS, SSH and NTP.</p>' +
            '<p class="pcap-dim">Display filters follow Wireshark syntax: protocol names, field comparisons, ' +
                'CIDR matches, quoted strings, boolean operators, parentheses, <code>contains</code> and ' +
                '<code>matches</code>. Invalid expressions keep the last result set and show an error.</p>' +
            '<p class="pcap-dim">Keyboard shortcuts are available under Help ▸ Keyboard Shortcuts. ' +
                'Filters, columns, time format and coloring rules are remembered in this browser.</p>');
    }

    function hexDump(bytes) {
        var count = Math.min(bytes.length, MAX_HEX_BYTES);
        var lines = ['Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII'];
        for (var i = 0; i < count; i += 16) {
            var hexPart = '';
            var ascii = '';
            for (var j = 0; j < 16; j++) {
                if (i + j < count) {
                    var value = bytes[i + j];
                    hexPart += HEX[value] + ' ';
                    ascii += (value >= 0x20 && value <= 0x7e) ? String.fromCharCode(value) : '.';
                } else {
                    hexPart += '   ';
                    ascii += ' ';
                }
                if (j === 7) hexPart += ' ';
            }
            lines.push(hex(i, 8) + '  ' + hexPart + '  ' + ascii);
        }
        if (bytes.length > count) {
            lines.push('… ' + (bytes.length - count) + ' more bytes not shown');
        }
        return lines.join('\n');
    }

    function readCaptureSource(source) {
        if (typeof source === 'string') {
            return fetch(source, { credentials: 'same-origin' }).then(function (resp) {
                if (!resp.ok) throw new Error('HTTP ' + resp.status + ' ' + resp.statusText);
                return resp.arrayBuffer();
            });
        }
        if (typeof Blob !== 'undefined' && source instanceof Blob) {
            if (typeof source.arrayBuffer === 'function') return source.arrayBuffer();
            return new Promise(function (resolve, reject) {
                var reader = new FileReader();
                reader.onload = function () { resolve(reader.result); };
                reader.onerror = function () { reject(reader.error || new Error('Could not read the selected file.')); };
                reader.readAsArrayBuffer(source);
            });
        }
        return Promise.reject(new Error('No capture file was provided.'));
    }

    function loadCapture(viewer, source) {
        if (source === undefined) source = viewer.source;
        viewer.source = source;
        if (source && source.name) {
            viewer.name = source.name;
            viewer.els.fname.textContent = source.name;
        }
        viewer.url = typeof source === 'string' ? source : null;
        viewer.blob = (typeof Blob !== 'undefined' && source instanceof Blob) ? source : null;

        showListMessage(viewer, 'Loading capture…', false);
        setStatus(viewer, 'Loading capture…');
        viewer.els.tbody.parentElement.parentElement.scrollTop = 0;

        readCaptureSource(source)
            .then(function (buffer) {
                if (buffer.byteLength > MAX_BYTES) {
                    throw new Error('Capture is too large (' + fmtBytes(buffer.byteLength) +
                        '). Limit is ' + fmtBytes(MAX_BYTES) + '.');
                }
                var cap = parseCapture(buffer);
                if (!cap) {
                    var head = new Uint8Array(buffer, 0, Math.min(4, buffer.byteLength));
                    var magic = Array.prototype.map.call(head, function (x) { return HEX[x]; }).join('');
                    throw new Error('Unsupported capture format (magic 0x' + magic + ').');
                }
                if (!cap.packets.length) {
                    throw new Error('No packets found in this capture.');
                }

                setTimeout(function () {
                    var packets = decodeAll(cap);
                    viewer.packets = packets;
                    viewer.view = packets.map(function (_, i) { return i; });
                    viewer.truncated = cap.truncated;
                    viewer.format = cap.format;
                    viewer.fileSize = buffer.byteLength;
                    viewer.linkType = packets.length ? packets[0].linkType : (cap.linkType != null ? cap.linkType : null);
                    viewer.selected = -1;
                    viewer.marked.clear();
                    viewer.comments = {};
                    viewer.findStatus = '';
                    viewer.els.stats.textContent = packets.length + ' packets · ' + fmtBytes(buffer.byteLength);
                    viewer.view = packets.map(function (_, i) { return i; });
                    computeRowColors(viewer);
                    applyFilter(viewer);
                    if (viewer.view.length) selectPacket(viewer, viewer.view[0]);
                    else viewer.els.tree.innerHTML = '<div class="pcap-hint">Select a packet to inspect its layers.</div>';
                    academyEmit('capture', {
                        name: viewer.name,
                        format: cap.format,
                        packetCount: packets.length,
                        bytes: buffer.byteLength,
                        packets: packets.map(packetSnapshot)
                    });
                }, 30);
            })
            .catch(function (err) {
                showListMessage(viewer, 'Could not open capture: ' + (err && err.message ? err.message : err), true);
                setStatus(viewer, 'Failed to load capture');
                viewer.els.stats.textContent = '—';
            });
    }

    function openPcapViewer(source, name) {
        closeViewer();
        var viewer = buildViewer(source, name);
        activeViewer = viewer;
        document.body.appendChild(viewer.overlay);
        document.body.classList.add('pcap-open');

        var savedZoom = 1;
        try {
            var rawZoom = parseFloat(localStorage.getItem('bw-pcap-zoom'));
            if (isFinite(rawZoom)) savedZoom = rawZoom;
        } catch (e) { }
        setZoom(viewer, savedZoom);

        viewer.onKey = function (e) {
            var tag = (e.target && e.target.tagName ? e.target.tagName : '').toLowerCase();
            var typing = tag === 'input' || tag === 'textarea' || tag === 'select' ||
                (e.target && e.target.isContentEditable);
            var ctrl = e.ctrlKey || e.metaKey;
            var key = e.key;

            if (key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                if (viewer.dialog) { closeDialog(viewer); return; }
                if (viewer.contextMenu) { closeContextMenu(viewer); return; }
                if (viewer.openMenuEl) { closeMenus(viewer); return; }
                if (viewer.helpOpen) {
                    toggleHelp(viewer, false);
                    viewer.els.filter.focus();
                    return;
                }
                if (e.target === viewer.els.filter && viewer.els.filter.value) {
                    clearFilter(viewer);
                    return;
                }
                closeViewer();
                return;
            }

            if (ctrl && !e.altKey && !e.shiftKey && (key === 'f' || key === 'F')) {
                e.preventDefault();
                closeMenus(viewer);
                toggleHelp(viewer, false);
                openFindDialog(viewer);
                return;
            }
            if (ctrl && !e.altKey && !e.shiftKey && key === '/') {
                e.preventDefault();
                closeMenus(viewer);
                toggleHelp(viewer, false);
                viewer.els.filter.focus();
                viewer.els.filter.select();
                return;
            }
            if (ctrl && !e.altKey && !e.shiftKey && (key === 'o' || key === 'O')) {
                e.preventDefault();
                if (typeof window.pcapOpenFileRequest === 'function') window.pcapOpenFileRequest();
                return;
            }
            if (ctrl && !e.altKey && (key === 'n' || key === 'N')) {
                e.preventDefault();
                findAgain(viewer, e.shiftKey ? -1 : 1);
                return;
            }
            if (ctrl && !e.altKey && (key === 'g' || key === 'G')) {
                e.preventDefault();
                openGotoDialog(viewer);
                return;
            }
            if (ctrl && !e.altKey && (key === 'm' || key === 'M')) {
                e.preventDefault();
                if (viewer.selected >= 0) toggleMark(viewer, viewer.selected);
                return;
            }
            if (ctrl && e.altKey && !e.shiftKey && (key === 'c' || key === 'C')) {
                e.preventDefault();
                if (viewer.selected >= 0) openCommentDialog(viewer, viewer.selected);
                return;
            }
            if (ctrl && e.altKey && e.shiftKey && (key === 't' || key === 'T')) {
                e.preventDefault();
                if (viewer.selected >= 0) openFollowStream(viewer, viewer.selected);
                return;
            }
            if (ctrl && (key === '=' || key === '+')) {
                e.preventDefault();
                stepZoom(viewer, 1);
                return;
            }
            if (ctrl && key === '-') {
                e.preventDefault();
                stepZoom(viewer, -1);
                return;
            }
            if (ctrl && key === '0') {
                e.preventDefault();
                setZoom(viewer, 1);
                return;
            }
            if (ctrl && (key === 'r' || key === 'R')) {
                e.preventDefault();
                loadCapture(viewer, viewer.source);
                return;
            }
            if (ctrl && (key === 'w' || key === 'W')) {
                e.preventDefault();
                closeViewer();
                return;
            }
            if (key === 'F1') {
                e.preventDefault();
                toggleHelp(viewer, !viewer.helpOpen);
                return;
            }
            if (typing || viewer.dialog || viewer.contextMenu) return;

            if (key === 'Home') { e.preventDefault(); goRelative(viewer, 'first'); }
            else if (key === 'End') { e.preventDefault(); goRelative(viewer, 'last'); }
            else if (key === 'ArrowDown') { e.preventDefault(); goRelative(viewer, 1); }
            else if (key === 'ArrowUp') { e.preventDefault(); goRelative(viewer, -1); }
        };
        document.addEventListener('keydown', viewer.onKey, true);
        loadCapture(viewer, source);
        academyEmit('ready', { name: viewer.name, source: source });
        return viewer;
    }

    function openPcapFile(file, name) {
        if (!file) return null;
        return openPcapViewer(file, name || file.name || 'capture');
    }

    window.openPcapViewer = openPcapViewer;
    window.openPcapFile = openPcapFile;
    window.closePcapViewer = closeViewer;

    window.PcapAcademyApi = {
        active: function () { return activeViewer; },
        captureName: function () { return activeViewer ? activeViewer.name : ''; },
        selectNo: function (no) {
            if (!activeViewer) return false;
            for (var i = 0; i < activeViewer.packets.length; i++) {
                if (activeViewer.packets[i].no === no) {
                    selectPacket(activeViewer, i);
                    return true;
                }
            }
            return false;
        },
        markNo: function (no, on) {
            if (!activeViewer) return false;
            for (var i = 0; i < activeViewer.packets.length; i++) {
                if (activeViewer.packets[i].no === no) {
                    var want = on === undefined ? !activeViewer.marked.has(i) : !!on;
                    if (want !== activeViewer.marked.has(i)) toggleMark(activeViewer, i);
                    return true;
                }
            }
            return false;
        },
        setFilter: function (expr) {
            if (!activeViewer) return false;
            activeViewer.els.filter.value = expr || '';
            applyFilter(activeViewer);
            return !activeViewer.filterError;
        },
        clearFilter: function () {
            if (!activeViewer) return;
            clearFilter(activeViewer);
        },
        openPanel: function (name) {
            if (!activeViewer) return false;
            var panels = {
                follow: function () { openFollowStream(activeViewer, activeViewer.selected); },
                hierarchy: function () { showProtocolHierarchy(activeViewer); },
                conversations: function () { showConversations(activeViewer); },
                endpoints: function () { showEndpoints(activeViewer); },
                io: function () { showIOGraph(activeViewer); },
                expert: function () { showExpertInfo(activeViewer); },
                http: function () { showHTTPObjects(activeViewer); },
                colors: function () { openColoringRules(activeViewer); },
                columns: function () { openColumnsDialog(activeViewer); },
                properties: function () { showCaptureProperties(activeViewer); }
            };
            if (!panels[name]) return false;
            panels[name]();
            return true;
        }
    };
})();
