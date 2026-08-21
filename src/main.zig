const std = @import("std");
const linux = std.os.linux;

const ETH_P_ALL: u16 = 0x0003;

var domains_only: bool = false;
var dashboard_mode: bool = false;
var should_stop: bool = false;

fn monotonicMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn realtimeUs() struct { sec: u32, usec: u32 } {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    return .{
        .sec = @intCast(ts.sec),
        .usec = @intCast(@divTrunc(ts.nsec, 1000)),
    };
}

const PcapGlobalHeader = extern struct {
    magic: u32 align(1) = 0xa1b2c3d4,
    version_major: u16 align(1) = 2,
    version_minor: u16 align(1) = 4,
    thiszone: i32 align(1) = 0,
    sigfigs: u32 align(1) = 0,
    snaplen: u32 align(1) = 65535,
    network: u32 align(1) = 1,
};

const PcapPacketHeader = extern struct {
    ts_sec: u32 align(1),
    ts_usec: u32 align(1),
    incl_len: u32 align(1),
    orig_len: u32 align(1),
};

fn openPcapFile(path: []const u8) ?i32 {
    var path_buf: [256]u8 = undefined;
    if (path.len >= path_buf.len - 1) return null;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const fd_rc = linux.open(
        @ptrCast(&path_buf),
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        0o644,
    );
    const fd: i32 = @intCast(checkErrno(fd_rc) catch {
        std.debug.print("could not open pcap file '{s}'\n", .{path});
        return null;
    });

    const header = PcapGlobalHeader{};
    const bytes = std.mem.asBytes(&header);
    _ = linux.write(fd, bytes.ptr, bytes.len);
    return fd;
}

fn writePcapPacket(fd: i32, frame: []const u8) void {
    const now = realtimeUs();
    const hdr = PcapPacketHeader{
        .ts_sec = now.sec,
        .ts_usec = now.usec,
        .incl_len = @intCast(frame.len),
        .orig_len = @intCast(frame.len),
    };
    const hdr_bytes = std.mem.asBytes(&hdr);
    _ = linux.write(fd, hdr_bytes.ptr, hdr_bytes.len);
    _ = linux.write(fd, frame.ptr, frame.len);
}

fn handleSigint(sig: linux.SIG) callconv(.c) void {
    _ = sig;
    should_stop = true;
}

fn installSigintHandler() void {
    const act = linux.Sigaction{
        .handler = .{ .handler = &handleSigint },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(linux.SIG.INT, &act, null);
}

const sockaddr_ll = extern struct {
    family: u16 = linux.AF.PACKET,
    protocol: u16 align(1) = 0,
    ifindex: i32 align(1) = 0,
    hatype: u16 align(1) = 0,
    pkttype: u8 = 0,
    halen: u8 = 0,
    addr: [8]u8 align(1) = [_]u8{0} ** 8,
};

fn readCmdlineArgs(buf: []u8) [][]const u8 {
    var static_args: [16][]const u8 = undefined;
    var count: usize = 0;

    const fd_rc = linux.open("/proc/self/cmdline", .{}, 0);
    const fd: i32 = @intCast(checkErrno(fd_rc) catch return static_args[0..0]);
    defer _ = linux.close(fd);

    const read_rc = linux.read(fd, buf.ptr, buf.len);
    const n = checkErrno(read_rc) catch return static_args[0..0];

    var it = std.mem.splitScalar(u8, buf[0..n], 0);
    var idx: usize = 0;
    while (it.next()) |arg| {
        if (arg.len == 0) continue;
        if (idx > 0 and count < static_args.len) {
            static_args[count] = arg;
            count += 1;
        }
        idx += 1;
    }
    return static_args[0..count];
}

fn ifreqWithName(name: []const u8) linux.ifreq {
    var ifr = std.mem.zeroes(linux.ifreq);
    const len = @min(name.len, linux.IFNAMESIZE - 1);
    @memcpy(ifr.ifrn.name[0..len], name[0..len]);
    return ifr;
}

fn bindToInterface(sock: i32, iface: []const u8) !void {
    var ifr = ifreqWithName(iface);

    const idx_rc = linux.ioctl(sock, linux.SIOCGIFINDEX, @intFromPtr(&ifr));
    _ = checkErrno(idx_rc) catch {
        std.debug.print("unknown interface '{s}' (see `ip a` for names)\n", .{iface});
        return error.NoSuchInterface;
    };
    const ifindex = ifr.ifru.ivalue;

    const flags_rc = linux.ioctl(sock, linux.SIOCGIFFLAGS, @intFromPtr(&ifr));
    _ = checkErrno(flags_rc) catch {
        std.debug.print("warning: could not read interface flags, skipping promiscuous mode\n", .{});
        return bindOnly(sock, ifindex);
    };
    ifr.ifru.flags.PROMISC = true;
    const set_rc = linux.ioctl(sock, linux.SIOCSIFFLAGS, @intFromPtr(&ifr));
    _ = checkErrno(set_rc) catch {
        std.debug.print("warning: could not enable promiscuous mode (need CAP_NET_ADMIN too)\n", .{});
    };

    try bindOnly(sock, ifindex);
}

fn bindOnly(sock: i32, ifindex: i32) !void {
    const addr = sockaddr_ll{
        .protocol = @byteSwap(ETH_P_ALL),
        .ifindex = ifindex,
    };
    const bind_rc = linux.bind(sock, @ptrCast(&addr), @sizeOf(sockaddr_ll));
    _ = try checkErrno(bind_rc);
}

fn checkErrno(rc: usize) !usize {
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        const errno: linux.E = @enumFromInt(-signed);
        std.debug.print("syscall failed: {t}\n", .{errno});
        return error.SyscallFailed;
    }
    return rc;
}

const EthHeader = extern struct {
    dst: [6]u8,
    src: [6]u8,
    ethertype_be: u16 align(1),

    fn ethertype(self: EthHeader) u16 {
        return @byteSwap(self.ethertype_be);
    }
};

const Ipv4Header = extern struct {
    version_ihl: u8,
    dscp_ecn: u8,
    total_len_be: u16 align(1),
    id_be: u16 align(1),
    flags_frag_be: u16 align(1),
    ttl: u8,
    protocol: u8,
    checksum_be: u16 align(1),
    src_be: u32 align(1),
    dst_be: u32 align(1),

    fn ihlBytes(self: Ipv4Header) usize {
        return @as(usize, self.version_ihl & 0x0f) * 4;
    }

    fn totalLen(self: Ipv4Header) u16 {
        return @byteSwap(self.total_len_be);
    }
};

const TcpHeader = extern struct {
    src_port_be: u16 align(1),
    dst_port_be: u16 align(1),
    seq_be: u32 align(1),
    ack_be: u32 align(1),
    offset_flags_be: u16 align(1),
    window_be: u16 align(1),
    checksum_be: u16 align(1),
    urgent_ptr_be: u16 align(1),

    fn srcPort(self: TcpHeader) u16 {
        return @byteSwap(self.src_port_be);
    }
    fn dstPort(self: TcpHeader) u16 {
        return @byteSwap(self.dst_port_be);
    }
    fn flags(self: TcpHeader) u8 {
        return @truncate(@byteSwap(self.offset_flags_be));
    }
    fn dataOffsetBytes(self: TcpHeader) usize {
        const raw = @byteSwap(self.offset_flags_be);
        return @as(usize, (raw >> 12) & 0xF) * 4;
    }
};

const UdpHeader = extern struct {
    src_port_be: u16 align(1),
    dst_port_be: u16 align(1),
    length_be: u16 align(1),
    checksum_be: u16 align(1),

    fn srcPort(self: UdpHeader) u16 {
        return @byteSwap(self.src_port_be);
    }
    fn dstPort(self: UdpHeader) u16 {
        return @byteSwap(self.dst_port_be);
    }
};

fn tcpFlagsStr(f: u8, buf: []u8) []const u8 {
    var i: usize = 0;
    if (f & 0x02 != 0) { buf[i] = 'S'; i += 1; }
    if (f & 0x10 != 0) { buf[i] = 'A'; i += 1; }
    if (f & 0x01 != 0) { buf[i] = 'F'; i += 1; }
    if (f & 0x04 != 0) { buf[i] = 'R'; i += 1; }
    if (f & 0x08 != 0) { buf[i] = 'P'; i += 1; }
    if (i == 0) { buf[0] = '-'; i = 1; }
    return buf[0..i];
}

fn wellKnownService(port: u16) ?[]const u8 {
    return switch (port) {
        20, 21 => "FTP",
        22 => "SSH",
        23 => "TELNET",
        25 => "SMTP",
        53 => "DNS",
        67, 68 => "DHCP",
        80 => "HTTP",
        123 => "NTP",
        143 => "IMAP",
        443 => "HTTPS",
        3306 => "MYSQL",
        5432 => "POSTGRES",
        6379 => "REDIS",
        else => null,
    };
}

fn formatIp(addr_be: u32, buf: []u8) ![]const u8 {
    const bytes = std.mem.asBytes(&addr_be);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
}

const HostCache = struct {
    const Entry = struct {
        ip: u32 = 0,
        used: bool = false,
        name: [64]u8 = undefined,
        len: u8 = 0,
    };

    entries: [256]Entry = [_]Entry{.{}} ** 256,

    fn slot(ip: u32) usize {
        return @as(usize, ip) % 256;
    }

    fn put(self: *HostCache, ip: u32, name: []const u8) void {
        const e = &self.entries[slot(ip)];
        e.ip = ip;
        e.used = true;
        const l = @min(name.len, e.name.len);
        @memcpy(e.name[0..l], name[0..l]);
        e.len = @intCast(l);
    }

    fn get(self: *HostCache, ip: u32) ?[]const u8 {
        const e = &self.entries[slot(ip)];
        if (e.used and e.ip == ip) return e.name[0..e.len];
        return null;
    }
};

var host_cache: HostCache = .{};

fn addrLabel(addr_be: u32, buf: []u8) []const u8 {
    if (host_cache.get(addr_be)) |name| return name;
    return formatIp(addr_be, buf) catch "?";
}

fn hasHostLabel(addr_be: u32) bool {
    return host_cache.get(addr_be) != null;
}

fn extractSni(payload: []const u8) ?[]const u8 {
    if (payload.len < 6) return null;
    if (payload[0] != 0x16) return null;
    if (payload[5] != 0x01) return null;

    var pos: usize = 9;
    if (payload.len < pos + 2 + 32 + 1) return null;
    pos += 2 + 32;

    const session_id_len = payload[pos];
    pos += 1;
    if (payload.len < pos + session_id_len + 2) return null;
    pos += session_id_len;

    const cipher_len = std.mem.readInt(u16, payload[pos..][0..2], .big);
    pos += 2;
    if (payload.len < pos + cipher_len + 1) return null;
    pos += cipher_len;

    const comp_len = payload[pos];
    pos += 1;
    if (payload.len < pos + comp_len + 2) return null;
    pos += comp_len;

    const ext_total_len = std.mem.readInt(u16, payload[pos..][0..2], .big);
    pos += 2;
    const ext_end = @min(pos + ext_total_len, payload.len);

    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, payload[pos..][0..2], .big);
        const ext_len = std.mem.readInt(u16, payload[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0 and ext_len >= 5) {
            var sp = pos + 2;
            const list_end = pos + ext_len;
            if (sp + 3 > list_end) return null;
            sp += 1;
            const name_len = std.mem.readInt(u16, payload[sp..][0..2], .big);
            sp += 2;
            if (sp + name_len > list_end or sp + name_len > payload.len) return null;
            return payload[sp .. sp + name_len];
        }
        pos += ext_len;
    }
    return null;
}

fn readDnsName(payload: []const u8, start: usize, buf: []u8) ?struct { name: []const u8, end: usize } {
    var pos = start;
    var out_len: usize = 0;
    var jumped = false;
    var end_pos: usize = start;
    var guard: usize = 0;

    while (true) {
        guard += 1;
        if (guard > 128) return null;
        if (pos >= payload.len) return null;

        const len_byte = payload[pos];
        if (len_byte == 0) {
            pos += 1;
            if (!jumped) end_pos = pos;
            break;
        }
        if (len_byte & 0xC0 == 0xC0) {
            if (pos + 1 >= payload.len) return null;
            const offset = (@as(usize, len_byte & 0x3F) << 8) | payload[pos + 1];
            if (!jumped) end_pos = pos + 2;
            jumped = true;
            pos = offset;
            continue;
        }
        if (len_byte & 0xC0 != 0) return null;

        const label_len = len_byte;
        pos += 1;
        if (pos + label_len > payload.len) return null;
        if (out_len != 0 and out_len < buf.len) {
            buf[out_len] = '.';
            out_len += 1;
        }
        const copy_len = @min(label_len, buf.len -| out_len);
        @memcpy(buf[out_len .. out_len + copy_len], payload[pos .. pos + copy_len]);
        out_len += copy_len;
        pos += label_len;
    }

    return .{ .name = buf[0..out_len], .end = end_pos };
}

fn extractDnsAnswers(payload: []const u8) void {
    if (payload.len < 12) return;
    const flags = std.mem.readInt(u16, payload[2..4], .big);
    if (flags & 0x8000 == 0) return;
    const qdcount = std.mem.readInt(u16, payload[4..6], .big);
    const ancount = std.mem.readInt(u16, payload[6..8], .big);
    if (qdcount == 0 or ancount == 0) return;

    var pos: usize = 12;
    var qname_buf: [128]u8 = undefined;
    const q = readDnsName(payload, pos, &qname_buf) orelse return;
    pos = q.end;
    if (pos + 4 > payload.len) return;
    pos += 4;

    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        var rr_name_buf: [128]u8 = undefined;
        const rr = readDnsName(payload, pos, &rr_name_buf) orelse return;
        pos = rr.end;
        if (pos + 10 > payload.len) return;

        const rtype = std.mem.readInt(u16, payload[pos..][0..2], .big);
        pos += 2 + 2 + 4;
        const rdlen = std.mem.readInt(u16, payload[pos..][0..2], .big);
        pos += 2;
        if (pos + rdlen > payload.len) return;

        if (rtype == 1 and rdlen == 4) {
            const ip_val = std.mem.bytesToValue(u32, payload[pos..][0..4]);
            host_cache.put(ip_val, q.name);
        }
        pos += rdlen;
    }
}

fn extractHttpHost(payload: []const u8) ?[]const u8 {
    const needle = "Host: ";
    const idx = std.mem.indexOf(u8, payload, needle) orelse return null;
    const rest = payload[idx + needle.len ..];
    const end = std.mem.indexOfAny(u8, rest, "\r\n") orelse rest.len;
    if (end == 0) return null;
    return rest[0..end];
}

fn recordFlow(flows: *std.AutoHashMap(FlowKey, FlowStats), key: FlowKey, len: u16) void {
    const gop = flows.getOrPut(key) catch return;
    if (!gop.found_existing) gop.value_ptr.* = .{};
    gop.value_ptr.bytes += len;
    gop.value_ptr.packets += 1;
}

fn protocolName(proto: u8) []const u8 {
    return switch (proto) {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        else => "OTHER",
    };
}

const FlowKey = struct {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
};

const FlowStats = struct {
    bytes: u64 = 0,
    packets: u32 = 0,
};

fn printTopFlows(flows: *std.AutoHashMap(FlowKey, FlowStats)) void {
    const Row = struct { key: FlowKey, stats: FlowStats };
    var top: [5]Row = [_]Row{.{ .key = undefined, .stats = .{} }} ** 5;

    var it = flows.iterator();
    while (it.next()) |kv| {
        if (domains_only and !hasHostLabel(kv.key_ptr.src_ip) and !hasHostLabel(kv.key_ptr.dst_ip)) continue;
        const row = Row{ .key = kv.key_ptr.*, .stats = kv.value_ptr.* };
        var i: usize = 0;
        while (i < top.len and top[i].stats.bytes >= row.stats.bytes) : (i += 1) {}
        if (i < top.len) {
            var j = top.len - 1;
            while (j > i) : (j -= 1) top[j] = top[j - 1];
            top[i] = row;
        }
    }

    std.debug.print("=== top flows ===\n", .{});
    var src_buf: [64]u8 = undefined;
    var dst_buf: [64]u8 = undefined;
    for (top) |row| {
        if (row.stats.bytes == 0) continue;
        std.debug.print("  {s}:{d} -> {s}:{d}  {s}  {d} bytes  {d} pkts\n", .{
            addrLabel(row.key.src_ip, &src_buf), row.key.src_port,
            addrLabel(row.key.dst_ip, &dst_buf), row.key.dst_port,
            protocolName(row.key.protocol),
            row.stats.bytes, row.stats.packets,
        });
    }
    std.debug.print("==================\n", .{});
}

fn formatBytes(n: u64, buf: []u8) []const u8 {
    if (n >= 1024 * 1024 * 1024) {
        const gb = @as(f64, @floatFromInt(n)) / (1024.0 * 1024.0 * 1024.0);
        return std.fmt.bufPrint(buf, "{d:.2} GB", .{gb}) catch "?";
    } else if (n >= 1024 * 1024) {
        const mb = @as(f64, @floatFromInt(n)) / (1024.0 * 1024.0);
        return std.fmt.bufPrint(buf, "{d:.2} MB", .{mb}) catch "?";
    } else if (n >= 1024) {
        const kb = @as(f64, @floatFromInt(n)) / 1024.0;
        return std.fmt.bufPrint(buf, "{d:.1} KB", .{kb}) catch "?";
    }
    return std.fmt.bufPrint(buf, "{d} B", .{n}) catch "?";
}

const HostBucket = struct { label: [64]u8 = undefined, label_len: u8 = 0, bytes: u64 = 0 };

fn mergeHostBuckets(counts: *std.AutoHashMap(u32, u64), buckets: *[64]HostBucket) usize {
    var bucket_count: usize = 0;

    var it = counts.iterator();
    while (it.next()) |kv| {
        if (domains_only and !hasHostLabel(kv.key_ptr.*)) continue;

        var raw_buf: [64]u8 = undefined;
        const label = addrLabel(kv.key_ptr.*, &raw_buf);

        var found = false;
        var i: usize = 0;
        while (i < bucket_count) : (i += 1) {
            if (std.mem.eql(u8, buckets[i].label[0..buckets[i].label_len], label)) {
                buckets[i].bytes += kv.value_ptr.*;
                found = true;
                break;
            }
        }
        if (!found and bucket_count < buckets.len) {
            const l = @min(label.len, buckets[bucket_count].label.len);
            @memcpy(buckets[bucket_count].label[0..l], label[0..l]);
            buckets[bucket_count].label_len = @intCast(l);
            buckets[bucket_count].bytes = kv.value_ptr.*;
            bucket_count += 1;
        }
    }

    var i: usize = 1;
    while (i < bucket_count) : (i += 1) {
        const key = buckets[i];
        var j = i;
        while (j > 0 and buckets[j - 1].bytes < key.bytes) : (j -= 1) buckets[j] = buckets[j - 1];
        buckets[j] = key;
    }
    return bucket_count;
}

fn printTopTalkers(counts: *std.AutoHashMap(u32, u64), session_total: u64) void {
    var buckets: [64]HostBucket = undefined;
    const bucket_count = mergeHostBuckets(counts, &buckets);

    var total_buf: [16]u8 = undefined;
    std.debug.print("--- total data used: {s} ---\n", .{formatBytes(session_total, &total_buf)});

    if (bucket_count > 0) {
        var top_buf: [16]u8 = undefined;
        std.debug.print("  most data used: {s} ({s})\n", .{
            buckets[0].label[0..buckets[0].label_len],
            formatBytes(buckets[0].bytes, &top_buf),
        });
    }

    const shown = @min(bucket_count, 5);
    for (buckets[0..shown]) |b| {
        var b_buf: [16]u8 = undefined;
        std.debug.print("  {s}  {s}\n", .{ b.label[0..b.label_len], formatBytes(b.bytes, &b_buf) });
    }
    std.debug.print("-------------------\n", .{});
}

fn renderDashboard(
    counts: *std.AutoHashMap(u32, u64),
    flows: *std.AutoHashMap(FlowKey, FlowStats),
    session_total: u64,
    packets_seen: u64,
    elapsed_ms: i64,
) void {
    var buckets: [64]HostBucket = undefined;
    const bucket_count = mergeHostBuckets(counts, &buckets);

    const elapsed_s = @max(@as(f64, @floatFromInt(elapsed_ms)) / 1000.0, 0.001);
    const pps = @as(f64, @floatFromInt(packets_seen)) / elapsed_s;
    const bps = @as(f64, @floatFromInt(session_total)) / elapsed_s;

    std.debug.print("\x1b[2J\x1b[H", .{});
    std.debug.print("packet-sniffer  (ctrl-c to stop)\n", .{});
    std.debug.print("========================================\n", .{});

    var total_buf: [16]u8 = undefined;
    var rate_buf: [16]u8 = undefined;
    std.debug.print("total data used : {s}\n", .{formatBytes(session_total, &total_buf)});
    std.debug.print("throughput      : {d:.0} pkt/s, {s}/s\n", .{ pps, formatBytes(@intFromFloat(bps), &rate_buf) });

    if (bucket_count > 0) {
        var top_buf: [16]u8 = undefined;
        std.debug.print("most data used  : {s} ({s})\n", .{
            buckets[0].label[0..buckets[0].label_len],
            formatBytes(buckets[0].bytes, &top_buf),
        });
    }

    std.debug.print("\n--- top hosts ---\n", .{});
    const shown = @min(bucket_count, 8);
    for (buckets[0..shown]) |b| {
        var b_buf: [16]u8 = undefined;
        std.debug.print("  {s}  {s}\n", .{ b.label[0..b.label_len], formatBytes(b.bytes, &b_buf) });
    }

    std.debug.print("\n--- top flows ---\n", .{});
    const FlowRow = struct { key: FlowKey, stats: FlowStats };
    var top: [8]FlowRow = [_]FlowRow{.{ .key = undefined, .stats = .{} }} ** 8;
    var it = flows.iterator();
    while (it.next()) |kv| {
        if (domains_only and !hasHostLabel(kv.key_ptr.src_ip) and !hasHostLabel(kv.key_ptr.dst_ip)) continue;
        const row = FlowRow{ .key = kv.key_ptr.*, .stats = kv.value_ptr.* };
        var i: usize = 0;
        while (i < top.len and top[i].stats.bytes >= row.stats.bytes) : (i += 1) {}
        if (i < top.len) {
            var j = top.len - 1;
            while (j > i) : (j -= 1) top[j] = top[j - 1];
            top[i] = row;
        }
    }
    var src_buf: [64]u8 = undefined;
    var dst_buf: [64]u8 = undefined;
    for (top) |row| {
        if (row.stats.bytes == 0) continue;
        var f_buf: [16]u8 = undefined;
        std.debug.print("  {s}:{d} -> {s}:{d}  {s}  {s}  {d} pkts\n", .{
            addrLabel(row.key.src_ip, &src_buf), row.key.src_port,
            addrLabel(row.key.dst_ip, &dst_buf), row.key.dst_port,
            protocolName(row.key.protocol),
            formatBytes(row.stats.bytes, &f_buf), row.stats.packets,
        });
    }
}

fn printUsage() void {
    std.debug.print(
        \\packet-sniffer [interface] [options]
        \\
        \\  interface        capture on this NIC in promiscuous mode (see `ip a`)
        \\                   omit to capture all interfaces, own traffic only
        \\
        \\options:
        \\  --dashboard      live-updating full screen view instead of scrolling log
        \\  --domains-only   hide rows without a resolved hostname
        \\  --pcap <file>    also write raw captured packets to a pcap file
        \\  --help, -h       show this message
        \\
        \\examples:
        \\  packet_sniffer
        \\  packet_sniffer wlan0
        \\  packet_sniffer wlan0 --dashboard
        \\  packet_sniffer wlan0 --domains-only
        \\  packet_sniffer wlan0 --pcap capture.pcap
        \\
    , .{});
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var byte_counts = std.AutoHashMap(u32, u64).init(allocator);
    defer byte_counts.deinit();

    var flows = std.AutoHashMap(FlowKey, FlowStats).init(allocator);
    defer flows.deinit();

    var argv_buf: [1024]u8 = undefined;
    const args = readCmdlineArgs(&argv_buf);
    var iface: ?[]const u8 = null;
    var pcap_path: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            printUsage();
            return;
        } else if (std.mem.eql(u8, a, "--domains-only")) {
            domains_only = true;
        } else if (std.mem.eql(u8, a, "--dashboard")) {
            dashboard_mode = true;
        } else if (std.mem.eql(u8, a, "--pcap")) {
            if (i + 1 < args.len) {
                i += 1;
                pcap_path = args[i];
            } else {
                std.debug.print("--pcap needs a file path\n", .{});
                return;
            }
        } else if (!std.mem.startsWith(u8, a, "--")) {
            iface = a;
        }
    }

    const pcap_fd: ?i32 = if (pcap_path) |p| openPcapFile(p) else null;
    defer {
        if (pcap_fd) |fd| _ = linux.close(fd);
    }

    const sock_rc = linux.socket(linux.AF.PACKET, linux.SOCK.RAW, @byteSwap(ETH_P_ALL));
    const sock: i32 = @intCast(checkErrno(sock_rc) catch {
        std.debug.print("try: sudo setcap cap_net_raw+ep ./zig-out/bin/packet_sniffer\n", .{});
        return error.SocketOpenFailed;
    });
    defer _ = linux.close(sock);

    if (iface) |name| {
        try bindToInterface(sock, name);
        if (!dashboard_mode) std.debug.print("capturing on {s} (promiscuous) ... (ctrl-c to stop)\n", .{name});
    } else {
        if (!dashboard_mode) {
            std.debug.print("capturing on all interfaces, own traffic only\n", .{});
            std.debug.print("pass an interface name (see `ip a`) to enable promiscuous capture, e.g.:\n", .{});
            std.debug.print("  ./zig-out/bin/packet_sniffer wlan0\n", .{});
            std.debug.print("capturing... (ctrl-c to stop)\n", .{});
        }
    }
    if (domains_only and !dashboard_mode) std.debug.print("(domains-only mode: hiding rows without a known hostname)\n", .{});

    installSigintHandler();

    var frame_buf: [2048]u8 = undefined;
    var ip_buf_src: [16]u8 = undefined;
    var ip_buf_dst: [16]u8 = undefined;
    var session_total: u64 = 0;
    var packets_seen: u64 = 0;
    const start_ms = monotonicMs();
    var last_redraw_ms: i64 = 0;

    while (!should_stop) {
        const read_rc = linux.read(sock, &frame_buf, frame_buf.len);
        const n = checkErrno(read_rc) catch continue;
        if (n < @sizeOf(EthHeader)) continue;

        if (pcap_fd) |fd| writePcapPacket(fd, frame_buf[0..n]);

        const eth: *const EthHeader = @ptrCast(&frame_buf);
        if (eth.ethertype() != 0x0800) continue;

        const ip_offset = @sizeOf(EthHeader);
        if (n < ip_offset + @sizeOf(Ipv4Header)) continue;

        const ip: *const Ipv4Header = @ptrCast(&frame_buf[ip_offset]);
        const ihl = ip.ihlBytes();
        if (ihl < @sizeOf(Ipv4Header)) continue;
        const l4_offset = ip_offset + ihl;

        session_total += ip.totalLen();
        packets_seen += 1;

        const gop_src = byte_counts.getOrPut(ip.src_be) catch continue;
        if (!gop_src.found_existing) gop_src.value_ptr.* = 0;
        gop_src.value_ptr.* += ip.totalLen();

        const gop_dst = byte_counts.getOrPut(ip.dst_be) catch continue;
        if (!gop_dst.found_existing) gop_dst.value_ptr.* = 0;
        gop_dst.value_ptr.* += ip.totalLen();

        var flags_buf: [5]u8 = undefined;

        switch (ip.protocol) {
            6 => {
                if (n < l4_offset + @sizeOf(TcpHeader)) continue;
                const tcp: *const TcpHeader = @ptrCast(&frame_buf[l4_offset]);
                const tcp_hdr_len = tcp.dataOffsetBytes();

                if (tcp_hdr_len >= @sizeOf(TcpHeader) and n > l4_offset + tcp_hdr_len) {
                    const payload = frame_buf[l4_offset + tcp_hdr_len .. n];
                    if (tcp.dstPort() == 443) {
                        if (extractSni(payload)) |host| host_cache.put(ip.dst_be, host);
                    }
                    if (tcp.dstPort() == 80 or tcp.srcPort() == 80) {
                        if (extractHttpHost(payload)) |host| {
                            const server_ip = if (tcp.dstPort() == 80) ip.dst_be else ip.src_be;
                            host_cache.put(server_ip, host);
                        }
                    }
                }

                recordFlow(&flows, .{
                    .src_ip = ip.src_be, .dst_ip = ip.dst_be,
                    .src_port = tcp.srcPort(), .dst_port = tcp.dstPort(),
                    .protocol = ip.protocol,
                }, ip.totalLen());

                if (!dashboard_mode and (!domains_only or hasHostLabel(ip.src_be) or hasHostLabel(ip.dst_be))) {
                    const src_str = addrLabel(ip.src_be, &ip_buf_src);
                    const dst_str = addrLabel(ip.dst_be, &ip_buf_dst);
                    const svc = wellKnownService(tcp.srcPort()) orelse wellKnownService(tcp.dstPort());
                    std.debug.print("{s}:{d} -> {s}:{d}  TCP [{s}]{s}{s}  len={d}\n", .{
                        src_str, tcp.srcPort(), dst_str, tcp.dstPort(),
                        tcpFlagsStr(tcp.flags(), &flags_buf),
                        if (svc != null) " " else "",
                        svc orelse "",
                        ip.totalLen(),
                    });
                }
            },
            17 => {
                if (n < l4_offset + @sizeOf(UdpHeader)) continue;
                const udp: *const UdpHeader = @ptrCast(&frame_buf[l4_offset]);

                if (udp.srcPort() == 53) {
                    const udp_hdr_len = @sizeOf(UdpHeader);
                    if (n > l4_offset + udp_hdr_len) {
                        extractDnsAnswers(frame_buf[l4_offset + udp_hdr_len .. n]);
                    }
                }

                recordFlow(&flows, .{
                    .src_ip = ip.src_be, .dst_ip = ip.dst_be,
                    .src_port = udp.srcPort(), .dst_port = udp.dstPort(),
                    .protocol = ip.protocol,
                }, ip.totalLen());

                if (!dashboard_mode and (!domains_only or hasHostLabel(ip.src_be) or hasHostLabel(ip.dst_be))) {
                    const src_str = addrLabel(ip.src_be, &ip_buf_src);
                    const dst_str = addrLabel(ip.dst_be, &ip_buf_dst);
                    const svc = wellKnownService(udp.srcPort()) orelse wellKnownService(udp.dstPort());
                    std.debug.print("{s}:{d} -> {s}:{d}  UDP{s}{s}  len={d}\n", .{
                        src_str, udp.srcPort(), dst_str, udp.dstPort(),
                        if (svc != null) " " else "",
                        svc orelse "",
                        ip.totalLen(),
                    });
                }
            },
            else => {
                recordFlow(&flows, .{
                    .src_ip = ip.src_be, .dst_ip = ip.dst_be,
                    .src_port = 0, .dst_port = 0,
                    .protocol = ip.protocol,
                }, ip.totalLen());

                if (!dashboard_mode and (!domains_only or hasHostLabel(ip.src_be) or hasHostLabel(ip.dst_be))) {
                    const src_str = addrLabel(ip.src_be, &ip_buf_src);
                    const dst_str = addrLabel(ip.dst_be, &ip_buf_dst);
                    std.debug.print("{s} -> {s}  proto={s}  len={d}\n", .{
                        src_str, dst_str, protocolName(ip.protocol), ip.totalLen(),
                    });
                }
            },
        }

        if (dashboard_mode) {
            const now_ms = monotonicMs();
            if (now_ms - last_redraw_ms >= 250) {
                renderDashboard(&byte_counts, &flows, session_total, packets_seen, now_ms - start_ms);
                last_redraw_ms = now_ms;
            }
        }
    }

    if (dashboard_mode) {
        renderDashboard(&byte_counts, &flows, session_total, packets_seen, monotonicMs() - start_ms);
    } else {
        std.debug.print("\n", .{});
        printTopTalkers(&byte_counts, session_total);
        printTopFlows(&flows);
    }
}

test "pcap file has valid global header and packet record" {
    const path = "/tmp/packet_sniffer_test.pcap";
    const fd = openPcapFile(path) orelse return error.OpenFailed;
    const fake_frame = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    writePcapPacket(fd, &fake_frame);
    _ = linux.close(fd);

    const read_fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    const read_fd: i32 = @intCast(try checkErrno(read_fd_rc));
    defer _ = linux.close(read_fd);
    defer _ = linux.unlink(path);

    var buf: [4096]u8 = undefined;
    const read_rc = linux.read(read_fd, &buf, buf.len);
    const n = try checkErrno(read_rc);
    const contents = buf[0..n];

    try std.testing.expect(contents.len == @sizeOf(PcapGlobalHeader) + @sizeOf(PcapPacketHeader) + fake_frame.len);

    const global: *const PcapGlobalHeader = @ptrCast(@alignCast(contents.ptr));
    try std.testing.expectEqual(@as(u32, 0xa1b2c3d4), global.magic);
    try std.testing.expectEqual(@as(u32, 1), global.network);

    const pkt_hdr: *const PcapPacketHeader = @ptrCast(@alignCast(contents.ptr + @sizeOf(PcapGlobalHeader)));
    try std.testing.expectEqual(@as(u32, fake_frame.len), pkt_hdr.incl_len);
    try std.testing.expectEqual(@as(u32, fake_frame.len), pkt_hdr.orig_len);

    const payload_start = @sizeOf(PcapGlobalHeader) + @sizeOf(PcapPacketHeader);
    try std.testing.expectEqualSlices(u8, &fake_frame, contents[payload_start..]);
}
