const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Ed25519 = crypto.sign.Ed25519;

export fn sodium_init() callconv(.c) c_int {
    return 0;
}

export fn sodium_memzero(pnt: [*c]u8, len: usize) callconv(.c) void {
    crypto.secureZero(u8, pnt[0..len]);
}

export fn randombytes_buf(pnt: [*c]u8, len: usize) callconv(.c) void {
    crypto.random.bytes(pnt[0..len]);
}

export fn sodium_malloc(len: usize) callconv(.c) ?*anyopaque {
    return std.c.malloc(len);
}

export fn sodium_free(pnt: ?*anyopaque) callconv(.c) void {
    return std.c.free(pnt);
}

export fn crypto_pwhash_scryptsalsa208sha256(
    out: [*c]u8,
    outlen: c_ulonglong,
    passwd: [*c]const u8,
    passwdlen: c_ulonglong,
    salt: [*c]const u8,
    opslimit: c_ulonglong,
    memlimit: usize,
) callconv(.c) c_int {
    crypto.pwhash.scrypt.kdf(
        std.heap.c_allocator,
        out[0..@intCast(outlen)],
        passwd[0..@intCast(passwdlen)],
        salt[0..32],
        crypto.pwhash.scrypt.Params.fromLimits(opslimit, memlimit),
    ) catch return -1;
    return 0;
}

const crypto_generichash_state = crypto.hash.blake2.Blake2b512;

export fn crypto_generichash_init(
    state: *crypto_generichash_state,
    _: [*c]const u8,
    _: usize,
    outlen: usize,
) c_int {
    state.* = crypto.hash.blake2.Blake2b512.init(.{ .expected_out_bits = outlen * 8 });
    return 0;
}

export fn crypto_generichash_update(
    state: *crypto_generichash_state,
    in: [*c]const u8,
    inlen: c_ulonglong,
) c_int {
    state.*.update(in[0..@intCast(inlen)]);
    return 0;
}

export fn crypto_generichash_final(
    state: *crypto_generichash_state,
    out: [*c]u8,
    outlen: usize,
) c_int {
    var h: [64]u8 = undefined;
    state.*.final(&h);
    @memcpy(out[0..outlen], h[0..outlen]);
    return 0;
}

export fn crypto_sign_keypair(pk: [*c]u8, sk: [*c]u8) callconv(.c) c_int {
    const kp = if (std.meta.hasFn(Ed25519.KeyPair, "generate")) Ed25519.KeyPair.generate() else (Ed25519.KeyPair.create(null) catch return -1);
    pk[0..32].* = kp.public_key.toBytes();
    sk[0..64].* = kp.secret_key.toBytes();
    return 0;
}

export fn crypto_sign_detached(
    sig_bytes: [*c]u8,
    _: [*c]c_ulonglong,
    m: [*c]const u8,
    mlen: c_ulonglong,
    sk_bytes: [*c]const u8,
) callconv(.c) c_int {
    const sk = Ed25519.SecretKey.fromBytes(sk_bytes[0..64].*) catch return -1;
    const kp = Ed25519.KeyPair.fromSecretKey(sk) catch return -1;
    var noise: [Ed25519.noise_length]u8 = undefined;
    crypto.random.bytes(&noise);
    const s = kp.sign(m[0..@intCast(mlen)], noise) catch return -1;
    sig_bytes[0..64].* = s.toBytes();
    return 0;
}

export fn crypto_sign_verify_detached(
    sig_bytes: [*c]const u8,
    m: [*c]const u8,
    mlen: c_ulonglong,
    pk_bytes: [*c]const u8,
) callconv(.c) c_int {
    const pk = Ed25519.PublicKey.fromBytes(pk_bytes[0..32].*) catch return -1;
    const sig = Ed25519.Signature.fromBytes(sig_bytes[0..64].*);
    sig.verify(m[0..@intCast(mlen)], pk) catch return 1;
    return 0;
}

export fn sodium_bin2hex(
    hex: [*c]u8,
    hex_maxlen: usize,
    bin: [*c]const u8,
    bin_len: usize,
) callconv(.c) [*c]u8 {
    _ = std.fmt.bufPrint(hex[0..hex_maxlen], "{x}", .{bin[0..bin_len]}) catch return null;
    return hex;
}
