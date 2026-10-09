//! SHA-256 for code signatures: the ARMv8 and x86 SHA extensions when present, portable otherwise.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The SHA-256 digests of two equally long messages, computed together: on CPUs with SHA
/// instructions the two dependency chains overlap, nearly doubling throughput.
pub fn digest2(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
    debug_assert_eq!(a.len(), b.len());
    #[cfg(target_arch = "aarch64")]
    {
        if a.len().is_multiple_of(64)
            && a.len() == b.len()
            && std::arch::is_aarch64_feature_detected!("sha2")
        {
            let (mut sa, mut sb) = (H0, H0);
            // SAFETY: the CPU supports the SHA2 instructions.
            unsafe { arm::compress2(&mut sa, &mut sb, a, b) };
            let mut ta = [0u8; 64];
            let mut tb = [0u8; 64];
            ta[0] = 0x80;
            tb[0] = 0x80;
            ta[56..].copy_from_slice(&((a.len() as u64) * 8).to_be_bytes());
            tb[56..].copy_from_slice(&((b.len() as u64) * 8).to_be_bytes());
            unsafe { arm::compress2(&mut sa, &mut sb, &ta, &tb) };
            return (words(sa), words(sb));
        }
    }
    (digest(a), digest(b))
}

fn words(state: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// The SHA-256 digest of `data`.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let full = data.len() / 64 * 64;
    compress(&mut state, &data[..full]);
    let rest = &data[full..];
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let n = if rest.len() < 56 { 64 } else { 128 };
    tail[n - 8..n].copy_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    compress(&mut state, &tail[..n]);
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    if blocks.is_empty() {
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha2") {
            // SAFETY: the CPU supports the SHA2 instructions.
            unsafe { arm::compress(state, blocks) };
            return;
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
        {
            // SAFETY: the CPU supports the SHA extensions and SSE4.1.
            unsafe { x86::compress(state, blocks) };
            return;
        }
    }
    portable(state, blocks);
}

fn portable(state: &mut [u32; 8], blocks: &[u8]) {
    for block in blocks.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use std::arch::aarch64::*;

    /// Two block sequences at once, fully unrolled, their rounds interleaved.
    #[target_feature(enable = "sha2")]
    #[allow(unused_assignments)]
    pub unsafe fn compress2(sa: &mut [u32; 8], sb: &mut [u32; 8], a: &[u8], b: &[u8]) {
        unsafe {
            let k: [uint32x4_t; 16] =
                std::array::from_fn(|r| vld1q_u32(super::K.as_ptr().add(r * 4)));
            let mut a0 = vld1q_u32(sa.as_ptr());
            let mut a1 = vld1q_u32(sa.as_ptr().add(4));
            let mut b0 = vld1q_u32(sb.as_ptr());
            let mut b1 = vld1q_u32(sb.as_ptr().add(4));
            for (ba, bb) in a.as_chunks::<64>().0.iter().zip(b.as_chunks::<64>().0) {
                let (sa0, sa1, sb0, sb1) = (a0, a1, b0, b1);
                let load =
                    |p: *const u8, o: usize| vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(o))));
                let (pa, pb) = (ba.as_ptr(), bb.as_ptr());
                let mut ma = [load(pa, 0), load(pa, 16), load(pa, 32), load(pa, 48)];
                let mut mb = [load(pb, 0), load(pb, 16), load(pb, 32), load(pb, 48)];
                macro_rules! round {
                    ($r:expr) => {{
                        let wa = vaddq_u32(ma[$r % 4], k[$r]);
                        let wb = vaddq_u32(mb[$r % 4], k[$r]);
                        let pa0 = a0;
                        let pb0 = b0;
                        a0 = vsha256hq_u32(a0, a1, wa);
                        b0 = vsha256hq_u32(b0, b1, wb);
                        a1 = vsha256h2q_u32(a1, pa0, wa);
                        b1 = vsha256h2q_u32(b1, pb0, wb);
                        if $r < 12 {
                            ma[$r % 4] = vsha256su1q_u32(
                                vsha256su0q_u32(ma[$r % 4], ma[($r + 1) % 4]),
                                ma[($r + 2) % 4],
                                ma[($r + 3) % 4],
                            );
                            mb[$r % 4] = vsha256su1q_u32(
                                vsha256su0q_u32(mb[$r % 4], mb[($r + 1) % 4]),
                                mb[($r + 2) % 4],
                                mb[($r + 3) % 4],
                            );
                        }
                    }};
                }
                round!(0);
                round!(1);
                round!(2);
                round!(3);
                round!(4);
                round!(5);
                round!(6);
                round!(7);
                round!(8);
                round!(9);
                round!(10);
                round!(11);
                round!(12);
                round!(13);
                round!(14);
                round!(15);
                a0 = vaddq_u32(a0, sa0);
                a1 = vaddq_u32(a1, sa1);
                b0 = vaddq_u32(b0, sb0);
                b1 = vaddq_u32(b1, sb1);
            }
            vst1q_u32(sa.as_mut_ptr(), a0);
            vst1q_u32(sa.as_mut_ptr().add(4), a1);
            vst1q_u32(sb.as_mut_ptr(), b0);
            vst1q_u32(sb.as_mut_ptr().add(4), b1);
        }
    }

    #[target_feature(enable = "sha2")]
    pub unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut efgh = vld1q_u32(state.as_ptr().add(4));
            for block in blocks.as_chunks::<64>().0 {
                let (abcd0, efgh0) = (abcd, efgh);
                let p = block.as_ptr();
                let mut m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
                let mut m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16))));
                let mut m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32))));
                let mut m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48))));
                for r in 0..16 {
                    let k = vld1q_u32(super::K.as_ptr().add(r * 4));
                    let wk = vaddq_u32(m0, k);
                    let prev = abcd;
                    abcd = vsha256hq_u32(abcd, efgh, wk);
                    efgh = vsha256h2q_u32(efgh, prev, wk);
                    if r < 12 {
                        let next = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3);
                        m0 = m1;
                        m1 = m2;
                        m2 = m3;
                        m3 = next;
                    } else {
                        m0 = m1;
                        m1 = m2;
                        m2 = m3;
                    }
                }
                abcd = vaddq_u32(abcd, abcd0);
                efgh = vaddq_u32(efgh, efgh0);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            vst1q_u32(state.as_mut_ptr().add(4), efgh);
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use std::arch::x86_64::*;

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
        unsafe {
            let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
            let tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i);
            let mut s1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);
            let tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
            s1 = _mm_shuffle_epi32(s1, 0x1B); // EFGH
            let mut s0 = _mm_alignr_epi8(tmp, s1, 8); // ABEF
            s1 = _mm_blend_epi16(s1, tmp, 0xF0); // CDGH
            for block in blocks.chunks_exact(64) {
                let (a0, c0) = (s0, s1);
                let p = block.as_ptr() as *const __m128i;
                let mut w = [
                    _mm_shuffle_epi8(_mm_loadu_si128(p), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(p.add(1)), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(p.add(2)), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(p.add(3)), mask),
                ];
                for r in 0..16 {
                    let k = _mm_loadu_si128(super::K.as_ptr().add(r * 4) as *const __m128i);
                    let m = _mm_add_epi32(w[r % 4], k);
                    s1 = _mm_sha256rnds2_epu32(s1, s0, m);
                    s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(m, 0x0E));
                    if r < 12 {
                        let t = _mm_alignr_epi8(w[(r + 3) % 4], w[(r + 2) % 4], 4);
                        let x = _mm_add_epi32(_mm_sha256msg1_epu32(w[r % 4], w[(r + 1) % 4]), t);
                        w[r % 4] = _mm_sha256msg2_epu32(x, w[(r + 3) % 4]);
                    }
                }
                s0 = _mm_add_epi32(s0, a0);
                s1 = _mm_add_epi32(s1, c0);
            }
            let tmp = _mm_shuffle_epi32(s0, 0x1B); // FEBA
            s1 = _mm_shuffle_epi32(s1, 0xB1); // DCHG
            let a = _mm_blend_epi16(tmp, s1, 0xF0); // DCBA
            let b = _mm_alignr_epi8(s1, tmp, 8); // ABEF → HGFE
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, a);
            _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: [u8; 32]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_digests() {
        assert_eq!(
            hex(digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn two_at_a_time_matches() {
        let a: Vec<u8> = (0..4096u32).map(|i| (i * 13) as u8).collect();
        let b: Vec<u8> = (0..4096u32).map(|i| (i * 31 + 5) as u8).collect();
        assert_eq!(digest2(&a, &b), (digest(&a), digest(&b)));
        assert_eq!(
            digest2(&a[..64], &b[..64]),
            (digest(&a[..64]), digest(&b[..64]))
        );
    }

    #[test]
    fn accelerated_matches_portable() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0, 1, 55, 56, 63, 64, 65, 4096, 9999] {
            let blocks = &data[..len / 64 * 64];
            let mut a = H0;
            let mut b = H0;
            compress(&mut a, blocks);
            portable(&mut b, blocks);
            assert_eq!(a, b, "len {len}");
        }
    }
}

#[cfg(test)]
mod bench {
    #[test]
    #[ignore]
    fn throughput() {
        let data = vec![7u8; 64 << 20];
        let t = std::time::Instant::now();
        let mut x = 0u8;
        for c in data.chunks(4096) {
            x ^= super::digest(c)[0];
        }
        let s = t.elapsed().as_secs_f64();
        eprintln!("sha256: {:.2} GB/s ({x})", 64.0 / 1024.0 / s);
        let t = std::time::Instant::now();
        for c in data.chunks(8192) {
            let (a, b) = super::digest2(&c[..4096], &c[4096..]);
            x ^= a[0] ^ b[0];
        }
        let s = t.elapsed().as_secs_f64();
        eprintln!("sha256 x2: {:.2} GB/s ({x})", 64.0 / 1024.0 / s);
    }
}
