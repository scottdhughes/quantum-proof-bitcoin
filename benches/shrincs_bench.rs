use criterion::{Criterion, criterion_group, criterion_main};
use qpb_consensus::shrincs_proto::hybrid;

fn bench_sign_verify(c: &mut Criterion) {
    let kp = hybrid::keygen();
    let msg = [0u8; 32];
    c.bench_function("shrincs_proto_sign_stateful", |b| {
        b.iter(|| hybrid::sign(&msg, &kp, 1, false))
    });
    let sig = hybrid::sign(&msg, &kp, 1, false);
    c.bench_function("shrincs_proto_verify_stateful", |b| {
        b.iter(|| hybrid::verify(&msg, &kp.pk, &sig, 1))
    });
    c.bench_function("shrincs_proto_sign_fallback", |b| {
        b.iter(|| hybrid::sign(&msg, &kp, 0, true))
    });
    let sig_fb = hybrid::sign(&msg, &kp, 0, true);
    c.bench_function("shrincs_proto_verify_fallback", |b| {
        b.iter(|| hybrid::verify(&msg, &kp.pk, &sig_fb, 0))
    });
}

fn bench_sweeps(c: &mut Criterion) {
    let msg = [0u8; 32];
    for q in 1u32..=10 {
        let kp = hybrid::keygen();
        let sig = hybrid::sign(&msg, &kp, q, false);
        c.bench_function(&format!("shrincs_sign_q{}", q), |b| {
            b.iter(|| hybrid::sign(&msg, &kp, q, false))
        });
        c.bench_function(&format!("shrincs_verify_q{}", q), |b| {
            b.iter(|| hybrid::verify(&msg, &kp.pk, &sig, q))
        });
        for pad in (0usize..=192).step_by(16) {
            let label = format!("shrincs_sign_q{}_pad{}", q, pad);
            c.bench_function(&label, |b| {
                b.iter(|| {
                    let mut s = hybrid::sign(&msg, &kp, q, false);
                    s.extend(std::iter::repeat(0u8).take(pad));
                    s
                })
            });
        }
    }
}

criterion_group!(benches, bench_sign_verify, bench_sweeps);
criterion_main!(benches);
