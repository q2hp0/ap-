use crate::abi::*;
use crate::detect::{detect, Analyzers};
use crate::event::{normalize, rule_name, validate, Finding};
use crate::guard::Guard;
use crate::policy::Policy;
use crate::risk::Risk;
use crate::store::Store;
use std::fs;
use std::path::Path;

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xd1b54a32d192ed03 } else { seed },
        }
    }

    fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

fn random_event(rng: &mut Rng, seq: u64) -> Event {
    let kind = rng.below(14) as u16;
    let mut event = Event::new(
        kind,
        seq,
        rng.next(),
        (rng.below(128) as i64) - 64,
    );
    event.tid = (rng.below(128) as i64) - 64;
    event.subkind = rng.below(32) as u32;
    event.severity = rng.below(8) as u32;
    event.confidence_x1000 = rng.below(1200) as u32;
    for i in 0..4 {
        event.arg[i] = rng.next();
    }
    for item in event.text.iter_mut() {
        *item = rng.next() as u8;
    }
    if rng.below(4) != 0 {
        let pos = rng.below(TEXT_LEN as u64) as usize;
        event.text[pos] = 0;
    }
    event
}

fn finding(rule: u32, confidence: u32) -> Finding {
    Finding {
        rule,
        rule_name: rule_name(rule),
        source: "test",
        severity: SEV_HIGH,
        confidence,
        evidence: 1,
        detail: "adversarial".to_string(),
        decision: DECISION_ALLOW,
    }
}

#[test]
fn fuzz_validation_detection_risk_guard_bounds() {
    let mut analyzers = Analyzers::new().unwrap();
    let mut risk = Risk::new(64, 5_000_000_000);
    let mut monitor = Guard::new(16);
    let monitor_policy = Policy::default();

    let mut hard_policy = Policy::default();
    hard_policy.guard_mode = true;
    hard_policy.alert_threshold = 0;
    hard_policy.min_confidence = 0;
    hard_policy.deny_rules = (1..=RULE_MAX).collect();
    let mut hard_guard = Guard::new(16);

    for seed in [0x5eed_1234_5678_9abc, 0xdead_beef_cafe_1234, 0x0bad_f00d_1234_5678] {
        let mut rng = Rng::new(seed);
        for seq in 1..=10_000u64 {
            let event = random_event(&mut rng, seq);
            if validate(&event).is_err() {
                continue;
            }
            let now = event.ts_ns;
            let item = normalize(&event, now).unwrap();
            assert!(item.severity_code <= SEV_CRITICAL);
            assert!(item.confidence <= 1000);

            let findings = detect(&event, &mut analyzers);
            assert!(findings.len() <= 4);
            for found in &findings {
                assert!(found.rule <= RULE_MAX);
                assert!(found.confidence <= 1000);
                assert_ne!(rule_name(found.rule), "unknown");
            }

            let (score, _) = risk.update(event.pid, item.severity_code, item.confidence, now);
            risk.evict_if_needed(event.pid.wrapping_add(1));
            assert!(risk.len() <= 64);

            let monitor_decision = monitor.apply(&monitor_policy, &findings, score);
            assert!(matches!(monitor_decision, DECISION_ALLOW));
            let hard_decision = hard_guard.apply(&hard_policy, &findings, score);
            assert!(matches!(hard_decision, DECISION_ALLOW | DECISION_DENY | DECISION_STOP));
            assert!(hard_guard.audit().len() <= 16);
        }
    }

    let (net, flow, intrusion) = analyzers.counters();
    assert!(net.findings <= 30_000);
    assert!(flow.findings <= 30_000);
    assert!(intrusion.findings <= 30_000);
    assert!(monitor.stats.alerts <= 30_000);
    assert!(hard_guard.stats.denials + hard_guard.stats.stops <= 30_000);
}

#[test]
fn slow_drip_cannot_cross_risk_threshold() {
    let mut risk = Risk::new(8, 5_000_000_000);
    let mut crossed = false;
    for i in 0..40u64 {
        let (_, did_cross) = risk.update(7, SEV_LOW, 1000, i * 6_000_000_000);
        crossed |= did_cross;
    }
    assert!(!crossed);
    assert!(risk.score(7) <= 3);

    let mut rapid = Risk::new(8, 5_000_000_000);
    let mut rapid_crossed = false;
    for i in 0..25u64 {
        let (_, did_cross) = rapid.update(9, SEV_LOW, 1000, 100 + i);
        rapid_crossed |= did_cross;
    }
    assert!(rapid_crossed);
}

#[test]
fn guard_fails_closed_on_every_missing_condition() {
    let strong = finding(RULE_WX_TRANSITION, 950);
    let weak = finding(RULE_WX_TRANSITION, 250);

    let mut policy = Policy::default();
    let mut guard = Guard::new(8);
    assert_eq!(guard.apply(&policy, &[strong.clone()], 100), DECISION_ALLOW);

    policy.guard_mode = true;
    assert_eq!(guard.apply(&policy, &[strong.clone()], 100), DECISION_ALLOW);

    policy.deny_rules.push(RULE_WX_TRANSITION);
    assert_eq!(guard.apply(&policy, &[strong.clone()], 10), DECISION_ALLOW);

    policy.alert_threshold = 10;
    assert_eq!(guard.apply(&policy, &[weak], 100), DECISION_ALLOW);

    assert_eq!(guard.apply(&policy, &[strong], 100), DECISION_DENY);
}

#[test]
fn store_rotation_survives_finding_flood() {
    let dir = std::env::temp_dir().join(format!("ap-adversarial-store-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("flood.jsonl");
    let mut store = Store::open(Path::new(&path), 4096);
    for i in 0..500 {
        store.append(&format!("{{\"rule\":\"wx_transition\",\"n\":{}}}", i));
    }
    assert_eq!(store.records, 500);
    assert!(store.rotations > 0);
    assert!(dir.join("flood.1.jsonl").exists());
    let _ = fs::remove_dir_all(&dir);
}
