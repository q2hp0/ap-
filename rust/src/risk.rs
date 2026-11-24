use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct RiskState {
    pub score: u32,
    pub last_ns: u64,
    pub events: u32,
}

pub struct Risk {
    states: HashMap<i64, RiskState>,
    max_states: usize,
    window_ns: u64,
}

impl Risk {
    pub fn new(max_states: usize, window_ns: u64) -> Self {
        Self {
            states: HashMap::new(),
            max_states,
            window_ns,
        }
    }

    pub fn score(&self, pid: i64) -> u32 {
        self.states.get(&pid).map(|s| s.score).unwrap_or(0)
    }

    pub fn update(&mut self, pid: i64, severity: u32, confidence: u32, now_ns: u64) -> (u32, bool) {
        if self.max_states == 0 {
            return (0, false);
        }
        let weight: u32 = match severity {
            0 => 1,
            1 => 3,
            2 => 8,
            3 => 18,
            _ => 35,
        };
        let gain = (weight * confidence.min(1000) / 1000).max(1);
        let state = self.states.entry(pid).or_insert_with(|| RiskState {
            score: 0,
            last_ns: now_ns,
            events: 0,
        });
        if now_ns >= state.last_ns && self.window_ns > 0 {
            let steps = (now_ns - state.last_ns) / self.window_ns;
            if steps > 0 {
                let decay = steps.saturating_mul(5).min(u32::MAX as u64) as u32;
                state.score = state.score.saturating_sub(decay);
            }
        }
        let before = state.score;
        state.score = state.score.saturating_add(gain).min(100);
        state.last_ns = now_ns;
        state.events = state.events.saturating_add(1);
        let crossed = before < 60 && state.score >= 60;
        (state.score, crossed)
    }

    pub fn evict_if_needed(&mut self, pid: i64) {
        let target = if self.states.contains_key(&pid) {
            self.max_states
        } else {
            self.max_states.saturating_sub(1)
        };
        while self.states.len() > target {
            let oldest = self
                .states
                .iter()
                .filter(|(key, _)| **key != pid)
                .min_by_key(|(_, state)| state.last_ns)
                .map(|(key, _)| *key)
                .or_else(|| {
                    self.states
                        .iter()
                        .min_by_key(|(_, state)| state.last_ns)
                        .map(|(key, _)| *key)
                });
            match oldest {
                Some(key) => {
                    self.states.remove(&key);
                }
                None => break,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_and_flags_threshold() {
        let mut risk = Risk::new(8, 1_000_000_000);
        assert_eq!(risk.update(7, 3, 1000, 100).1, false);
        let (score, crossed) = risk.update(7, 4, 1000, 200);
        assert_eq!(score, 53);
        assert_eq!(crossed, false);
        let (score, crossed) = risk.update(7, 3, 1000, 300);
        assert!(score >= 60);
        assert!(crossed);
    }

    #[test]
    fn huge_time_gap_does_not_overflow() {
        let mut risk = Risk::new(4, 1);
        risk.update(1, 4, 1000, 0);
        let (score, _) = risk.update(1, 4, 1000, u64::MAX);
        assert!(score <= 100);
    }

    #[test]
    fn evicts_when_already_over_cap() {
        let mut risk = Risk::new(2, 1000);
        for pid in 1..5 {
            risk.update(pid, 3, 1000, 100 + pid as u64);
        }
        assert!(risk.len() > 2);
        risk.evict_if_needed(9);
        assert!(risk.len() <= 2);
    }

    #[test]
    fn decays_and_evicts() {
        let mut risk = Risk::new(2, 1000);
        risk.update(1, 4, 1000, 10);
        risk.update(2, 4, 1000, 20);
        risk.evict_if_needed(3);
        risk.update(3, 4, 1000, 30);
        assert_eq!(risk.len(), 2);
        let before = risk.score(3);
        risk.update(3, 0, 100, 6000);
        assert!(risk.score(3) < before);
    }
}
