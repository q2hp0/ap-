use crate::abi::ABI_VERSION;
use crate::event::{Finding, Normalized};
use std::io::{self, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct Cli {
    color: bool,
    verbose: bool,
    max_rate: u32,
    window: Instant,
    window_count: u32,
    pub dropped: u64,
    pub printed: u64,
}

pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}z", now.as_secs(), now.subsec_millis())
}

impl Cli {
    pub fn new(json_only: bool, verbose: bool, max_rate: u32) -> Self {
        if !json_only {
            print!("\x1b[2j\x1b[h\x1b[40m\x1b[37m");
            let _ = io::stdout().flush();
        }
        Self {
            color: !json_only,
            verbose,
            max_rate: max_rate.max(1),
            window: Instant::now(),
            window_count: 0,
            dropped: 0,
            printed: 0,
        }
    }

    fn emit(&self, body: &str) {
        if self.color {
            println!("\x1b[40m\x1b[37m{}\x1b[0m", body);
        } else {
            println!("{}", body);
        }
        let _ = io::stdout().flush();
    }

    pub fn startup(&self, mode: &str, caps: i32, self_hardened: bool) {
        self.emit(&format!(
            "{{\n  \"ap\": {{\n    \"state\": \"active\",\n    \"mode\": \"{}\",\n    \"engine\": \"running\",\n    \"abi\": {},\n    \"caps\": {},\n    \"self_hardened\": {}\n  }}\n}}",
            escape(mode), ABI_VERSION, caps, self_hardened
        ));
    }

    pub fn shutdown(&self, reason: &str, events: u64, findings: u64) {
        self.emit(&format!(
            "{{\n  \"ap\": {{\n    \"state\": \"stopped\",\n    \"reason\": \"{}\",\n    \"events\": {},\n    \"findings\": {}\n  }}\n}}",
            escape(reason), events, findings
        ));
    }

    pub fn event(&mut self, item: &Normalized, findings: &[Finding], decision: i32, id: u64) {
        let important = item.severity_code >= 2 || !findings.is_empty();
        if !self.verbose && (!important || item.kind == "heartbeat") {
            return;
        }
        if self.window.elapsed().as_secs() >= 1 {
            self.window = Instant::now();
            self.window_count = 0;
        }
        if self.window_count >= self.max_rate {
            self.dropped += 1;
            return;
        }
        self.window_count += 1;
        self.printed += 1;
        let action = match decision {
            1 => "denied",
            2 => "isolated",
            _ if findings.is_empty() => "observed",
            _ => "investigating",
        };
        let rule = findings
            .first()
            .map(|f| format!(",\n    \"rule\": \"{}\"", escape(f.rule_name)))
            .unwrap_or_default();
        let names: Vec<String> = findings
            .iter()
            .map(|f| format!("\"{}\"", escape(f.rule_name)))
            .collect();
        let rules = if names.is_empty() {
            String::new()
        } else {
            format!(",\n    \"rules\": [{}]", names.join(", "))
        };
        self.emit(&format!(
            "{{\n  \"event\": {{\n    \"id\": \"{:016x}\",\n    \"ts\": \"{}\",\n    \"source\": \"{}\",\n    \"type\": \"{}\",\n    \"severity\": \"{}\",\n    \"confidence\": {:.2},\n    \"pid\": {},\n    \"action\": \"{}\"{}{}\n  }}\n}}",
            id,
            timestamp(),
            escape(item.source),
            escape(item.kind),
            item.severity,
            item.confidence as f64 / 1000.0,
            item.pid,
            action,
            rule,
            rules
        ));
    }

    pub fn status(&self, label: &str, values: &[(&str, String)]) {
        let mut fields = String::new();
        for (index, (key, value)) in values.iter().enumerate() {
            fields.push_str(&format!(
                "    \"{}\": {}{}\n",
                escape(key),
                value,
                if index + 1 == values.len() { "" } else { "," }
            ));
        }
        self.emit(&format!(
            "{{\n  \"{}\": {{\n{}  }}\n}}",
            escape(label), fields
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_handles_json_characters() {
        assert_eq!(escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn timestamp_is_stable() {
        let value = timestamp();
        assert!(value.ends_with('z'));
        assert!(value.contains('.'));
    }
}
