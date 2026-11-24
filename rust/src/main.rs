use ap::engine::Engine;
use ap::ipc::Ipc;
use ap::policy::Policy;
use ap::policyfile;
use ap::store::Store;
use ap::update;
use std::path::Path;

fn takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "--verify-store"
            | "--policy"
            | "--seal-policy"
            | "--verify-policy"
            | "--seal-update"
            | "--verify-update"
            | "--stage-update"
            | "--install-update"
            | "--rollback-update"
            | "--activation-plan"
            | "--deny"
            | "--stop"
            | "--enable"
            | "--disable"
            | "--socket"
            | "--store"
            | "--threshold"
            | "--min-confidence"
            | "--max-states"
            | "--queue-depth"
            | "--max-events"
            | "--mask"
            | "--lsm-mask"
            | "--duration"
            | "--proc-interval-ms"
            | "--proc-max-pids"
            | "--proc-map-samples"
            | "--proc-wx-per-scan"
            | "--proc-io-per-scan"
            | "--correlate-window-ms"
            | "--capture-iface"
            | "--capture-file"
            | "--capture-snaplen"
            | "--kernel-events"
            | "--client-key"
            | "--audit-key"
            | "--audit-writer"
    )
}

fn mode_path(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--trace" {
            break;
        }
        if args[i] == flag {
            i += 1;
            return args
                .get(i)
                .cloned()
                .map(Some)
                .ok_or_else(|| format!("missing path after {}", flag));
        }
        if takes_value(&args[i]) {
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(None)
}

fn mode_two_paths(args: &[String], flag: &str) -> Result<Option<(String, String)>, String> {
    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--trace" {
            break;
        }
        if args[i] == flag {
            let first = args
                .get(i + 1)
                .cloned()
                .ok_or_else(|| format!("missing first path after {}", flag))?;
            let second = args
                .get(i + 2)
                .cloned()
                .ok_or_else(|| format!("missing second path after {}", flag))?;
            return Ok(Some((first, second)));
        }
        if takes_value(&args[i]) {
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(None)
}

fn strip_option(args: &[String], target: &str) -> Vec<String> {
    let mut out = vec![args.first().cloned().unwrap_or_else(|| "ap".to_string())];
    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--trace" {
            out.extend_from_slice(&args[i..]);
            break;
        }
        if args[i] == target {
            i += 2;
            continue;
        }
        out.push(args[i].clone());
        if takes_value(&args[i]) && i + 1 < args.len() {
            out.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn has_flag(args: &[String], flag: &str) -> bool {
    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--trace" {
            return false;
        }
        if args[i] == flag {
            return true;
        }
        if takes_value(&args[i]) {
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

fn print_help() {
    println!("ap [options] [--trace command args]");
    println!("options: --guard --deny rules --stop rules --enable rules --disable rules");
    println!("         --socket path --store path --threshold n --min-confidence n");
    println!("         --max-states n --queue-depth n --max-events n --mask n --duration ms");
    println!("         --proc-interval-ms n --proc-max-pids n --proc-map-samples n");
    println!("         --proc-wx-per-scan n --proc-io-per-scan n --no-proc-scan");
    println!("         --capture [--capture-iface name | --capture-file path] --capture-snaplen n");
    println!("         --kernel-events path --ipc-strict-seq");
    println!("         --kernel-sensor --lsm-enforce --lsm-mask n (hex or decimal)");
    println!("         --chain-guard (requires --guard and deny or stop rules)");
    println!("         --client-key pid:path (repeatable, at most 16)");
    println!("         --audit-process [--audit-key path]");
    println!("         --policy path --seal-policy path --verify-policy path --verify-store path");
    println!("         --seal-update manifest --verify-update manifest");
    println!("         --stage-update manifest destination");
    println!("         --install-update manifest root --rollback-update root");
    println!("         --activation-plan root [--require-approval]");
    println!("         --json --verbose --once --no-self-harden --no-fork --help");
    println!("rules: comma separated names, or all for --enable and --disable");
    println!("policy: ap_policy_v1 file with key=value lines and a final mac line");
    println!("update: ap_update_v1 manifest with file lines and a final mac line; local snapshots");
    println!("approval: --require-approval adds and checks a second local 0600 key");
}

fn merged_args(args: &[String]) -> Result<Vec<String>, String> {
    let path = mode_path(args, "--policy")?;
    let stripped = strip_option(args, "--policy");
    match path {
        Some(path) => {
            let mut merged = policyfile::load_args(Path::new(&path))
                .map_err(|message| format!("policy load failed: {}", message))?;
            for value in stripped.into_iter().skip(1) {
                merged.push(value);
            }
            Ok(merged)
        }
        None => Ok(stripped),
    }
}

fn update_options(args: &[String]) -> update::Options {
    update::Options {
        require_approval: has_flag(args, "--require-approval"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let writer_paths = match mode_two_paths(&args, "--audit-writer") {
        Ok(paths) => paths,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some((store, key)) = writer_paths {
        if let Err(message) = ap::audit::writer_loop(Path::new(&store), Path::new(&key)) {
            eprintln!("ap: audit writer failed: {}", message);
            std::process::exit(1);
        }
        return;
    }

    let audit_key = match mode_path(&args, "--audit-key") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };

    let store_path = match mode_path(&args, "--verify-store") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some(path) = store_path {
        let result = match audit_key {
            Some(ref key) => Store::verify_with_key(Path::new(&path), Path::new(key)),
            None => Store::verify(Path::new(&path)),
        };
        match result {
            Ok(records) => println!("{{\"verify\": {{\"state\": \"ok\", \"records\": {}}}}}", records),
            Err(message) => {
                eprintln!("ap: store verify failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let seal_path = match mode_path(&args, "--seal-policy") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some(path) = seal_path {
        match policyfile::seal(Path::new(&path)) {
            Ok(entries) => println!(
                "{{\"policy\": {{\"state\": \"sealed\", \"entries\": {}}}}}",
                entries
            ),
            Err(message) => {
                eprintln!("ap: policy seal failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let verify_path = match mode_path(&args, "--verify-policy") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some(path) = verify_path {
        match policyfile::verify(Path::new(&path)) {
            Ok(entries) => println!(
                "{{\"policy\": {{\"state\": \"ok\", \"entries\": {}}}}}",
                entries
            ),
            Err(message) => {
                eprintln!("ap: policy verify failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let seal_update_path = match mode_path(&args, "--seal-update") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some(path) = seal_update_path {
        match update::seal_with(Path::new(&path), update_options(&args)) {
            Ok(entries) => println!(
                "{{\"update\": {{\"state\": \"sealed\", \"entries\": {}}}}}",
                entries
            ),
            Err(message) => {
                eprintln!("ap: update seal failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let verify_update_path = match mode_path(&args, "--verify-update") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some(path) = verify_update_path {
        match update::verify_with(Path::new(&path), update_options(&args)) {
            Ok((entries, bytes)) => println!(
                "{{\"update\": {{\"state\": \"ok\", \"entries\": {}, \"bytes\": {}}}}}",
                entries, bytes
            ),
            Err(message) => {
                eprintln!("ap: update verify failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let stage_update_paths = match mode_two_paths(&args, "--stage-update") {
        Ok(paths) => paths,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some((manifest, destination)) = stage_update_paths {
        match update::stage_with(
            Path::new(&manifest),
            Path::new(&destination),
            update_options(&args),
        ) {
            Ok((entries, bytes)) => println!(
                "{{\"update\": {{\"state\": \"staged\", \"entries\": {}, \"bytes\": {}}}}}",
                entries, bytes
            ),
            Err(message) => {
                eprintln!("ap: update stage failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let install_update_paths = match mode_two_paths(&args, "--install-update") {
        Ok(paths) => paths,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some((manifest, root)) = install_update_paths {
        match update::install_with(Path::new(&manifest), Path::new(&root), update_options(&args)) {
            Ok((entries, bytes, release)) => println!(
                "{{\"update\": {{\"state\": \"installed\", \"entries\": {}, \"bytes\": {}, \"release\": \"{}\"}}}}",
                entries, bytes, release
            ),
            Err(message) => {
                eprintln!("ap: update install failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let rollback_update_path = match mode_path(&args, "--rollback-update") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some(root) = rollback_update_path {
        match update::rollback_with(Path::new(&root), update_options(&args)) {
            Ok(release) => println!(
                "{{\"update\": {{\"state\": \"rolled_back\", \"release\": \"{}\"}}}}",
                release
            ),
            Err(message) => {
                eprintln!("ap: update rollback failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    let activation_path = match mode_path(&args, "--activation-plan") {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    if let Some(root) = activation_path {
        match update::plan(Path::new(&root), update_options(&args)) {
            Ok(plan) => println!(
                "{{\"update\": {{\"state\": \"plan\", \"active\": \"{}\", \"previous\": \"{}\", \"integrity\": \"verified\", \"entries\": {}, \"bytes\": {}, \"executed\": false}}}}",
                plan.active,
                plan.previous.unwrap_or_else(|| "none".to_string()),
                plan.entries,
                plan.bytes
            ),
            Err(message) => {
                eprintln!("ap: update plan failed: {}", message);
                std::process::exit(1);
            }
        }
        return;
    }

    if has_flag(&args, "--help") {
        print_help();
        return;
    }

    let merged = match merged_args(&args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    let policy = match Policy::from_args(&merged) {
        Ok(policy) => policy,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(2);
        }
    };
    let client_keys = policy.client_keys.clone();
    let ipc = match Ipc::open_with_client_keys(
        &policy.socket_path,
        policy.ipc_strict_seq,
        &client_keys,
    ) {
        Ok(ipc) => Some(ipc),
        Err(message) => {
            eprintln!("ap: telemetry socket unavailable: {}", message);
            None
        }
    };
    let engine = match Engine::new(policy) {
        Ok(engine) => engine,
        Err(message) => {
            eprintln!("ap: {}", message);
            std::process::exit(1);
        }
    };
    if let Err(message) = engine.run(ipc) {
        eprintln!("ap: {}", message);
        std::process::exit(1);
    }
}
