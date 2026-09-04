#![cfg(feature = "tier2-bonsol")]

use serde_json::Value;
use serial_test::serial;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

const STATUS_CU_BASELINE: u64 = 145_339;
const STATUS_CU_TOLERANCE: u64 = STATUS_CU_BASELINE / 10;
const RPC_PORT: &str = "38899";
const WS_PORT: &str = "38900";
const IMAGE_SERVER_PORT: &str = "38080";

#[test]
#[serial]
fn tier2_aggregate_full_happy() {
    let stack = Tier2Stack::start();
    let result = stack.run_callback_mode("settle");

    assert_eq!(result["status"], "success");
    assert_nonempty_str(&result, "markerPda");
    assert_nonempty_str(&result, "aggregateJob");
    assert_nonempty_str(&result, "executionAccount");
    assert_nonempty_str(&result, "statusSignature");
    assert_nonempty_str(&result, "settleSignature");
    assert_status_cu_within_baseline(&result);
    assert!(result["settleComputeUnits"].as_u64().is_some());
}

#[test]
#[serial]
fn tier2_callback_runtime_error_fatal() {
    let stack = Tier2Stack::start();
    let result = stack.run_callback_mode("n1-callback-error");

    assert_eq!(result["status"], "status_failed_as_observed");
    assert_eq!(result["statusFailureObserved"], true);
    assert_nonempty_str(&result, "markerPda");
    assert_nonempty_str(&result, "executionAccount");
    assert_nonempty_str(&result, "statusSignature");
    assert_status_cu_within_baseline(&result);
    assert!(
        result["statusError"].is_object(),
        "missing statusError in {result}"
    );
}

#[test]
#[serial]
fn tier2_marker_pda_seeds_bind() {
    let stack = Tier2Stack::start();
    let result = stack.run_callback_mode("n3-wrong-execution-account");

    assert_eq!(result["status"], "success");
    assert_nonempty_str(&result, "markerPda");
    assert_nonempty_str(&result, "statusSignature");
    assert_status_cu_within_baseline(&result);
    let replay = stack.read_runtime_json(result["replayResultPath"].as_str().unwrap());
    assert_eq!(replay["mode"], "wrong-execution-account");
    assert_eq!(replay["accepted"], false);
}

#[test]
#[serial]
fn tier2_replay_after_cleanup_rejected() {
    let stack = Tier2Stack::start();
    let result = stack.run_callback_mode("n6-replay-after-cleanup");

    assert_eq!(result["status"], "success");
    assert_nonempty_str(&result, "markerPda");
    assert_nonempty_str(&result, "statusSignature");
    assert_status_cu_within_baseline(&result);
    let replay = stack.read_runtime_json(result["replayResultPath"].as_str().unwrap());
    assert_eq!(replay["mode"], "replay");
    assert_eq!(replay["accepted"], false);
}

#[test]
#[serial]
fn tier2_wrong_image_id_at_execute() {
    let stack = Tier2Stack::start();
    let result = stack.run_callback_mode("n2-wrong-image-id");

    assert_eq!(result["status"], "execute_failed_as_expected");
    assert_nonempty_str(&result, "imageId");
    assert_nonempty_str(&result, "executionId");
    assert!(result["error"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
}

struct Tier2Stack {
    repo_root: PathBuf,
    runtime_dir: PathBuf,
}

impl Tier2Stack {
    fn start() -> Self {
        let repo_root = repo_root();
        let runtime_dir = artifact_runtime_dir(&repo_root);
        compose_down(&repo_root, &runtime_dir);

        let output = compose_command(&repo_root, &runtime_dir)
            .args([
                "up",
                "-d",
                "--no-deps",
                "bonsol-validator",
                "bonsol-image-server",
                "bonsol-node",
            ])
            .output()
            .expect("start Bonsol compose stack");
        assert_success(output, "docker compose up");
        wait_for_container_health("kswarm-bonsol-validator", Duration::from_secs(180));
        wait_for_container_health("kswarm-bonsol-image-server", Duration::from_secs(180));
        wait_for_container_health("kswarm-bonsol-node", Duration::from_secs(180));

        Self {
            repo_root,
            runtime_dir,
        }
    }

    fn run_callback_mode(&self, mode: &str) -> Value {
        let output = compose_command(&self.repo_root, &self.runtime_dir)
            .args([
                "--profile",
                "callback-test",
                "run",
                "--rm",
                "--no-deps",
                "-e",
                &format!("PHASE0_CALLBACK_TEST_MODE={mode}"),
                "-e",
                "PHASE0_CALLBACK_EXECUTE_TIMEOUT=1200",
                "-e",
                "PHASE0_CALLBACK_EXPECTED_FAILURE_TIMEOUT=300",
                "bonsol-callback-smoke-test",
            ])
            .output()
            .unwrap_or_else(|err| panic!("run Bonsol callback mode {mode}: {err}"));
        assert_success(output, &format!("bonsol callback mode {mode}"))
    }

    fn read_runtime_json(&self, container_path: &str) -> Value {
        let relative = container_path
            .strip_prefix("/runtime/bonsol/")
            .unwrap_or(container_path);
        let path = self.runtime_dir.join(relative);
        serde_json::from_slice(
            &fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display())),
        )
        .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
    }
}

impl Drop for Tier2Stack {
    fn drop(&mut self) {
        compose_down(&self.repo_root, &self.runtime_dir);
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn artifact_runtime_dir(repo_root: &Path) -> PathBuf {
    if let Ok(dir) = env::var("BONSOL_RUNTIME_HOST_DIR") {
        let dir = PathBuf::from(dir);
        assert_artifacts_present(&dir);
        return dir;
    }

    let fresh_dir = PathBuf::from("/tmp/kswarm-bonsol-phase0b-fresh");
    if artifacts_present(&fresh_dir) {
        return fresh_dir;
    }
    if fresh_dir.exists() {
        build_bonsol_artifacts(repo_root, &fresh_dir);
        assert_artifacts_present(&fresh_dir);
        return fresh_dir;
    }

    let legacy_dir = PathBuf::from("/tmp/kswarm-bonsol-phase0b");
    if artifacts_present(&legacy_dir) {
        return legacy_dir;
    }

    let dir = PathBuf::from("/tmp/kswarm-bonsol-phase0c-runtime");
    build_bonsol_artifacts(repo_root, &dir);
    assert_artifacts_present(&dir);
    dir
}

fn build_bonsol_artifacts(repo_root: &Path, runtime_dir: &Path) {
    fs::create_dir_all(runtime_dir).expect("create Bonsol runtime dir");
    compose_down(repo_root, runtime_dir);
    let output = compose_command(repo_root, runtime_dir)
        .args([
            "run",
            "--rm",
            "-e",
            "BONSOL_BUILDER_KEEPALIVE=0",
            "bonsol-builder",
        ])
        .output()
        .expect("run Bonsol builder");
    assert_success(output, "bonsol-builder");
}

fn artifacts_present(dir: &Path) -> bool {
    [
        "ready",
        "bonsol.so",
        "callback_example.so",
        "kswarm_protocol.so",
        "bonsol-callback-harness",
        "reducer-manifest.json",
        "client-keypair.json",
        "node-keypair.json",
    ]
    .iter()
    .all(|file| dir.join(file).is_file())
}

fn assert_artifacts_present(dir: &Path) {
    assert!(
        artifacts_present(dir),
        "Bonsol runtime dir is incomplete: {}",
        dir.display()
    );
}

fn compose_command(repo_root: &Path, runtime_dir: &Path) -> Command {
    let mut command = Command::new("docker");
    command
        .current_dir(repo_root)
        .env("BONSOL_RUNTIME_HOST_DIR", runtime_dir)
        .env("BONSOL_VALIDATOR_RPC_PORT", RPC_PORT)
        .env("BONSOL_VALIDATOR_WS_PORT", WS_PORT)
        .env("BONSOL_IMAGE_SERVER_PORT", IMAGE_SERVER_PORT)
        .args(["compose", "-f", "docker-compose.bonsol.yml"]);
    command
}

fn compose_down(repo_root: &Path, runtime_dir: &Path) {
    let _ = compose_command(repo_root, runtime_dir)
        .args(["down", "-v", "--remove-orphans"])
        .output();
}

fn wait_for_container_health(container: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let output = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                container,
            ])
            .output()
            .unwrap_or_else(|err| panic!("inspect {container}: {err}"));
        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if output.status.success() && (status == "healthy" || status == "running") {
            return;
        }
        if Instant::now() >= deadline {
            panic!("container {container} did not become healthy; last status: {status}");
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn assert_success(output: Output, label: &str) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        panic!(
            "{label} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }

    if let Some(value) = parse_last_json_object(&stdout) {
        println!("{label}: {}", serde_json::to_string(&value).unwrap());
        value
    } else {
        println!("{label} stdout:\n{stdout}");
        Value::Null
    }
}

fn parse_last_json_object(stdout: &str) -> Option<Value> {
    for (idx, _) in stdout.match_indices('{').rev() {
        if let Ok(value) = serde_json::from_str::<Value>(&stdout[idx..]) {
            return Some(value);
        }
    }
    None
}

fn assert_nonempty_str(value: &Value, key: &str) {
    assert!(
        value[key]
            .as_str()
            .is_some_and(|text| !text.is_empty() && text != "null"),
        "missing {key} in {value}"
    );
}

fn assert_status_cu_within_baseline(value: &Value) {
    let cu = value["statusComputeUnits"]
        .as_u64()
        .expect("statusComputeUnits");
    assert!(
        cu.abs_diff(STATUS_CU_BASELINE) <= STATUS_CU_TOLERANCE,
        "StatusV1 CU {cu} outside {STATUS_CU_BASELINE} +/- {STATUS_CU_TOLERANCE}"
    );
}
