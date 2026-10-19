//! In-app "Check for updates" (BRIEF §2, §9).
//!
//! The app has no network code. It can run exactly one thing: the
//! update-helper.sh bundled in its own Resources, with a fixed mode chosen
//! here (never by the webview). The helper uses git to fetch `master` and,
//! for an install, runs the local release script from a dedicated worktree.
//! This is the only module allowed to spawn processes (scripts/check-surface.sh).

use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Baked in by build.rs.
pub const COMMIT: &str = env!("LOCKBOX_GIT_SHA");
const DIRTY: &str = env!("LOCKBOX_GIT_DIRTY");
const REPO_DIR: &str = env!("LOCKBOX_REPO_DIR");
const BUILD_PATH: &str = env!("LOCKBOX_BUILD_PATH");

pub const HELPER: &str = "resources/update-helper.sh";

#[derive(Serialize)]
pub struct AppInfo {
    version: String,
    commit: String,
    dirty: bool,
}

pub fn app_info(version: String) -> AppInfo {
    AppInfo {
        version,
        commit: COMMIT.into(),
        dirty: DIRTY == "true",
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    UpToDate,
    Available,
    /// The installed build's commit isn't in the repo (e.g. built from an
    /// unpushed branch that was since deleted); offer master anyway.
    UnknownInstalled,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Commit {
    sha: String,
    subject: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    status: Status,
    installed: String,
    latest: String,
    commits: Vec<Commit>,
}

fn helper_command(helper: &Path) -> Command {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg(helper).env("PATH", BUILD_PATH).stdin(Stdio::null());
    cmd
}

pub fn check(helper: &Path) -> Result<CheckResult, String> {
    check_in(helper, Path::new(REPO_DIR), COMMIT)
}

fn check_in(helper: &Path, repo: &Path, installed: &str) -> Result<CheckResult, String> {
    let out = helper_command(helper)
        .args(["check".as_ref(), repo.as_os_str(), installed.as_ref()])
        .output()
        .map_err(|e| format!("could not run update helper: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("Update check failed: {}", last_lines(&err, 8)));
    }
    parse_check(&String::from_utf8_lossy(&out.stdout), installed)
}

fn parse_check(stdout: &str, installed: &str) -> Result<CheckResult, String> {
    let mut status = None;
    let mut latest = String::new();
    let mut commits = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("LATEST ") {
            latest = rest.trim().into();
        } else if let Some(rest) = line.strip_prefix("STATUS ") {
            status = Some(match rest.trim() {
                "up-to-date" => Status::UpToDate,
                "available" => Status::Available,
                "unknown-installed" => Status::UnknownInstalled,
                other => return Err(format!("unexpected helper status '{other}'")),
            });
        } else if let Some(rest) = line.strip_prefix("COMMIT ") {
            let (sha, subject) = rest.split_once(' ').unwrap_or((rest, ""));
            commits.push(Commit {
                sha: sha.into(),
                subject: subject.into(),
            });
        }
    }
    let status = status.ok_or("update helper gave no status")?;
    if latest.is_empty() {
        return Err("update helper gave no latest commit".into());
    }
    Ok(CheckResult {
        status,
        installed: installed.into(),
        latest,
        commits,
    })
}

pub fn log_path() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Logs/lockbox/update.log")
}

/// Runs the install to completion. On success the release script quits this
/// app and relaunches the new one, so in practice this only returns on error.
/// Output goes to a log file, not a pipe: the helper must outlive this
/// process, and writing to a pipe whose reader died would kill it.
pub fn install(helper: &Path) -> Result<(), String> {
    let log = log_path();
    if let Some(dir) = log.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("could not create log dir: {e}"))?;
    }
    let file = fs::File::create(&log).map_err(|e| format!("could not open update log: {e}"))?;
    let file2 = file
        .try_clone()
        .map_err(|e| format!("could not open update log: {e}"))?;

    use std::os::unix::process::CommandExt;
    let status = helper_command(helper)
        .args(["install".as_ref(), Path::new(REPO_DIR).as_os_str()])
        .stdout(file)
        .stderr(file2)
        // Own process group, so the helper isn't caught up in this app quitting.
        .process_group(0)
        .status()
        .map_err(|e| format!("could not run update helper: {e}"))?;
    if status.success() {
        return Ok(());
    }
    let tail = fs::read_to_string(&log).unwrap_or_default();
    Err(format!(
        "Update failed. Nothing was installed.\n\n{}\n\nFull log: {}",
        last_lines(&tail, 15),
        log.display()
    ))
}

fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.trim_end().lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(HELPER)
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().into()
    }

    /// A bare "remote" plus a clone of it whose origin points at the bare repo.
    fn repos() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let remote = tmp.path().join("remote.git");
        let clone = tmp.path().join("clone");
        git(tmp.path(), &["init", "-q", "--bare", "-b", "master", remote.to_str().unwrap()]);
        git(tmp.path(), &["clone", "-q", remote.to_str().unwrap(), clone.to_str().unwrap()]);
        git(&clone, &["checkout", "-q", "-b", "master"]);
        (tmp, remote, clone)
    }

    fn commit_and_push(clone: &Path, msg: &str) -> String {
        git(clone, &["commit", "-q", "--allow-empty", "-m", msg]);
        git(clone, &["push", "-q", "origin", "master"]);
        git(clone, &["rev-parse", "HEAD"])
    }

    #[test]
    fn check_reports_up_to_date() {
        let (_t, _remote, clone) = repos();
        let head = commit_and_push(&clone, "first");
        let r = check_in(&helper(), &clone, &head).unwrap();
        assert_eq!(r.status, Status::UpToDate);
        assert_eq!(r.latest, head);
        assert!(r.commits.is_empty());
    }

    #[test]
    fn check_lists_new_commits_on_master() {
        let (_t, _remote, clone) = repos();
        let installed = commit_and_push(&clone, "first");
        commit_and_push(&clone, "second");
        let latest = commit_and_push(&clone, "third: with spaces");
        git(&clone, &["reset", "-q", "--hard", &installed]);

        let r = check_in(&helper(), &clone, &installed).unwrap();
        assert_eq!(r.status, Status::Available);
        assert_eq!(r.latest, latest);
        let subjects: Vec<_> = r.commits.iter().map(|c| c.subject.as_str()).collect();
        assert_eq!(subjects, ["third: with spaces", "second"]);
    }

    #[test]
    fn check_handles_unknown_installed_commit() {
        let (_t, _remote, clone) = repos();
        commit_and_push(&clone, "first");
        let r = check_in(&helper(), &clone, &"0".repeat(40)).unwrap();
        assert_eq!(r.status, Status::UnknownInstalled);
        assert_eq!(r.commits.len(), 1);
    }

    #[test]
    fn installed_ahead_of_master_is_up_to_date() {
        // A dev build from a feature branch that master hasn't caught up with.
        let (_t, _remote, clone) = repos();
        commit_and_push(&clone, "first");
        git(&clone, &["commit", "-q", "--allow-empty", "-m", "unmerged work"]);
        let head = git(&clone, &["rev-parse", "HEAD"]);
        assert_eq!(check_in(&helper(), &clone, &head).unwrap().status, Status::UpToDate);
    }

    #[test]
    fn merge_commit_alone_is_up_to_date() {
        // master merges a develop the installed build already contains.
        let (_t, _remote, clone) = repos();
        commit_and_push(&clone, "first");
        git(&clone, &["checkout", "-q", "-b", "develop"]);
        git(&clone, &["commit", "-q", "--allow-empty", "-m", "feature"]);
        let installed = git(&clone, &["rev-parse", "HEAD"]);
        git(&clone, &["checkout", "-q", "master"]);
        git(&clone, &["merge", "-q", "--no-ff", "-m", "Merge develop", "develop"]);
        git(&clone, &["push", "-q", "origin", "master"]);
        assert_eq!(
            check_in(&helper(), &clone, &installed).unwrap().status,
            Status::UpToDate
        );
    }

    #[test]
    fn merged_new_work_lists_only_real_commits() {
        let (_t, _remote, clone) = repos();
        let installed = commit_and_push(&clone, "first");
        git(&clone, &["checkout", "-q", "-b", "develop"]);
        git(&clone, &["commit", "-q", "--allow-empty", "-m", "new feature"]);
        git(&clone, &["checkout", "-q", "master"]);
        git(&clone, &["merge", "-q", "--no-ff", "-m", "Merge develop", "develop"]);
        git(&clone, &["push", "-q", "origin", "master"]);
        let r = check_in(&helper(), &clone, &installed).unwrap();
        assert_eq!(r.status, Status::Available);
        let subjects: Vec<_> = r.commits.iter().map(|c| c.subject.as_str()).collect();
        assert_eq!(subjects, ["new feature"]);
    }

    #[test]
    fn check_failure_surfaces_helper_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = check_in(&helper(), tmp.path(), "abc").unwrap_err();
        assert!(err.contains("lockbox repo not found"), "{err}");
    }

    #[test]
    fn parse_rejects_missing_status() {
        assert!(parse_check("LATEST abc\n", "x").is_err());
        assert!(parse_check("STATUS up-to-date\n", "x").is_err());
        assert!(parse_check("LATEST abc\nSTATUS weird\n", "x").is_err());
    }

    #[test]
    fn last_lines_takes_tail() {
        assert_eq!(last_lines("a\nb\nc\n", 2), "b\nc");
        assert_eq!(last_lines("a", 5), "a");
    }
}
