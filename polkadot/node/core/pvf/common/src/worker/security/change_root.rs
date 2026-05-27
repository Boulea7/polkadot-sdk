// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Functionality for securing workers by unsharing some namespaces from other processes and
//! changing the root.

use crate::{
	worker::{WorkerInfo, WorkerKind},
	LOG_TARGET,
};
use std::{env, ffi::CString, io, os::unix::ffi::OsStrExt, path::Path, ptr};

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("{0}")]
	OsErrWithContext(String),
	#[error(transparent)]
	Io(#[from] io::Error),
	#[error("assertion failed: {0}")]
	AssertionFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Try to enable for the given kind of worker.
///
/// NOTE: This should not be called in a multi-threaded context. `unshare(2)`:
///       "CLONE_NEWUSER requires that the calling process is not threaded."
pub fn enable_for_worker(worker_info: &WorkerInfo) -> Result<()> {
	gum::trace!(
		target: LOG_TARGET,
		?worker_info,
		"enabling change-root",
	);

	try_restrict(worker_info)
}

/// Runs a check for unshare-and-change-root and returns an error indicating whether it can be fully
/// enabled on the current Linux environment.
///
/// NOTE: This should not be called in a multi-threaded context. `unshare(2)`:
///       "CLONE_NEWUSER requires that the calling process is not threaded."
pub fn check_can_fully_enable(tempdir: &Path) -> Result<()> {
	let worker_dir_path = tempdir.to_owned();
	try_restrict(&WorkerInfo {
		pid: std::process::id(),
		kind: WorkerKind::CheckPivotRoot,
		version: None,
		worker_dir_path,
	})
}

/// Unshare the user namespace and change root to be the worker directory.
///
/// NOTE: This should not be called in a multi-threaded context. `unshare(2)`:
///       "CLONE_NEWUSER requires that the calling process is not threaded."
fn try_restrict(worker_info: &WorkerInfo) -> Result<()> {
	// TODO: Remove this once this is stable: https://github.com/rust-lang/rust/issues/105723
	macro_rules! cstr_ptr {
		($e:expr) => {
			concat!($e, "\0").as_ptr().cast::<core::ffi::c_char>()
		};
	}

	let worker_dir_path_c = CString::new(worker_info.worker_dir_path.as_os_str().as_bytes())
		.expect("on unix; the path will never contain 0 bytes; qed");

	// Wrapper around all the work to prevent repetitive error handling.
	//
	// # Errors
	//
	// It's the caller's responsibility to call `Error::last_os_error`. Note that that alone does
	// not give the context of which call failed, so we return a &str error.
	|| -> std::result::Result<(), &'static str> {
		// 1. `unshare` the user and the mount namespaces.
		// SAFETY: no preconditions beyond running single-threaded (caller's responsibility).
		if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } < 0 {
			return Err("unshare user and mount namespaces");
		}

		// Establish a 1-line identity uid/gid map in the new user namespace so the
		// worker's EUID/EGID have a mapping in it. Without this, attempts to create
		// nested user namespaces fail with EPERM (see clone(2)). PolkaVM needs this
		// when spawning a new sandbox, which is in turn needed for the
		// `sp_virtualization` host functions.
		// SAFETY: getuid is documented as never failing.
		let uid = unsafe { libc::getuid() };
		// SAFETY: getgid is documented as never failing.
		let gid = unsafe { libc::getgid() };
		if std::fs::write("/proc/self/setgroups", "deny").is_err() {
			return Err("write /proc/self/setgroups");
		}
		if std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).is_err() {
			return Err("write /proc/self/uid_map");
		}
		if std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).is_err() {
			return Err("write /proc/self/gid_map");
		}

		// SAFETY: We pass null-terminated C strings and use the APIs as documented. In fact, steps
		//         (2) and (3) are adapted from the example in pivot_root(2), with the additional
		//         change described in the `pivot_root(".", ".")` section.
		unsafe {
			// 2. Setup mounts.
			//
			// Ensure that new root and its parent mount don't have shared propagation (which would
			// cause pivot_root() to return an error), and prevent propagation of mount events to
			// the initial mount namespace.
			if libc::mount(
				ptr::null(),
				cstr_ptr!("/"),
				ptr::null(),
				libc::MS_REC | libc::MS_PRIVATE,
				ptr::null(),
			) < 0
			{
				return Err("mount MS_PRIVATE");
			}
			// Ensure that the new root is a mount point.
			let additional_flags =
				if let WorkerKind::Execute | WorkerKind::CheckPivotRoot = worker_info.kind {
					libc::MS_RDONLY
				} else {
					0
				};
			if libc::mount(
				worker_dir_path_c.as_ptr(),
				worker_dir_path_c.as_ptr(),
				ptr::null(), // ignored when MS_BIND is used
				libc::MS_BIND |
					libc::MS_REC | libc::MS_NOEXEC |
					libc::MS_NODEV | libc::MS_NOSUID |
					libc::MS_NOATIME |
					additional_flags,
				ptr::null(), // ignored when MS_BIND is used
			) < 0
			{
				return Err("mount MS_BIND");
			}

			// 3. `pivot_root` to the artifact directory.
			if libc::chdir(worker_dir_path_c.as_ptr()) < 0 {
				return Err("chdir to worker dir path");
			}
			if libc::syscall(libc::SYS_pivot_root, cstr_ptr!("."), cstr_ptr!(".")) < 0 {
				return Err("pivot_root");
			}
			if libc::umount2(cstr_ptr!("."), libc::MNT_DETACH) < 0 {
				return Err("umount the old root mount point");
			}
		}

		Ok(())
	}()
	.map_err(|err_ctx| {
		let err = io::Error::last_os_error();
		Error::OsErrWithContext(format!("{}: {}", err_ctx, err))
	})?;

	// Do some assertions.
	if env::current_dir()? != Path::new("/") {
		return Err(Error::AssertionFailed(
			"expected current dir after pivot_root to be `/`".into(),
		));
	}
	env::set_current_dir("..")?;
	if env::current_dir()? != Path::new("/") {
		return Err(Error::AssertionFailed(
			"expected not to be able to break out of new root by doing `..`".into(),
		));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::thread;

	/// Nested `CLONE_NEWUSER` succeeds inside the namespace established by `try_restrict`.
	///
	/// Regression test for PolkaVM's sandbox EPERM-ing inside the PVF execute worker when the
	/// identity `uid_map`/`gid_map` writes after `unshare(CLONE_NEWUSER | CLONE_NEWNS)` were
	/// missing.
	#[test]
	fn nested_user_namespace_works_after_restrict() {
		// Probe in a throwaway thread so `check_can_fully_enable`'s `pivot_root` side-effects
		// don't leak to the test thread. Skip when the host can't support the full sequence
		// (Docker without `--privileged`, kernel without `CONFIG_USER_NS`, etc.) — same
		// convention used by the sibling `seccomp::tests` / `landlock::tests`.
		let probe_tmp = tempfile::tempdir().unwrap();
		let probe_dir = probe_tmp.path().to_owned();
		let supported = thread::spawn(move || check_can_fully_enable(&probe_dir).is_ok())
			.join()
			.unwrap_or(false);
		if !supported {
			return;
		}

		let tmp = tempfile::tempdir().unwrap();
		let worker_dir = tmp.path().to_owned();
		let handle = thread::spawn(move || {
			try_restrict(&WorkerInfo {
				pid: std::process::id(),
				kind: WorkerKind::CheckPivotRoot,
				version: None,
				worker_dir_path: worker_dir,
			})
			.expect("try_restrict failed in a supported environment");

			// The exact syscall PolkaVM issues to spawn its sandbox.
			// SAFETY: single-threaded (just spawned).
			let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
			assert_eq!(
				rc,
				0,
				"nested unshare(CLONE_NEWUSER) failed: {}",
				std::io::Error::last_os_error()
			);
		});
		assert!(handle.join().is_ok());
	}
}
