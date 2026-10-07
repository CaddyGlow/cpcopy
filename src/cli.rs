//! Command-line adapter shared by the standalone and repository binaries.
use clap::{CommandFactory, FromArgMatches, Parser};
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

#[cfg(feature = "live-progress")]
#[path = "live_cli.rs"]
mod live;

#[derive(Parser)]
#[command(
    name = "cpcopy",
    version,
    infer_long_args = true,
    about = "Independent Rust Linux copier"
)]
struct Cli {
    #[arg(required = true, num_args = 1..)]
    operands: Vec<PathBuf>,
    /// Copy all sources into this existing directory.
    #[arg(short = 't', long, conflicts_with = "no_target_directory")]
    target_directory: Option<PathBuf>,
    /// Treat the destination as an exact path, even if it is a directory.
    #[arg(short = 'T', long)]
    no_target_directory: bool,
    /// Remove trailing slashes from source operands before copying.
    #[arg(long)]
    strip_trailing_slashes: bool,
    #[arg(short = 'l', long, conflicts_with = "symbolic_link")]
    link: bool,
    #[arg(short = 's', long)]
    symbolic_link: bool,
    #[arg(short = 'f', long)]
    force: bool,
    #[arg(long)]
    remove_destination: bool,
    #[arg(long)]
    attributes_only: bool,
    #[arg(long)]
    copy_contents: bool,
    #[arg(long)]
    keep_directory_symlink: bool,
    #[arg(long, alias = "parent")]
    parents: bool,
    #[arg(short = 'x', long)]
    one_file_system: bool,
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "always", default_value = "auto", overrides_with = "reflink", value_parser = ["auto", "always", "never"])]
    reflink: String,
    #[arg(long, default_value = "auto", overrides_with = "sparse", value_parser = ["auto", "always", "never"])]
    sparse: String,
    #[arg(long, alias = "b", num_args = 0..=1, require_equals = true, default_missing_value = "", value_parser = backup_type, overrides_with = "backup")]
    backup: Option<String>,
    #[arg(short = 'b')]
    backup_short: bool,
    #[arg(short = 'S', long, overrides_with = "suffix")]
    suffix: Option<OsString>,
    #[arg(short = 'i', long, overrides_with = "no_clobber")]
    interactive: bool,
    #[arg(short = 'v', long)]
    verbose: bool,
    #[arg(long)]
    debug: bool,
    #[arg(short = 'n', long, overrides_with = "interactive")]
    no_clobber: bool,
    #[arg(short = 'u', long, num_args = 0..=1, require_equals = true, default_missing_value = "older", value_parser = ["all", "older", "none", "none-fail"])]
    update: Option<String>,
    /// Recursively preserve source links and attributes.
    #[arg(short = 'a', long)]
    archive: bool,
    #[arg(short = 'R', short_alias = 'r', long)]
    recursive: bool,
    #[arg(short = 'P', long, overrides_with_all = ["dereference", "command_line_dereference"])]
    no_dereference: bool,
    #[arg(short = 'L', long, overrides_with_all = ["no_dereference", "command_line_dereference"])]
    dereference: bool,
    #[arg(short = 'H', overrides_with_all = ["no_dereference", "dereference"])]
    command_line_dereference: bool,
    /// Preserve hard links and symbolic links.
    #[arg(short = 'd')]
    preserve_link_types: bool,
    /// Maximum buffered read/write request size.
    #[arg(long, default_value_t = crate::DEFAULT_BUFFER_SIZE, value_parser = clap::value_parser!(u32).range(4096..=16777216))]
    buffer_size: u32,
    /// Maximum concurrent independent regular-file copies.
    #[arg(short = 'j', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
    jobs: u32,
    /// Exclude basenames using case-sensitive glob patterns; prune matching directories.
    #[arg(long = "exclude")]
    exclusions: Vec<OsString>,
    /// Emit JSON Lines completion, exclusion and summary events to stderr.
    #[arg(long)]
    progress: bool,
    /// Show live bytes, throughput and elapsed time; estimate ETA for a single file.
    #[cfg(feature = "live-progress")]
    #[arg(long, conflicts_with = "progress")]
    live_progress: bool,
    /// Preserve selected source attributes.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "mode,ownership,timestamps", value_delimiter = ',', value_parser = ["timestamps", "mode", "ownership", "links", "xattr", "streams", "sacl", "all"])]
    preserve: Vec<String>,
    #[arg(long, value_delimiter = ',', value_parser = ["timestamps", "mode", "ownership", "links", "xattr", "streams", "sacl", "all"])]
    no_preserve: Vec<String>,
    #[arg(short = 'p')]
    preserve_basic: bool,
}

/// Parse arguments and execute the copier. Returns 0 on success and 1 on failure.
pub fn run() -> ExitCode {
    #[cfg(target_os = "linux")]
    // SAFETY: CLI startup precedes any worker or concurrent locale-dependent code.
    unsafe {
        libc::setlocale(libc::LC_ALL, c"".as_ptr());
    }

    let program = std::env::args_os()
        .next()
        .and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "cpcopy".into());
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    // GNU cp applies this option when copying into a target directory.
    if cli.strip_trailing_slashes
        && !cli.no_target_directory
        && (cli.target_directory.is_some() || cli.operands.last().is_some_and(|path| path.is_dir()))
    {
        let source_count = if cli.target_directory.is_some() {
            cli.operands.len()
        } else {
            cli.operands.len().saturating_sub(1)
        };
        for source in &mut cli.operands[..source_count] {
            // Work on native bytes so non-UTF-8 names survive normalization.
            // A root operand must retain one slash.
            let bytes = source.as_os_str().as_encoded_bytes();
            let mut length = bytes.len();
            while length > 1 && is_path_separator(bytes[length - 1]) && source.file_name().is_some()
            {
                length -= 1;
            }
            // SAFETY: Removing ASCII slashes preserves valid encoded boundaries.
            *source =
                unsafe { OsString::from_encoded_bytes_unchecked(bytes[..length].to_vec()) }.into();
        }
    }
    let mut backup_control = if cli.backup.is_some() || cli.backup_short || cli.suffix.is_some() {
        Some(
            cli.backup
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| {
                    std::env::var("VERSION_CONTROL")
                        .ok()
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "existing".into())
                }),
        )
    } else {
        None
    };
    if let Some(control) = &mut backup_control {
        match backup_type(control) {
            Ok(normalized) => *control = normalized,
            Err(error) => {
                eprintln!("{program}: {error} in VERSION_CONTROL");
                return ExitCode::FAILURE;
            }
        }
    }
    let no_clobber = cli.no_clobber || matches!(cli.update.as_deref(), Some("none" | "none-fail"));
    if backup_control.is_some() && no_clobber {
        eprintln!("{program}: options --backup and --no-clobber are mutually exclusive");
        return ExitCode::FAILURE;
    }
    let link_policy = [
        ("dereference", crate::Dereference::Always),
        ("no_dereference", crate::Dereference::Never),
        ("command_line_dereference", crate::Dereference::CommandLine),
        ("preserve_link_types", crate::Dereference::Never),
        ("archive", crate::Dereference::Never),
    ]
    .into_iter()
    .filter_map(|(id, policy)| {
        (matches.value_source(id) == Some(clap::parser::ValueSource::CommandLine))
            .then(|| matches.index_of(id).map(|index| (index, policy)))
            .flatten()
    })
    .max_by_key(|(index, _)| *index)
    .map(|(_, policy)| policy);
    let options = crate::CopyOptions {
        buffer_size: cli.buffer_size,
        jobs: cli.jobs as usize,
        #[cfg(feature = "live-progress")]
        live_progress: None,
        sparse: match cli.sparse.as_str() {
            "always" => crate::SparseMode::Always,
            "never" => crate::SparseMode::Never,
            _ => crate::SparseMode::Auto,
        },
        reflink: match cli.reflink.as_str() {
            "always" => crate::ReflinkMode::Always,
            "never" => crate::ReflinkMode::Never,
            _ => crate::ReflinkMode::Auto,
        },
        exclusions: cli.exclusions,
        hard_link: cli.link,
        symbolic_link: cli.symbolic_link,
        force: cli.force,
        overwrite: true,
        remove_destination: cli.remove_destination,
        attributes_only: cli.attributes_only,
        copy_contents: cli.copy_contents,
        keep_directory_symlink: cli.keep_directory_symlink,
        parents: cli.parents,
        one_file_system: cli.one_file_system,
        backup_suffix: if backup_control.is_some()
            && !matches!(backup_control.as_deref(), Some("none" | "off"))
        {
            Some(cli.suffix.unwrap_or_else(|| {
                std::env::var_os("SIMPLE_BACKUP_SUFFIX").unwrap_or_else(|| "~".into())
            }))
        } else {
            None
        },
        backup_mode: match backup_control.as_deref() {
            Some("numbered" | "t") => crate::BackupMode::Numbered,
            Some("simple" | "never") => crate::BackupMode::Simple,
            _ => crate::BackupMode::Existing,
        },
        no_clobber,
        fail_on_skip: cli.update.as_deref() == Some("none-fail"),
        update: cli.update.as_deref() == Some("older"),
        merge_directories: true,
        preserve_timestamps: preservation(&matches, "timestamps").unwrap_or(false),
        preserve_mode: preservation(&matches, "mode").unwrap_or(false),
        preserve_ownership: preservation(&matches, "ownership").unwrap_or(false),
        creation_mask: creation_mask(),
        default_permissions: preservation(&matches, "mode") == Some(false),
        preserve_links: preservation(&matches, "links").unwrap_or(false),
        preserve_xattrs: preservation(&matches, "xattr").unwrap_or(false),
        preserve_streams: (cfg!(windows)
            || matches
                .get_many::<String>("preserve")
                .is_some_and(|v| v.into_iter().any(|a| a == "streams")))
            && preservation(&matches, "streams").unwrap_or(false),
        preserve_sacl: matches
            .get_many::<String>("preserve")
            .is_some_and(|v| v.into_iter().any(|a| a == "sacl"))
            && preservation(&matches, "sacl").unwrap_or(false),
        reject_symlinks: false,
        stop_on_error: false,
        cancellation: crate::Cancellation::default(),
        preserve_windows_attributes: false,
        reduce_xattr_diagnostics: cli.archive,
        require_preserve_xattrs: [("preserve", true), ("no_preserve", false)]
            .into_iter()
            .flat_map(|(id, enabled)| {
                matches
                    .get_many::<String>(id)
                    .into_iter()
                    .flatten()
                    .zip(matches.indices_of(id).into_iter().flatten())
                    .filter(|(value, _)| value.as_str() == "xattr")
                    .map(move |(_, index)| (index, enabled))
            })
            .max_by_key(|(index, _)| *index)
            .is_some_and(|(_, enabled)| enabled),
        allow_dangling_destination: std::env::var_os("POSIXLY_CORRECT").is_some(),
        recursive: cli.recursive || cli.archive,
        dereference: link_policy.unwrap_or(if (cli.recursive || cli.archive) && !cli.link {
            crate::Dereference::Never
        } else {
            crate::Dereference::Always
        }),
    };
    let result = destinations(
        &cli.operands,
        cli.target_directory.as_deref(),
        cli.no_target_directory,
        cli.parents,
    );
    let copies = match result {
        Ok(copies) => copies,
        Err(error) => {
            eprintln!("{program}: {error:#}");
            return ExitCode::FAILURE;
        }
    };
    let mut failed = false;
    #[cfg(feature = "live-progress")]
    let mut options = options;
    #[cfg(feature = "live-progress")]
    let reporter = if cli.live_progress {
        let progress = crate::LiveProgress::default();
        let total = live::single_file_total(&copies, &options);
        match live::Reporter::start(progress.clone(), total) {
            Ok(reporter) => {
                options.live_progress = Some(progress);
                Some(reporter)
            }
            Err(error) => {
                eprintln!("{program}: live progress unavailable: {error}");
                None
            }
        }
    } else {
        None
    };
    let mut session = crate::CopySession::default();
    for (source, destination) in copies {
        let absolute_destination =
            std::path::absolute(&destination).unwrap_or_else(|_| destination.clone());
        let display_destination = |path: &std::path::Path| {
            path.strip_prefix(&absolute_destination)
                .map(|suffix| {
                    if suffix.as_os_str().is_empty() {
                        destination.clone()
                    } else {
                        destination.join(suffix)
                    }
                })
                .unwrap_or_else(|_| path.to_owned())
        };
        if let Err(error) = session.copy_with_overwrite_policy(
            &source,
            &destination,
            &options,
            &mut |event| {
                if cli.progress {
                    emit(event)?;
                }
                if let Some(warning) = &event.warning {
                    eprintln!("{program}: setting attributes for {}: {}", quote_path(&display_destination(&warning.destination)), os_error(&std::io::Error::from_raw_os_error(warning.error)));
                }
                let directory = (cli.verbose || cli.debug) && {
                    if options.dereference == crate::Dereference::Always
                        || (options.dereference == crate::Dereference::CommandLine
                            && event.source == source)
                    {
                        std::fs::metadata(&event.source)
                    } else {
                        std::fs::symlink_metadata(&event.source)
                    }
                    .is_ok_and(|metadata| metadata.is_dir())
                };
                if (cli.verbose || cli.debug)
                    && (event.kind == crate::EventKind::DirectoryCreated
                        || (event.kind == crate::EventKind::Completed && !directory))
                {
                    println!(
                        "{} -> {}",
                        quote_path(&event.source),
                        quote_path(&display_destination(&event.destination))
                    );
                }
                if cli.debug {
                    if event.kind == crate::EventKind::Skipped {
                        println!(
                            "skipped {}",
                            quote_path(&display_destination(&event.destination))
                        );
                    }
                    if let Some(details) = event.diagnostics {
                        let offload = if details.offloaded { "yes" } else if details.offload_attempted { "unsupported" } else { "avoided" };
                        let reflink = if details.cloned {
                            "yes"
                        } else if details.reflink_attempted {
                            "unsupported"
                        } else {
                            "no"
                        };
                        let sparse = match (details.seek_hole, details.scanned_zeros) {
                            (true, true) if cfg!(windows) => "allocated ranges + zeros",
                            (true, false) if cfg!(windows) => "allocated ranges",
                            (true, true) => "SEEK_HOLE + zeros",
                            (true, false) => "SEEK_HOLE",
                            (false, true) => "zeros",
                            (false, false) => "no",
                        };
                        println!(
                            "copy offload: {offload}, reflink: {reflink}, sparse detection: {sparse}"
                        );
                    }
                }
                Ok(())
            },
            &mut |_, destination| {
                if !cli.interactive {
                    return Ok(true);
                }
                use std::io::Write;
                eprint!(
                    "{program}: overwrite {}? ",
                    quote_path(&display_destination(destination))
                );
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                Ok(answer.starts_with('y') || answer.starts_with('Y'))
            },
        ) {
            if error.downcast_ref::<crate::OverwriteDeclined>().is_some() {
                failed = true;
                continue;
            }
            report_error(&program, &error, &source, &destination, &display_destination);
            failed = true;
        }
    }
    #[cfg(feature = "live-progress")]
    if let Some(reporter) = reporter {
        reporter.finish(failed);
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn creation_mask() -> u32 {
    // Linux exposes the mask without changing process-global state.
    #[cfg(target_os = "linux")]
    if let Ok(status) = std::fs::read_to_string("/proc/self/status")
        && let Some(mask) = status.lines().find_map(|line| line.strip_prefix("Umask:"))
        && let Ok(mask) = u32::from_str_radix(mask.trim(), 8)
    {
        return mask;
    }
    0o022
}

fn preservation(matches: &clap::ArgMatches, attribute: &str) -> Option<bool> {
    let mut policies = Vec::new();
    for (id, enabled) in [("preserve", true), ("no_preserve", false)] {
        if let (Some(values), Some(indices)) =
            (matches.get_many::<String>(id), matches.indices_of(id))
        {
            policies.extend(
                values
                    .zip(indices)
                    .filter(|(value, _)| value.as_str() == attribute || value.as_str() == "all")
                    .map(|(_, index)| (index, enabled)),
            );
        }
    }
    if matches.value_source("archive") == Some(clap::parser::ValueSource::CommandLine)
        && let Some(index) = matches.index_of("archive")
    {
        policies.push((index, true));
    }
    let shorthand = if attribute == "links" {
        "preserve_link_types"
    } else {
        "preserve_basic"
    };
    if !matches!(attribute, "xattr" | "streams" | "sacl")
        && matches.value_source(shorthand) == Some(clap::parser::ValueSource::CommandLine)
        && let Some(index) = matches.index_of(shorthand)
    {
        policies.push((index, true));
    }
    policies
        .into_iter()
        .max_by_key(|(index, _)| *index)
        .map(|(_, enabled)| enabled)
}

fn backup_type(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let names = [
        ("none", "none"),
        ("off", "none"),
        ("simple", "simple"),
        ("never", "simple"),
        ("numbered", "numbered"),
        ("t", "numbered"),
        ("existing", "existing"),
        ("nil", "existing"),
    ];
    if let Some((_, mode)) = names.iter().find(|(name, _)| *name == value) {
        return Ok((*mode).into());
    }
    let mut matches = names.iter().filter(|(name, _)| name.starts_with(value));
    let Some((_, mode)) = matches.next() else {
        return Err(format!("invalid backup type '{value}'"));
    };
    if matches.any(|(_, other)| other != mode) {
        return Err(format!("ambiguous backup type '{value}'"));
    }
    Ok((*mode).into())
}

fn destinations(
    operands: &[PathBuf],
    target: Option<&std::path::Path>,
    exact: bool,
    parents: bool,
) -> anyhow::Result<Vec<(PathBuf, PathBuf)>> {
    let (sources, destination) = if let Some(target) = target {
        (operands, target)
    } else {
        let (destination, sources) = operands
            .split_last()
            .ok_or_else(|| anyhow::anyhow!("missing operand"))?;
        if sources.is_empty() {
            anyhow::bail!("missing destination operand");
        }
        (sources, destination.as_path())
    };
    if exact && sources.len() != 1 {
        anyhow::bail!("extra operand with --no-target-directory");
    }
    let metadata = match std::fs::metadata(destination) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound || is_symlink_loop(&error) => {
            None
        }
        Err(error) => {
            let message = error.to_string();
            let message = message
                .rsplit_once(" (os error ")
                .map_or(message.as_str(), |(text, _)| text);
            anyhow::bail!(
                "{} {}: {message}",
                if target.is_some() {
                    "target directory"
                } else {
                    "cannot stat"
                },
                quote_path(destination)
            );
        }
    };
    let directory = !exact && metadata.is_some_and(|metadata| metadata.is_dir());
    if (target.is_some() || sources.len() > 1) && !directory {
        anyhow::bail!("target {} is not a directory", quote_path(destination));
    }
    if parents && !directory {
        anyhow::bail!("with --parents, the destination must be a directory");
    }
    sources
        .iter()
        .map(|source| {
            let destination = if parents {
                destination.join(parent_relative_path(source))
            } else if directory {
                if source.as_os_str().as_encoded_bytes().ends_with(b"/.")
                    || (cfg!(windows) && source.as_os_str().as_encoded_bytes().ends_with(b"\\."))
                    || source == std::path::Path::new(".")
                {
                    return Ok((source.clone(), destination.to_owned()));
                }
                destination.join(source.file_name().ok_or_else(|| {
                    anyhow::anyhow!("source has no basename: {}", quote_path(source))
                })?)
            } else {
                destination.to_owned()
            };
            Ok((source.clone(), destination))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn emit(event: &crate::CopyEvent) -> anyhow::Result<()> {
    use std::{io::Write, os::unix::ffi::OsStrExt};
    let value = serde_json::json!({
        "event": event.kind.as_str(),
        "source_bytes": event.source.as_os_str().as_bytes(),
        "destination_bytes": event.destination.as_os_str().as_bytes(),
        "bytes": event.bytes,
        "completed": event.completed,
        "copied_bytes": event.copied_bytes,
        "warning": event.warning.as_ref().map(|warning| serde_json::json!({
            "destination_bytes": warning.destination.as_os_str().as_bytes(),
            "errno": warning.error,
        })),
    });
    let mut stderr = std::io::stderr().lock();
    serde_json::to_writer(&mut stderr, &value)?;
    writeln!(stderr)?;
    Ok(())
}
#[cfg(windows)]
fn emit(event: &crate::CopyEvent) -> anyhow::Result<()> {
    use std::{io::Write, os::windows::ffi::OsStrExt};
    let value = serde_json::json!({
        "event": event.kind.as_str(),
        "source_utf16": event.source.as_os_str().encode_wide().collect::<Vec<_>>(),
        "destination_utf16": event.destination.as_os_str().encode_wide().collect::<Vec<_>>(),
        "bytes": event.bytes,
        "completed": event.completed,
        "copied_bytes": event.copied_bytes,
        "warning": event.warning.as_ref().map(|warning| serde_json::json!({
            "destination_utf16": warning.destination.as_os_str().encode_wide().collect::<Vec<_>>(),
            "win32_error": warning.error,
        })),
    });
    let mut stderr = std::io::stderr().lock();
    serde_json::to_writer(&mut stderr, &value)?;
    writeln!(stderr)?;
    Ok(())
}
#[cfg(not(any(target_os = "linux", windows)))]
fn emit(_: &crate::CopyEvent) -> anyhow::Result<()> {
    Ok(())
}

fn is_symlink_loop(error: &std::io::Error) -> bool {
    #[cfg(target_os = "linux")]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = error;
        false
    }
}
fn is_path_separator(byte: u8) -> bool {
    byte == b'/' || (cfg!(windows) && byte == b'\\')
}
fn parent_relative_path(source: &std::path::Path) -> PathBuf {
    #[cfg(windows)]
    {
        source
            .components()
            .filter(|component| {
                !matches!(
                    component,
                    std::path::Component::Prefix(_) | std::path::Component::RootDir
                )
            })
            .collect()
    }
    #[cfg(not(windows))]
    {
        source
            .strip_prefix(std::path::Path::new("/"))
            .unwrap_or(source)
            .to_owned()
    }
}

fn os_error(error: &std::io::Error) -> String {
    let message = error.to_string();
    message
        .rsplit_once(" (os error ")
        .map_or_else(|| message.clone(), |(text, _)| text.to_owned())
}

// GNU's shell-escape-always quoting in the C locale. Work on encoded bytes to
// retain invalid UTF-8 rather than silently replacing parts of a filename.
fn quote_path(path: &std::path::Path) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    let printable = |character: char| locale_printable(character);
    if bytes.contains(&b'\'')
        && std::str::from_utf8(bytes).is_ok_and(|text| {
            text.chars().all(|character| {
                printable(character) && !matches!(character, '"' | '$' | '`' | '\\')
            })
        })
    {
        return format!("\"{}\"", String::from_utf8_lossy(bytes));
    }
    let mut output = String::from("'");
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte >= 128 {
            let length = match byte {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => 1,
            };
            if let Some(character) = bytes
                .get(index..index + length)
                .and_then(|chunk| std::str::from_utf8(chunk).ok())
                .and_then(|text| text.chars().next())
                .filter(|character| printable(*character))
            {
                if escaped {
                    output.push_str("''");
                    escaped = false;
                }
                output.push(character);
                index += length;
                continue;
            }
        }
        index += 1;
        let control = !(32..127).contains(&byte);
        if control != escaped {
            output.push_str(if control { "'$'" } else { "''" });
            escaped = control;
        }
        if control {
            match byte {
                7 => output.push_str("\\a"),
                8 => output.push_str("\\b"),
                9 => output.push_str("\\t"),
                10 => output.push_str("\\n"),
                11 => output.push_str("\\v"),
                12 => output.push_str("\\f"),
                13 => output.push_str("\\r"),
                _ => {
                    use std::fmt::Write;
                    let _ = write!(output, "\\{byte:03o}");
                }
            }
        } else if byte == b'\'' {
            output.push_str("'\\''");
        } else {
            output.push(char::from(byte));
        }
    }
    output.push('\'');
    output
}

fn report_error(
    program: &str,
    error: &anyhow::Error,
    source: &std::path::Path,
    destination: &std::path::Path,
    display_destination: &dyn Fn(&std::path::Path) -> PathBuf,
) {
    if let Some(errors) = error.downcast_ref::<crate::MultipleCopyErrors>() {
        for error in &errors.0 {
            report_error(program, error, source, destination, display_destination);
        }
        return;
    }
    if let Some(replaced) = error.downcast_ref::<crate::ReplacedSourceError>() {
        eprintln!(
            "{program}: skipping file {}, as it was replaced while being copied",
            quote_path(&replaced.0)
        );
    } else if let Some(pair) = error.downcast_ref::<crate::FilePairOperationError>() {
        if pair.operation == "failed to clone" {
            eprintln!(
                "{program}: failed to clone {} from {}: {}",
                quote_path(&display_destination(&pair.destination)),
                quote_path(&pair.source),
                os_error(&pair.error)
            );
        } else {
            eprintln!(
                "{program}: error copying {} to {}: {}",
                quote_path(&pair.source),
                quote_path(&display_destination(&pair.destination)),
                os_error(&pair.error)
            );
        }
    } else if let Some(metadata) = error.downcast_ref::<crate::MetadataPreservationError>() {
        eprintln!(
            "{program}: setting attributes for {}: {}",
            quote_path(&display_destination(&metadata.destination)),
            os_error(&metadata.error)
        );
    } else if let Some(operation) = error.downcast_ref::<crate::FileOperationError>() {
        let path = if matches!(
            operation.operation,
            "cannot open for reading" | "cannot access" | "error reading"
        ) {
            operation.path.clone()
        } else {
            display_destination(&operation.path)
        };
        if operation.operation == "cannot open for reading" {
            eprintln!(
                "{program}: cannot open {} for reading: {}",
                quote_path(&path),
                os_error(&operation.error)
            );
        } else {
            eprintln!(
                "{program}: {} {}: {}",
                operation.operation,
                quote_path(&path),
                os_error(&operation.error)
            );
        }
    } else if let Some(link) = error.downcast_ref::<crate::CreatedSymlinkError>() {
        eprintln!(
            "{program}: will not copy {} through just-created symlink {}",
            quote_path(&link.source_path),
            quote_path(&display_destination(&link.destination_path))
        );
    } else if let Some(copy) = error.downcast_ref::<crate::IntoSelfError>() {
        eprintln!(
            "{program}: cannot copy a directory, {}, into itself, {}",
            quote_path(&copy.source_path),
            quote_path(&display_destination(&copy.destination_path))
        );
    } else if let Some(link) = error.downcast_ref::<crate::LinkCreationError>() {
        let message = link.error.to_string();
        let message = message
            .rsplit_once(" (os error ")
            .map_or(message.as_str(), |(text, _)| text);
        eprintln!(
            "{program}: cannot create {} {} to {}: {message}",
            if link.symbolic {
                "symlink"
            } else {
                "hard link"
            },
            quote_path(&display_destination(&link.destination_path)),
            quote_path(&link.source_path)
        );
    } else if let Some(same_file) = error.downcast_ref::<crate::SameFileError>() {
        eprintln!(
            "{program}: {} and {} are the same file",
            quote_path(&same_file.source_path),
            quote_path(&display_destination(&same_file.destination_path))
        );
    } else if let Some(stat_error) = error.downcast_ref::<crate::SourceStatError>() {
        eprintln!(
            "{program}: cannot stat {}: {}",
            quote_path(&stat_error.path),
            os_error(&stat_error.error)
        );
    } else if error.downcast_ref::<crate::DanglingDestination>().is_some() {
        eprintln!("{program}: {error} {}", quote_path(destination));
    } else if error
        .downcast_ref::<crate::BackupWouldDestroySource>()
        .is_some()
    {
        eprintln!(
            "{program}: backing up {} might destroy source;  {} not copied",
            quote_path(destination),
            quote_path(source)
        );
    } else {
        eprintln!("{program}: {error:#}");
    }
}

fn locale_printable(character: char) -> bool {
    if character.is_ascii() {
        return (' '..='~').contains(&character);
    }
    #[cfg(windows)]
    {
        !character.is_control()
    }
    #[cfg(target_os = "linux")]
    {
        unsafe extern "C" {
            fn iswprint(character: u32) -> libc::c_int;
        }
        // SAFETY: nl_langinfo returns a terminated process-locale codeset name;
        // iswprint accepts a Unicode scalar in the active UTF-8 locale.
        unsafe {
            let codeset = std::ffi::CStr::from_ptr(libc::nl_langinfo(libc::CODESET));
            if codeset.to_bytes().eq_ignore_ascii_case(b"UTF-8") {
                return iswprint(character as u32) != 0;
            }
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(all(test, feature = "live-progress"))]
mod live_progress_tests {
    use super::*;

    #[test]
    fn live_terminal_progress_conflicts_with_json_progress() {
        assert!(
            Cli::try_parse_from(["cpcopy", "--progress", "--live-progress", "src", "dst"]).is_err()
        );
    }

    #[test]
    fn live_terminal_progress_is_opt_in() {
        assert!(
            !Cli::try_parse_from(["cpcopy", "src", "dst"])
                .unwrap()
                .live_progress
        );
        assert!(
            Cli::try_parse_from(["cpcopy", "--live-progress", "src", "dst"])
                .unwrap()
                .live_progress
        );
    }
}
