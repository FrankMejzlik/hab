//!
//! Code shared throught the project.
//!

use std::error::Error as StdError;
use std::fmt;

// ---
use clap::Parser;
// ---

// ***
// The general error type we're using throught this program.
// ***

pub type UnixTimestamp = u128;

/// General error type used in this binary.
#[derive(Debug)]
pub struct Error {
    msg: String,
}

/// The error must be printable.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

/// Implement the std::error::Error interface.
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
    fn description(&self) -> &str {
        &self.msg
    }
    fn cause(&self) -> Option<&dyn StdError> {
        None
    }
}

// ***
// The clap config for command line arguments.
// ***

/// Modes in which the progarm can operate.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ProgramMode {
    /// The broadcaster of the data.
    Sender,
    /// The subscriber to the broadcasters.
    Receiver,
}

/// Define the CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// What mode to launch the program in.
    #[clap(value_enum)]
    pub mode: ProgramMode,
    /// Seed used for the CSPRNG.
    #[clap(short, long, default_value_t = 42)]
    pub seed: u64,
    /// A port number to listen at.
    #[clap(short, long, default_value_t = 5555)]
    pub port: u32,
    /// The input file (if none, STDIN), only aplicable with `Sender`.
    #[clap(short, long)]
    pub input: Option<String>,
    /// The input file (if none, STDOUT), only aplicable with `Receiver`.
    #[clap(short, long)]
    pub output: Option<String>,
}

///
/// Setups the logger so it ignores the debug & trace logs in the third-party libs.
///
pub fn setup_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                //chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                chrono::Local::now().format("%H:%M:%S"),
                record.level(),
                message
            ))
        })
        // Disable all by default
        .level(log::LevelFilter::Warn)
        // Allow for this module
        .level_for("hashsig", log::LevelFilter::Trace)
        .chain(std::io::stdout())
        .chain(fern::log_file("output.log")?)
        .apply()?;
    Ok(())
}

///
/// Wrapper around the standard logging macros to accept also tag and log the messages
/// also to separate files per tag.
///

#[macro_export]
macro_rules! trace {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Trace {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}][{}][{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        "TRACE",
                        $tag,
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            log::trace!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::trace!($($arg)+);
    }};
}

#[macro_export]
macro_rules! debug {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Debug {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}][{}][{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        "DEBUG",
                        $tag,
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            log::debug!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::debug!($($arg)+);
    }};
}

#[macro_export]
macro_rules! info {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Info {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}][{}][{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        "INFO",
                        $tag,
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            log::info!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::info!($($arg)+);
    }};

}

#[macro_export]
macro_rules! warn {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Info {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}][{}][{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        "WARN",
                        $tag,
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            log::warn!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::warn!($($arg)+);
    }};

}

#[macro_export]
macro_rules! error {
	(tag: $tag:expr, $($arg:tt)+) => {{
        use crate::config::LOGS_DIR;
        use std::io::Write;

        if log::max_level() >= log::Level::Info {
            let mut log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}.log", LOGS_DIR, $tag))
                .unwrap();

			let inner = format!($($arg)+);

            log_file
                .write_all(
                    format!(
                        "[{}][{}][{}] {}\n",
                        chrono::Local::now().format("%H:%M:%S"),
                        "ERROR",
                        $tag,
                        inner
                    )
                    .as_bytes(),
                )
                .unwrap();

            log::error!($($arg)+);
        }
    }};

	($($arg:tt)+) => {{
            log::error!($($arg)+);
    }};

}
