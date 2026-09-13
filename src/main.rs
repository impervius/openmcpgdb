use clap::Parser;
use openmcpgdb::{ServerConfig, error::OpenMcpGdbError, runtime::run_from_config};
use std::path::PathBuf;

/// Interactive MCP server to control gdb.
#[derive(Debug, Parser)]
#[command(name = "openmcpgdb", version, about)]
struct Cli {
    /// Path to a JSON config file. Every field is optional; a minimal
    /// config is just {}. With no argument, built-in defaults apply
    /// (stdio transport, gdb resolved from PATH); a config file is never
    /// read implicitly.
    config_path: Option<PathBuf>,

    /// GDB binary to use (absolute path or command name resolved via PATH),
    /// e.g. --gdb-path gdb-multiarch. Overrides the `gdb_path` field from
    /// the config file and the built-in default. Useful for multi-arch
    /// targets where a native `gdb` cannot load a foreign ELF.
    #[arg(long = "gdb-path", value_name = "PATH")]
    gdb_path: Option<PathBuf>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), OpenMcpGdbError> {
    // Print errors with their user-facing Display text (including guidance)
    // instead of the Debug fallback used by the Result return path.
    let exit = real_main().await;
    if let Err(err) = &exit {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
    exit
}

async fn real_main() -> Result<(), OpenMcpGdbError> {
    let cli = Cli::parse();

    // Load base config: explicit file (unvalidated, so CLI can override
    // first) or built-in defaults. A config file is only ever read when
    // explicitly passed, so startup never depends on the working directory
    // (deterministic for MCP client registration).
    let mut config = match cli.config_path {
        Some(path) => {
            if !path.exists() {
                return Err(OpenMcpGdbError::ConfigNotFound { path });
            }
            ServerConfig::from_file_unvalidated(&path)?
        }
        None => ServerConfig::default(),
    };

    // CLI takes precedence over the config file (and defaults).
    // `run_from_config` performs the single validation pass.
    if let Some(gdb_path) = cli.gdb_path {
        config.gdb_path = gdb_path;
    }

    run_from_config(config).await
}

#[cfg(test)]
mod cli_tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn no_args_gives_defaults() {
        let cli = Cli::try_parse_from(["openmcpgdb"]).expect("empty args parse");
        assert_eq!(cli.config_path, None);
        assert_eq!(cli.gdb_path, None);
    }

    #[test]
    fn config_positional_is_kept() {
        let cli = Cli::try_parse_from(["openmcpgdb", "config.json"]).expect("parses");
        assert_eq!(cli.config_path, Some(PathBuf::from("config.json")));
        assert_eq!(cli.gdb_path, None);
    }

    #[test]
    fn gdb_path_long_form_parses() {
        let cli =
            Cli::try_parse_from(["openmcpgdb", "--gdb-path", "gdb-multiarch"]).expect("parses");
        assert_eq!(cli.gdb_path, Some(PathBuf::from("gdb-multiarch")));
        assert_eq!(cli.config_path, None);
    }

    #[test]
    fn gdb_path_equals_form_parses() {
        let cli = Cli::try_parse_from(["openmcpgdb", "--gdb-path=/usr/bin/gdb"]).expect("parses");
        assert_eq!(cli.gdb_path, Some(PathBuf::from("/usr/bin/gdb")));
    }

    #[test]
    fn cli_and_config_combine() {
        let cli = Cli::try_parse_from(["openmcpgdb", "--gdb-path", "gdb-multiarch", "config.json"])
            .expect("parses");
        assert_eq!(cli.gdb_path, Some(PathBuf::from("gdb-multiarch")));
        assert_eq!(cli.config_path, Some(PathBuf::from("config.json")));
    }

    #[test]
    fn missing_value_and_unknown_flag_error() {
        assert!(Cli::try_parse_from(["openmcpgdb", "--gdb-path"]).is_err());
        assert!(Cli::try_parse_from(["openmcpgdb", "--nope"]).is_err());
        assert!(Cli::try_parse_from(["openmcpgdb", "a.json", "b.json"]).is_err());
    }
}
