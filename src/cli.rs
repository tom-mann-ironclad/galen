use std::path::PathBuf;

const DEFAULT_DATABASE: &str = "./signature_database.sqlite";
const DEFAULT_YARA_DIR: &str = "./yara/";
const DEFAULT_YARA_CACHE: &str = "./yara/compiled/galen.yaraxc";

/// Commands which the user can use with the CLI.
pub enum Command {
    Scan(ScanArgs),
    Update(UpdateArgs),
    Help,
}

/// The arguments which a `Scan` command needs.
pub struct ScanArgs {
    /// The target to be scanned.
    pub target: PathBuf,
    /// The signatures database to use.
    pub database: PathBuf,
    /// The compiled YARA rules cache.
    pub yara_rules_cache: PathBuf,
}

/// The arguments which an `Update` command needs.
pub struct UpdateArgs {
    /// The database to be updated.
    pub database: PathBuf,
    /// The Malware Bazaar auth key.
    pub auth_key: String,
    /// The YARA rules storage location on disk.
    pub yara_rules_path: PathBuf,
    /// The compiled YARA rules cache.
    pub yara_rules_cache: PathBuf,
}

/// Function to parse the arguments passed to the CLI.
pub fn parse_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();

    // Skip program name
    let _program = args.next();

    let Some(command) = args.next() else {
        return Err("No arguments provided".to_string());
    };

    match command.as_str() {
        "scan" => parse_scan(args),
        "update" => parse_update(args),
        "--help" | "-h" | "help" => Ok(Command::Help),
        _other => Err("Unknown command".to_string()),
    }
}

/// Function to parse the arguments of a scan command.
fn parse_scan<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut target: Option<PathBuf> = None;
    let mut database = PathBuf::from(DEFAULT_DATABASE);
    let mut yara_rules_cache = PathBuf::from(DEFAULT_YARA_CACHE);

    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--database" | "-d" => {
                let Some(value) = args.next() else {
                    return Err("No arguments provided".to_string());
                };

                database = PathBuf::from(value);
            }

            "--yara-cache" | "-y" => {
                let Some(value) = args.next() else {
                    return Err("No arguments provided".to_string());
                };
                yara_rules_cache = PathBuf::from(value);
            }

            value if value.starts_with("-") => {
                return Err("Unknown argument provided".to_string());
            }

            value => {
                // Guard to only allow a single target
                if target.is_some() {
                    return Err("Multiple scan targets provided".to_string());
                }

                target = Some(PathBuf::from(value));
            }
        }
    }

    // Only accept scan commands which contain a target
    let Some(target) = target else {
        return Err("No scan target provided".to_string());
    };

    Ok(Command::Scan(ScanArgs { target, database, yara_rules_cache }))
}

fn parse_update<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let auth_key = match std::env::var("GALEN_AUTH_KEY") {
        Ok(key) => key,
        Err(err) => return Err(err.to_string()),
    };
    let mut args = args.into_iter();

    if let Some(arg) = args.next() {
            // Guard to catch invalid parameters
            let _value = arg.as_str();
            {
                return Err("Unknown parameter provided".to_string());
            }
        
    }

    Ok(Command::Update(UpdateArgs {
        database: PathBuf::from(DEFAULT_DATABASE),
        auth_key,
        yara_rules_path: PathBuf::from(DEFAULT_YARA_DIR),
        yara_rules_cache: PathBuf::from(DEFAULT_YARA_CACHE),
    }))
}
