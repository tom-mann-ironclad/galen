use std::path::PathBuf;

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
}

/// The arguments which an `Update` command needs.
pub struct UpdateArgs {
    /// The source to use when updating.
    pub source: String,
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
    let mut database = PathBuf::from("./signature_database.sqlite");

    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--database" | "-d" => {
                let Some(value) = args.next() else {
                    return Err("No arguments provided".to_string());
                };

                database = PathBuf::from(value);
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

    Ok(Command::Scan(ScanArgs { target, database }))
}

fn parse_update<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut source = String::from("local");

    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--source" | "-s" => {
                let Some(value) = args.next() else {
                    return Err("No arguments provided".to_string());
                };

                source = value;
            }

            // Guard to catch invalid parameters
            _value => {
                return Err("Unknown parameter provided".to_string());
            }
        }
    }

    Ok(Command::Update(UpdateArgs { source }))
}
