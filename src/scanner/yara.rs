use super::heuristics::Confidence;
use std::{fs::File, io::BufReader, path::Path};
use yara_x::Rules;

/// Function to load a compiled YARA rules cache from disk.
pub fn load_yara_rules_cache(path: impl AsRef<Path>) -> Result<Rules, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let rules = Rules::deserialize_from(reader)?;
    Ok(rules)
}

/// Internal classifications of YARA rules.
#[derive(Debug)]
pub enum YaraRuleClass {
    EICAR,
    AMTSO,
    HighConfidenceMalware,
    MalwareFamily,
    SuspiciousCapability,
    Persistence,
    CredentialAccess,
    DefenseEvasion,
    PackerOrObfuscation,
    ExploitOrVulnerability,
    WebShell,
    DualUseTool,
    GenericIndicator,
    Unknown,
}

/// Internal metric of likely a rule is to be relevant.
#[derive(Debug)]
pub enum RuleStrength {
    GenericPrimitive,
    CombinedSuspiciousPrimitives,
    ConcreteTechnique,
    MalwareSpecific,
    HighConfidenceMalware,
}

#[derive(Debug)]
pub struct MatchedYaraRule {
    pub name: String,
    pub class: YaraRuleClass,
    pub strength: RuleStrength,
}

impl MatchedYaraRule {
    pub fn from_yara_rule(rule: yara_x::Rule<'_, '_>) -> Self {
        let identifier = rule.identifier();

        let class = classify_yara_rule(
            identifier,
            rule.tags().map(|tag| tag.identifier()),
            rule.metadata().map(|metadata| metadata.0),
        );

        let strength =
            infer_persistence_strength(identifier, rule.tags().map(|tag| tag.identifier()));

        Self {
            name: identifier.to_string(),
            class,
            strength,
        }
    }
}

fn classify_yara_rule<'a>(
    identifier: &str,
    tags: impl IntoIterator<Item = &'a str>,
    metadata_keys: impl IntoIterator<Item = &'a str>,
) -> YaraRuleClass {
    let mut saw_persistence = contains_class_hint(
        identifier,
        &["ldpreload", "ld_preload", "systemd", "cron", "persistence"],
    );

    let mut saw_eicar = contains_class_hint(identifier, &["eicar", "EICAR", "Eicar"]);

    let mut saw_amtso = contains_class_hint(identifier, &["amtso", "AMTSO", "Atmtso"]);

    let mut saw_packer =
        contains_class_hint(identifier, &["packer", "packed", "upx", "obfus", "cryptor"]);

    let mut saw_credential = contains_class_hint(
        identifier,
        &[
            "credential",
            "password",
            "keylogger",
            "stealer",
            "infostealer",
        ],
    );

    for tag in tags {
        saw_persistence |= contains_class_hint(
            tag,
            &["ldpreload", "ld_preload", "systemd", "cron", "persistence"],
        );

        saw_eicar |= contains_class_hint(tag, &["eicar"]);

        saw_amtso |= contains_class_hint(tag, &["amtso"]);

        saw_packer |= contains_class_hint(tag, &["packer", "packed", "upx", "obfus", "cryptor"]);

        saw_credential |= contains_class_hint(
            tag,
            &[
                "credential",
                "password",
                "keylogger",
                "stealer",
                "infostealer",
            ],
        );
    }

    for key in metadata_keys {
        // Metadata keys alone are usually less useful than values,
        // but this lets you handle fields like "malware", "family", etc.
        saw_credential |= contains_class_hint(key, &["credential", "stealer"]);
        saw_eicar |= contains_class_hint(key, &["EICAR"]);
        saw_amtso |= contains_class_hint(key, &["AMTSO"]);
    }

    if saw_credential {
        YaraRuleClass::CredentialAccess
    } else if saw_persistence {
        YaraRuleClass::Persistence
    } else if saw_packer {
        YaraRuleClass::PackerOrObfuscation
    } else if saw_eicar {
        YaraRuleClass::EICAR
    } else if saw_amtso {
        YaraRuleClass::AMTSO
    } else {
        YaraRuleClass::Unknown
    }
}

fn contains_class_hint(value: &str, needles: &[&str]) -> bool {
    let value = value.to_ascii_lowercase();
    needles.iter().any(|needle| value.contains(needle))
}

fn infer_persistence_strength<'a>(
    identifier: &'a str,
    tags: impl IntoIterator<Item = &'a str>,
) -> RuleStrength {
    let mut saw_ld_preload = false;
    let mut saw_cron = false;
    let mut saw_systemd = false;
    let mut saw_shell_startup = false;

    for value in std::iter::once(identifier).chain(tags) {
        let v = value.to_ascii_lowercase();

        saw_ld_preload |= v.contains("ldpreload") || v.contains("ld_preload");
        saw_cron |= v.contains("cron") || v.contains("crontab");
        saw_systemd |= v.contains("systemd") || v.contains("systemctl") || v.contains("service");
        saw_shell_startup |=
            v.contains("bashrc") || v.contains("profile") || v.contains("autostart");
    }

    let hits = [saw_ld_preload, saw_cron, saw_systemd, saw_shell_startup]
        .into_iter()
        .filter(|seen| *seen)
        .count();

    match hits {
        0 | 1 => RuleStrength::GenericPrimitive,
        _ => RuleStrength::CombinedSuspiciousPrimitives,
    }
}

pub fn score_matched_rule(class: &YaraRuleClass, strength: &RuleStrength) -> (u16, Confidence) {
    match (class, strength) {
        (YaraRuleClass::EICAR | YaraRuleClass::AMTSO, _) => (80, Confidence::High),
        (_, RuleStrength::HighConfidenceMalware) => (75, Confidence::High),
        (_, RuleStrength::MalwareSpecific) => (60, Confidence::High),

        (YaraRuleClass::Persistence, RuleStrength::ConcreteTechnique) => (35, Confidence::Medium),

        (YaraRuleClass::Persistence, RuleStrength::CombinedSuspiciousPrimitives) => {
            (20, Confidence::Low)
        }

        (YaraRuleClass::Persistence, RuleStrength::GenericPrimitive) => (10, Confidence::Low),

        (YaraRuleClass::CredentialAccess, RuleStrength::ConcreteTechnique) => {
            (45, Confidence::Medium)
        }

        (YaraRuleClass::CredentialAccess, RuleStrength::GenericPrimitive) => (15, Confidence::Low),

        (YaraRuleClass::PackerOrObfuscation, RuleStrength::GenericPrimitive) => {
            (5, Confidence::Low)
        }

        (_, RuleStrength::GenericPrimitive) => (5, Confidence::Low),
        _ => (10, Confidence::Low),
    }
}
