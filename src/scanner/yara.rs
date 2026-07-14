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
    needles
        .iter()
        .any(|needle| value.contains(&needle.to_ascii_lowercase()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufWriter;

    fn compile_rules(source: &str) -> Rules {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).unwrap();
        compiler.build()
    }

    #[test]
    fn load_yara_rules_cache_reads_serialized_rules_and_reports_missing_files() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let rules = compile_rules("rule always_matches { condition: true }");
        rules.serialize_into(BufWriter::new(&file)).unwrap();

        let loaded = load_yara_rules_cache(file.path()).unwrap();

        assert_eq!(loaded.iter().len(), 1);
        assert!(load_yara_rules_cache(file.path().with_extension("missing")).is_err());
    }

    #[test]
    fn classify_yara_rule_uses_identifier_tags_and_metadata_hints() {
        assert!(matches!(
            classify_yara_rule("linux_ld_preload_backdoor", [], []),
            YaraRuleClass::Persistence
        ));
        assert!(matches!(
            classify_yara_rule("generic_rule", ["credential_theft"], []),
            YaraRuleClass::CredentialAccess
        ));
        assert!(matches!(
            classify_yara_rule("generic_rule", [], ["EICAR"]),
            YaraRuleClass::EICAR
        ));
        assert!(matches!(
            classify_yara_rule("generic_rule", ["upx"], []),
            YaraRuleClass::PackerOrObfuscation
        ));
    }

    #[test]
    fn classify_yara_rule_recognizes_each_hint_source_independently() {
        let cases = [
            (
                "credential_from_identifier",
                "browser_password_stealer",
                vec![],
                vec![],
                YaraRuleClass::CredentialAccess,
            ),
            (
                "credential_from_tag",
                "generic_rule",
                vec!["keylogger"],
                vec![],
                YaraRuleClass::CredentialAccess,
            ),
            (
                "credential_from_metadata_key",
                "generic_rule",
                vec![],
                vec!["credential_family"],
                YaraRuleClass::CredentialAccess,
            ),
            (
                "persistence_from_identifier",
                "systemd_service_dropper",
                vec![],
                vec![],
                YaraRuleClass::Persistence,
            ),
            (
                "persistence_from_tag",
                "generic_rule",
                vec!["cron"],
                vec![],
                YaraRuleClass::Persistence,
            ),
            (
                "packer_from_identifier",
                "upx_packed_binary",
                vec![],
                vec![],
                YaraRuleClass::PackerOrObfuscation,
            ),
            (
                "packer_from_tag",
                "generic_rule",
                vec!["cryptor"],
                vec![],
                YaraRuleClass::PackerOrObfuscation,
            ),
            (
                "eicar_from_identifier",
                "EICAR_Test_File",
                vec![],
                vec![],
                YaraRuleClass::EICAR,
            ),
            (
                "eicar_from_tag",
                "generic_rule",
                vec!["eicar"],
                vec![],
                YaraRuleClass::EICAR,
            ),
            (
                "eicar_from_metadata_key",
                "generic_rule",
                vec![],
                vec!["EICAR"],
                YaraRuleClass::EICAR,
            ),
            (
                "amtso_from_identifier",
                "AMTSO_Test_File",
                vec![],
                vec![],
                YaraRuleClass::AMTSO,
            ),
            (
                "amtso_from_tag",
                "generic_rule",
                vec!["amtso"],
                vec![],
                YaraRuleClass::AMTSO,
            ),
            (
                "amtso_from_metadata_key",
                "generic_rule",
                vec![],
                vec!["AMTSO"],
                YaraRuleClass::AMTSO,
            ),
        ];

        for (name, identifier, tags, metadata_keys, expected) in cases {
            let class = classify_yara_rule(identifier, tags, metadata_keys);
            assert!(
                std::mem::discriminant(&class) == std::mem::discriminant(&expected),
                "{name}: got {class:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn classify_yara_rule_exercises_combined_tag_and_metadata_updates() {
        assert!(matches!(
            classify_yara_rule(
                "generic_rule",
                ["persistence", "eicar", "amtso", "cryptor", "password"],
                ["credential", "EICAR", "AMTSO"]
            ),
            YaraRuleClass::CredentialAccess
        ));
        assert!(matches!(
            classify_yara_rule("generic_rule", std::iter::empty(), std::iter::empty()),
            YaraRuleClass::Unknown
        ));
    }

    #[test]
    fn classify_yara_rule_repeated_hints_do_not_toggle_matches_off() {
        assert!(matches!(
            classify_yara_rule("credential_stealer", ["password"], ["credential"]),
            YaraRuleClass::CredentialAccess
        ));
        assert!(matches!(
            classify_yara_rule(
                "ld_preload_persistence",
                ["ldpreload", "persistence"],
                std::iter::empty()
            ),
            YaraRuleClass::Persistence
        ));
        assert!(matches!(
            classify_yara_rule("packed_upx_binary", ["upx", "cryptor"], std::iter::empty()),
            YaraRuleClass::PackerOrObfuscation
        ));
        assert!(matches!(
            classify_yara_rule("EICAR_Test_File", ["eicar"], ["EICAR"]),
            YaraRuleClass::EICAR
        ));
        assert!(matches!(
            classify_yara_rule("AMTSO_Test_File", ["amtso"], ["AMTSO"]),
            YaraRuleClass::AMTSO
        ));
    }

    #[test]
    fn classify_yara_rule_duplicate_tags_do_not_toggle_matches_off() {
        let cases = [
            (
                "persistence_duplicate_tags",
                ["cron", "systemd"].as_slice(),
                YaraRuleClass::Persistence,
            ),
            (
                "eicar_duplicate_tags",
                ["eicar", "eicar"].as_slice(),
                YaraRuleClass::EICAR,
            ),
            (
                "amtso_duplicate_tags",
                ["amtso", "amtso"].as_slice(),
                YaraRuleClass::AMTSO,
            ),
            (
                "packer_duplicate_tags",
                ["upx", "cryptor"].as_slice(),
                YaraRuleClass::PackerOrObfuscation,
            ),
            (
                "credential_duplicate_tags",
                ["password", "stealer"].as_slice(),
                YaraRuleClass::CredentialAccess,
            ),
        ];

        for (name, tags, expected) in cases {
            let class = classify_yara_rule("generic_rule", tags.iter().copied(), []);
            assert!(
                std::mem::discriminant(&class) == std::mem::discriminant(&expected),
                "{name}: got {class:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn infer_persistence_strength_increases_when_multiple_primitives_are_seen() {
        assert!(matches!(
            infer_persistence_strength("cron_rule", std::iter::empty()),
            RuleStrength::GenericPrimitive
        ));
        assert!(matches!(
            infer_persistence_strength("cron_rule", ["systemd"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
    }

    #[test]
    fn infer_persistence_strength_counts_each_primitive_once() {
        for identifier in [
            "ld_preload_rule",
            "cron_rule",
            "systemctl_rule",
            "bashrc_rule",
        ] {
            assert!(
                matches!(
                    infer_persistence_strength(identifier, std::iter::empty()),
                    RuleStrength::GenericPrimitive
                ),
                "{identifier}"
            );
        }

        assert!(matches!(
            infer_persistence_strength("ldpreload_rule", ["cron"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
        assert!(matches!(
            infer_persistence_strength("systemd_rule", ["profile"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
        assert!(matches!(
            infer_persistence_strength("generic_rule", ["autostart"]),
            RuleStrength::GenericPrimitive
        ));
    }

    #[test]
    fn infer_persistence_strength_repeated_hints_do_not_toggle_matches_off() {
        assert!(matches!(
            infer_persistence_strength("ld_preload_rule", ["ldpreload", "cron"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
        assert!(matches!(
            infer_persistence_strength("cron_rule", ["crontab", "systemd"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
        assert!(matches!(
            infer_persistence_strength("systemd_rule", ["service", "bashrc"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
        assert!(matches!(
            infer_persistence_strength("profile_rule", ["autostart", "cron"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
    }

    #[test]
    fn infer_persistence_strength_counts_systemctl_and_service_as_systemd_hints() {
        assert!(matches!(
            infer_persistence_strength("systemctl_rule", ["cron"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
        assert!(matches!(
            infer_persistence_strength("service_rule", ["ldpreload"]),
            RuleStrength::CombinedSuspiciousPrimitives
        ));
    }

    #[test]
    fn score_matched_rule_covers_high_confidence_and_low_signal_rules() {
        assert_eq!(
            score_matched_rule(&YaraRuleClass::EICAR, &RuleStrength::GenericPrimitive),
            (80, Confidence::High)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::Unknown,
                &RuleStrength::HighConfidenceMalware
            ),
            (75, Confidence::High)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::MalwareFamily,
                &RuleStrength::MalwareSpecific
            ),
            (60, Confidence::High)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::Persistence,
                &RuleStrength::ConcreteTechnique
            ),
            (35, Confidence::Medium)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::Persistence,
                &RuleStrength::CombinedSuspiciousPrimitives
            ),
            (20, Confidence::Low)
        );
        assert_eq!(
            score_matched_rule(&YaraRuleClass::Persistence, &RuleStrength::GenericPrimitive),
            (10, Confidence::Low)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::CredentialAccess,
                &RuleStrength::ConcreteTechnique
            ),
            (45, Confidence::Medium)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::CredentialAccess,
                &RuleStrength::GenericPrimitive
            ),
            (15, Confidence::Low)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::PackerOrObfuscation,
                &RuleStrength::GenericPrimitive
            ),
            (5, Confidence::Low)
        );
        assert_eq!(
            score_matched_rule(&YaraRuleClass::Unknown, &RuleStrength::GenericPrimitive),
            (5, Confidence::Low)
        );
        assert_eq!(
            score_matched_rule(
                &YaraRuleClass::DefenseEvasion,
                &RuleStrength::ConcreteTechnique
            ),
            (10, Confidence::Low)
        );
    }
}
