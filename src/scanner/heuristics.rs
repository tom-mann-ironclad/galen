pub const MAX_FINDINGS_PER_FILE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Clean,
    Informational,
    Suspicious,
    LikelyMalicious,
    Malicious,
}

impl Verdict {
    pub fn label(&self) -> &str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Informational => "informational",
            Verdict::Suspicious => "suspicious",
            Verdict::LikelyMalicious => "likely malicious",
            Verdict::Malicious => "malicious",
        }
    }

    pub fn json_label(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Informational => "informational",
            Verdict::Suspicious => "suspicious",
            Verdict::LikelyMalicious => "likely_malicious",
            Verdict::Malicious => "malicious",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(&self) -> &str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }

    pub fn json_label(&self) -> &str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingId {
    KnownHash,
    SingleYaraRule,
    MultipleYaraRules,
    YaraPersistenceIndicator,
    YaraRootkitIndicator,
    YaraPackerIndicator,
    StaticLdPreloadReference,
    ElfWritableExecutableSegment,
    RuntimeMemfdExec,
}

impl FindingId {
    pub fn label(&self) -> &str {
        match self {
            FindingId::KnownHash => "known hash",
            FindingId::SingleYaraRule => "single YARA rule match",
            FindingId::MultipleYaraRules => "multiple YARA rule match",
            FindingId::YaraPersistenceIndicator => "persistence indicator",
            FindingId::YaraRootkitIndicator => "rootkit indicator",
            FindingId::YaraPackerIndicator => "packer indicator",
            FindingId::StaticLdPreloadReference => "static LRD preload reference",
            FindingId::ElfWritableExecutableSegment => "writable executable segement",
            FindingId::RuntimeMemfdExec => "runtime memfd exec",
        }
    }

    pub fn json_label(&self) -> &str {
        match self {
            FindingId::KnownHash => "known_hash",
            FindingId::SingleYaraRule => "single_yara_rule_match",
            FindingId::MultipleYaraRules => "multiple_yara_rule_match",
            FindingId::YaraPersistenceIndicator => "persistence_indicator",
            FindingId::YaraRootkitIndicator => "rootkit_indicator",
            FindingId::YaraPackerIndicator => "packer_indicator",
            FindingId::StaticLdPreloadReference => "static_lrd_preload_reference",
            FindingId::ElfWritableExecutableSegment => "writable_executable_segement",
            FindingId::RuntimeMemfdExec => "runtime_memfd_exec",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Finding {
    pub id: FindingId,
    pub score: u16,
    pub confidence: Confidence,
}

#[derive(Debug, Default)]
pub struct HeuristicAccumulator {
    score: u16,
    findings: [Option<Finding>; MAX_FINDINGS_PER_FILE],
    num_findings: usize,
}

impl HeuristicAccumulator {
    pub fn new() -> Self {
        Self {
            score: 0,
            findings: [None; MAX_FINDINGS_PER_FILE],
            num_findings: 0,
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.score = self.score.saturating_add(finding.score);
        if self.num_findings < MAX_FINDINGS_PER_FILE {
            self.findings[self.num_findings] = Some(finding);
            self.num_findings += 1;
        }
    }

    pub fn score(&self) -> u16 {
        self.score
    }

    pub fn findings(&self) -> [Option<Finding>; MAX_FINDINGS_PER_FILE] {
        self.findings
    }

    pub fn verdict(&self) -> Verdict {
        match self.score {
            0 => Verdict::Clean,
            1..=29 => Verdict::Informational,
            30..=59 => Verdict::Suspicious,
            60..=89 => Verdict::LikelyMalicious,
            _ => Verdict::Malicious,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(score: u16) -> Finding {
        Finding {
            id: FindingId::KnownHash,
            score,
            confidence: Confidence::High,
        }
    }

    #[test]
    fn verdict_thresholds_cover_boundary_scores() {
        let cases = [
            (0, Verdict::Clean),
            (1, Verdict::Informational),
            (29, Verdict::Informational),
            (30, Verdict::Suspicious),
            (59, Verdict::Suspicious),
            (60, Verdict::LikelyMalicious),
            (89, Verdict::LikelyMalicious),
            (90, Verdict::Malicious),
        ];

        for (score, expected) in cases {
            let mut accumulator = HeuristicAccumulator::new();
            if score > 0 {
                accumulator.add(finding(score));
            }

            assert_eq!(accumulator.verdict(), expected);
        }
    }

    #[test]
    fn accumulator_saturates_score_and_caps_retained_findings() {
        let mut accumulator = HeuristicAccumulator::new();

        for _ in 0..(MAX_FINDINGS_PER_FILE + 2) {
            accumulator.add(finding(u16::MAX));
        }

        assert_eq!(accumulator.score(), u16::MAX);
        assert_eq!(
            accumulator.findings().iter().flatten().count(),
            MAX_FINDINGS_PER_FILE
        );
    }

    #[test]
    fn labels_are_distinct_for_human_and_json_verdicts() {
        assert_eq!(Verdict::LikelyMalicious.label(), "likely malicious");
        assert_eq!(Verdict::LikelyMalicious.json_label(), "likely_malicious");
    }

    #[test]
    fn confidence_labels_are_stable() {
        let cases = [
            (Confidence::Low, "low", "low"),
            (Confidence::Medium, "medium", "medium"),
            (Confidence::High, "high", "high"),
        ];

        for (confidence, label, json_label) in cases {
            assert_eq!(confidence.label(), label);
            assert_eq!(confidence.json_label(), json_label);
        }
    }

    #[test]
    fn finding_id_labels_are_stable() {
        let cases = [
            (FindingId::KnownHash, "known hash", "known_hash"),
            (
                FindingId::SingleYaraRule,
                "single YARA rule match",
                "single_yara_rule_match",
            ),
            (
                FindingId::MultipleYaraRules,
                "multiple YARA rule match",
                "multiple_yara_rule_match",
            ),
            (
                FindingId::YaraPersistenceIndicator,
                "persistence indicator",
                "persistence_indicator",
            ),
            (
                FindingId::YaraRootkitIndicator,
                "rootkit indicator",
                "rootkit_indicator",
            ),
            (
                FindingId::YaraPackerIndicator,
                "packer indicator",
                "packer_indicator",
            ),
            (
                FindingId::StaticLdPreloadReference,
                "static LRD preload reference",
                "static_lrd_preload_reference",
            ),
            (
                FindingId::ElfWritableExecutableSegment,
                "writable executable segement",
                "writable_executable_segement",
            ),
            (
                FindingId::RuntimeMemfdExec,
                "runtime memfd exec",
                "runtime_memfd_exec",
            ),
        ];

        for (finding, label, json_label) in cases {
            assert_eq!(finding.label(), label);
            assert_eq!(finding.json_label(), json_label);
        }
    }
}
