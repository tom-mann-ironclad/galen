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
