use crate::{
    DetectionRecord,
    scanner::heuristics::Finding,
    scanner::scan::{DetectionSurface, ScanSummaryStats, SkipReason},
    should_display_detection,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub schema_version: u16,
    pub summary: ReportSummary,
    pub yara: YaraReport,
    pub visible_detections: Vec<DetectionReportRecord>,
    pub suppressed_detections: Vec<DetectionReportRecord>,
}

impl ScanReport {
    pub fn from_summary(summary: &ScanSummaryStats, scan_time: std::time::Duration) -> Self {
        let visible_records: Vec<&DetectionRecord> = summary
            .detections
            .iter()
            .filter(|record| should_display_detection(record, &summary.detections))
            .collect();

        let suppressed_records: Vec<&DetectionRecord> = summary
            .detections
            .iter()
            .filter(|record| !should_display_detection(record, &summary.detections))
            .collect();

        Self {
            schema_version: 1,
            summary: ReportSummary::from_summary(
                summary,
                &visible_records,
                &suppressed_records,
                scan_time,
            ),
            yara: YaraReport::from_summary(summary),
            visible_detections: visible_records
                .iter()
                .map(|record| DetectionReportRecord::from_detection(record))
                .collect(),

            suppressed_detections: suppressed_records
                .iter()
                .map(|record| DetectionReportRecord::from_detection(record))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub scanned_files: u64,
    pub filesystem_files: u64,
    pub archive_entries: u64,
    pub scanned_archives: u64,
    pub skipped_files: u64,
    pub skips: Vec<SkipReportItem>,
    pub raw_detection_records: u64,
    pub visible_detection_records: u64,
    pub suppressed_detection_records: u64,
    pub raw_detections_by_surface: Vec<SurfaceReportItem>,
    pub scan_time_ms: f64,
}

impl ReportSummary {
    pub fn from_summary(
        summary: &ScanSummaryStats,
        visible_records: &[&DetectionRecord],
        suppressed_records: &[&DetectionRecord],
        scan_time: std::time::Duration,
    ) -> Self {
        let skips = SkipReason::ALL
            .iter()
            .copied()
            .filter_map(|reason| {
                let count = summary.skip_count(reason);

                if count == 0 {
                    return None;
                }

                Some(SkipReportItem {
                    reason: reason.json_label().to_string(),
                    count: count as u64,
                })
            })
            .collect();

        let raw_detections_by_surface = DetectionSurface::ALL
            .iter()
            .copied()
            .filter_map(|surface| {
                let count = summary
                    .detections
                    .iter()
                    .filter(|record| record.surface == surface)
                    .count() as u64;

                if count == 0 {
                    return None;
                }

                Some(SurfaceReportItem {
                    surface: surface.json_label().to_string(),
                    count,
                })
            })
            .collect();

        Self {
            scanned_files: summary.total_files_scanned(),
            filesystem_files: summary.filesystem_files_scanned,
            archive_entries: summary.archive_entries_scanned,
            scanned_archives: summary.archives_scanned,

            skipped_files: summary.files_skipped,
            skips,

            raw_detection_records: summary.detections.len() as u64,
            visible_detection_records: visible_records.len() as u64,
            suppressed_detection_records: suppressed_records.len() as u64,
            raw_detections_by_surface,

            scan_time_ms: scan_time.as_secs_f64() * 1000.0,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SkipReportItem {
    pub reason: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct SurfaceReportItem {
    pub surface: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct YaraReport {
    pub rules_triggered: Vec<YaraRuleReport>,
}

impl YaraReport {
    pub fn from_summary(summary: &ScanSummaryStats) -> Self {
        let mut rules_triggered: Vec<_> = summary
            .yara_rules_triggered
            .iter()
            .map(|(rule, files)| YaraRuleReport {
                rule: rule.clone(),
                files: *files,
            })
            .collect();

        rules_triggered.sort_by(|a, b| a.rule.cmp(&b.rule));

        Self { rules_triggered }
    }
}

#[derive(Debug, Serialize)]
pub struct YaraRuleReport {
    pub rule: String,
    pub files: u64,
}

#[derive(Debug, Serialize)]
pub struct DetectionReportRecord {
    pub path: String,
    pub score: u16,
    pub verdict: String,
    pub surface: String,
    pub findings: Vec<FindingReportRecord>,
}

impl DetectionReportRecord {
    fn from_detection(record: &DetectionRecord) -> Self {
        Self {
            path: record.path.display().to_string(),
            score: record.score,
            verdict: record.verdict.json_label().to_string(),
            surface: record.surface.json_label().to_string(),
            findings: record
                .findings
                .iter()
                .flatten()
                .map(FindingReportRecord::from_finding)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FindingReportRecord {
    pub id: String,
    pub score: u16,
    pub confidence: String,
}

impl FindingReportRecord {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            id: finding.id.json_label().to_string(),
            score: finding.score,
            confidence: finding.confidence.json_label().to_string(),
        }
    }
}
