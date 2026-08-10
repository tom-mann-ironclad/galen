use serde_json::{Map, Value};
use std::{env, fs};

const SCHEMA_SOURCE: &str = include_str!("../schemas/scan-report-v1.schema.json");
const SUCCESS_REPORT: &str = include_str!("fixtures/json/scan-report-v1-success.json");
const ERROR_REPORT: &str = include_str!("fixtures/json/scan-report-v1-error.json");

#[test]
fn golden_json_reports_match_the_v1_schema() {
    let schema_source = match env::var_os("GALEN_JSON_SCHEMA_PATH") {
        Some(path) => fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read compatibility schema {path:?}: {error}")),
        None => SCHEMA_SOURCE.to_string(),
    };
    let schema: Value = serde_json::from_str(&schema_source).expect("v1 schema is valid JSON");

    for (name, source) in [
        ("success report", SUCCESS_REPORT),
        ("error report", ERROR_REPORT),
    ] {
        let report: Value = serde_json::from_str(source).expect("golden report is valid JSON");
        validate(&schema, &schema, &report, "$", name).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn schema_validation_rejects_an_invalid_report() {
    let schema: Value = serde_json::from_str(SCHEMA_SOURCE).expect("v1 schema is valid JSON");
    let mut report: Value =
        serde_json::from_str(SUCCESS_REPORT).expect("success report is valid JSON");
    report["visible_detections"][0]["findings"][0]["id"] =
        Value::String("writable_executable_segement".to_string());

    let scan_report_schema = schema
        .pointer("/$defs/scan_report")
        .expect("scan report definition exists");
    let error = validate(&schema, scan_report_schema, &report, "$", "invalid report").unwrap_err();

    assert!(error.contains("visible_detections"), "{error}");
    assert!(
        error.contains("is not one of the allowed values"),
        "{error}"
    );
}

/// Validate the assertion vocabulary used by scan-report-v1.schema.json.
/// Unknown assertion keywords fail the test so schema coverage cannot silently regress.
fn validate(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
    document: &str,
) -> Result<(), String> {
    let schema = schema
        .as_object()
        .ok_or_else(|| format!("{document}: schema at {path} is not an object"))?;
    reject_unknown_assertions(schema, path)?;

    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let target = resolve_local_reference(root, reference)?;
        validate(root, target, instance, path, document)?;
    }

    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = branches
            .iter()
            .filter(|branch| validate(root, branch, instance, path, document).is_ok())
            .count();
        if matches != 1 {
            return Err(format!(
                "{document}: {path} matched {matches} oneOf branches instead of exactly one"
            ));
        }
    }

    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        let matches = match expected {
            "object" => instance.is_object(),
            "array" => instance.is_array(),
            "string" => instance.is_string(),
            "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
            "number" => instance.is_number(),
            other => return Err(format!("unsupported schema type {other:?} at {path}")),
        };
        if !matches {
            return Err(format!("{document}: {path} is not of type {expected}"));
        }
    }

    if let Some(expected) = schema.get("const")
        && instance != expected
    {
        return Err(format!("{document}: {path} does not equal {expected}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(instance)
    {
        return Err(format!(
            "{document}: {path} value {instance} is not one of the allowed values"
        ));
    }

    validate_object(root, schema, instance, path, document)?;
    validate_array(root, schema, instance, path, document)?;
    validate_string(schema, instance, path, document)?;
    validate_number(schema, instance, path, document)
}

fn validate_object(
    root: &Value,
    schema: &Map<String, Value>,
    instance: &Value,
    path: &str,
    document: &str,
) -> Result<(), String> {
    let Some(object) = instance.as_object() else {
        return Ok(());
    };
    let properties = schema.get("properties").and_then(Value::as_object);

    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(key) {
                return Err(format!(
                    "{document}: {path} is missing required property {key}"
                ));
            }
        }
    }

    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
        for key in object.keys() {
            if !properties.is_some_and(|properties| properties.contains_key(key)) {
                return Err(format!("{document}: {path} has unexpected property {key}"));
            }
        }
    }

    if let Some(properties) = properties {
        for (key, property_schema) in properties {
            if let Some(value) = object.get(key) {
                validate(
                    root,
                    property_schema,
                    value,
                    &format!("{path}.{key}"),
                    document,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_array(
    root: &Value,
    schema: &Map<String, Value>,
    instance: &Value,
    path: &str,
    document: &str,
) -> Result<(), String> {
    let Some(items) = instance.as_array() else {
        return Ok(());
    };
    if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64)
        && items.len() as u64 > maximum
    {
        return Err(format!("{document}: {path} contains too many items"));
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            validate(
                root,
                item_schema,
                item,
                &format!("{path}[{index}]"),
                document,
            )?;
        }
    }
    Ok(())
}

fn validate_string(
    schema: &Map<String, Value>,
    instance: &Value,
    path: &str,
    document: &str,
) -> Result<(), String> {
    if let (Some(value), Some(minimum)) = (
        instance.as_str(),
        schema.get("minLength").and_then(Value::as_u64),
    ) && value.chars().count() < minimum as usize
    {
        return Err(format!("{document}: {path} is shorter than {minimum}"));
    }
    Ok(())
}

fn validate_number(
    schema: &Map<String, Value>,
    instance: &Value,
    path: &str,
    document: &str,
) -> Result<(), String> {
    let Some(value) = instance.as_f64() else {
        return Ok(());
    };
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
        && value < minimum
    {
        return Err(format!("{document}: {path} is below {minimum}"));
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64)
        && value > maximum
    {
        return Err(format!("{document}: {path} is above {maximum}"));
    }
    Ok(())
}

fn resolve_local_reference<'a>(root: &'a Value, reference: &str) -> Result<&'a Value, String> {
    let pointer = reference
        .strip_prefix('#')
        .ok_or_else(|| format!("only local schema references are supported: {reference}"))?;
    root.pointer(pointer)
        .ok_or_else(|| format!("schema reference does not exist: {reference}"))
}

fn reject_unknown_assertions(schema: &Map<String, Value>, path: &str) -> Result<(), String> {
    const SUPPORTED: &[&str] = &[
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "title",
        "description",
        "oneOf",
        "type",
        "additionalProperties",
        "required",
        "properties",
        "const",
        "items",
        "maxItems",
        "minLength",
        "enum",
        "minimum",
        "maximum",
    ];
    for keyword in schema.keys() {
        if !SUPPORTED.contains(&keyword.as_str()) {
            return Err(format!("unsupported schema keyword {keyword:?} at {path}"));
        }
    }
    Ok(())
}
