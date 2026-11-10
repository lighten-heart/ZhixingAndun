"""JSON Schema validation with no remote references or unbounded regex dialect."""
import json
from jsonschema import Draft202012Validator


def validate_schema(schema):
    if len(json.dumps(schema)) > 16000:
        raise ValueError("JSON Schema exceeds limit")
    def walk(item, depth=0):
        if depth > 16:
            raise ValueError("JSON Schema nesting exceeds limit")
        if isinstance(item, dict):
            if any(k in item for k in ("$ref", "$dynamicRef", "$recursiveRef", "patternProperties")):
                raise ValueError("Schema references/patternProperties are not supported")
            if "pattern" in item:
                from .policy import safe_parameter_pattern
                safe_parameter_pattern(item["pattern"])
            for value in item.values():
                walk(value, depth + 1)
        elif isinstance(item, list):
            if len(item) > 100:
                raise ValueError("Schema array exceeds limit")
            for value in item:
                walk(value, depth + 1)
    walk(schema)
    Draft202012Validator.check_schema(schema)
    return schema


def schema_matches(schema, args):
    validate_schema(schema)
    return Draft202012Validator(schema).is_valid(args)
