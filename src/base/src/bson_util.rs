use bson::Document;
use bson::RawDocumentBuf;
use bson::{Array, Bson};
use error::NanoError;
use proto::database_proto::structured_query::composite_filter::Operator as CompositeOp;
use proto::database_proto::structured_query::field_filter::Operator;
use proto::database_proto::structured_query::filter::FilterType;
use proto::database_proto::structured_query::value::ValueType;
use proto::database_proto::structured_query::Filter;
use proto::database_proto::structured_query::Value;
use proto::database_proto::structured_query::{CompositeFilter, FieldFilter};
use proto::database_proto::{index::IndexField, Index};
use serde_json::Value as JsonValue;

pub fn json_str_to_bson_document(json_str: &str) -> std::result::Result<Document, NanoError> {
    let value: JsonValue =
        serde_json::from_str(json_str).map_err(|e| NanoError::InvalidJson(format!("{}", e)))?;
    let bson_document =
        bson::to_document(&value).map_err(|e| NanoError::InvalidDocumentBytes(format!("{}", e)))?;
    Ok(bson_document)
}

pub fn json_str_to_index(json_str: &str, idx: u32) -> std::result::Result<Index, NanoError> {
    let value: JsonValue =
        serde_json::from_str(json_str).map_err(|e| NanoError::InvalidJson(format!("{}", e)))?;

    if let Some(name) = value.get("name") {
        if let Some(fields) = value.get("fields") {
            return Ok(Index {
                id: idx,
                name: name.as_str().unwrap().to_string(),
                fields: fields
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|field| serde_json::from_value::<IndexField>(field.clone()).unwrap())
                    .collect(),
            });
        }
    }
    Err(NanoError::InvalidJson(format!("")))
}

pub fn json_str_to_bson_bytes(json_str: &str) -> std::result::Result<Vec<u8>, NanoError> {
    match json_str_to_bson_document(json_str) {
        Ok(doc) => Ok(bson_document_into_bytes(&doc)),
        Err(err) => Err(err),
    }
}

pub fn bytes_to_bson_document(buf: Vec<u8>) -> std::result::Result<Document, NanoError> {
    let doc = RawDocumentBuf::from_bytes(buf)
        .map_err(|e| NanoError::InvalidDocumentBytes(format!("{}", e)))?;
    let bson_document = doc
        .to_document()
        .map_err(|e| NanoError::InvalidDocumentBytes(format!("{}", e)))
        .unwrap();
    Ok(bson_document)
}

pub fn bson_document_into_bytes(doc: &Document) -> Vec<u8> {
    let row_doc = RawDocumentBuf::from_document(doc).unwrap();
    row_doc.into_bytes()
}

pub fn bson_value_from_proto_value(value: &Value) -> std::result::Result<Bson, NanoError> {
    if let Some(value_type) = &value.value_type {
        match value_type {
            ValueType::BooleanValue(b) => Ok(Bson::Boolean(*b)),
            ValueType::IntegerValue(n) => Ok(Bson::Int64(*n)),
            ValueType::StringValue(s) => Ok(Bson::String(s.to_string())),
            _ => Err(NanoError::InvalidFilterValue(
                "value is not support".to_string(),
            )),
        }
    } else {
        Err(NanoError::InvalidFilterValue("value is none".to_string()))
    }
}

fn field_filter_from_json_value(
    filter_doc: &Document,
) -> std::result::Result<Option<Filter>, NanoError> {
    let field = filter_doc.get_str("field").map_err(|e| {
        NanoError::InvalidFilterJson(format!("filed is required in filter json for {e}"))
    })?;
    let value = match filter_doc.get("value") {
        Some(v) => filter_value_from_bson_value(v)?,
        None => {
            return Err(NanoError::InvalidFilterJson(
                "value is required in filter json".to_string(),
            ));
        }
    };

    let op_str = filter_doc
        .get_str("op")
        .map_err(|_| NanoError::InvalidFilterJson("op is required in filter json".to_string()))?;
    let op = match op_str {
        "==" => Operator::Equal,
        ">" => Operator::GreaterThan,
        "<" => Operator::LessThan,
        ">=" => Operator::GreaterThanOrEqual,
        "<=" => Operator::LessThanOrEqual,
        "!=" => {
            return Err(NanoError::InvalidFilterOp(format!(
                "OP {} un-support currently",
                op_str
            )));
        }
        _ => {
            return Err(NanoError::InvalidFilterOp(format!("Invalid OP {}", op_str)));
        }
    };

    Ok(Some(Filter {
        filter_type: Some(FilterType::FieldFilter(FieldFilter {
            field: field.to_string(),
            op: op.into(),
            value: Some(value),
        })),
    }))
}

fn composite_filter_from_json_value(
    filters_doc: &Array,
    op: CompositeOp,
) -> std::result::Result<Option<Filter>, NanoError> {
    if filters_doc.is_empty() {
        return Err(NanoError::InvalidFilterJson("filters is empty".to_string()));
    }
    let mut filters = vec![];
    for filter in filters_doc {
        if let Some(filter_doc) = filter.as_document() {
            let op_str = filter_doc.get_str("op").map_err(|_| {
                NanoError::InvalidFilterJson("op is required in filter json".to_string())
            })?;

            if op_str != "==" {
                return Err(NanoError::InvalidFilterJson(format!(
                    "{} is not support in composite filter",
                    op_str
                )));
            };
            if let Ok(Some(filter)) = field_filter_from_json_value(filter_doc) {
                filters.push(filter);
            } else {
                return Err(NanoError::InvalidFilterJson(
                    "invalid field filter".to_string(),
                ));
            }
        } else {
            return Err(NanoError::InvalidFilterJson("invalid document".to_string()));
        }
    }

    Ok(Some(Filter {
        filter_type: Some(FilterType::CompositeFilter(CompositeFilter {
            filters,
            op: op.into(),
        })),
    }))
}

pub fn filter_from_json_value(json_str: &str) -> std::result::Result<Option<Filter>, NanoError> {
    if json_str.is_empty() {
        Ok(None)
    } else {
        let filter_doc = json_str_to_bson_document(json_str)
            .map_err(|e| NanoError::InvalidFilterValue(format!("{:?}", e)))?;

        if filter_doc.contains_key("field") {
            field_filter_from_json_value(&filter_doc)
        } else if filter_doc.contains_key("AND") {
            if let Ok(filters) = filter_doc.get_array("AND") {
                composite_filter_from_json_value(filters, CompositeOp::And)
            } else {
                Err(NanoError::InvalidFilterJson(
                    "filter json is invalid".to_string(),
                ))
            }
        } else if filter_doc.contains_key("and") {
            if let Ok(filters) = filter_doc.get_array("and") {
                composite_filter_from_json_value(filters, CompositeOp::And)
            } else {
                Err(NanoError::InvalidFilterJson(
                    "filter json is invalid".to_string(),
                ))
            }
        } else {
            Err(NanoError::InvalidFilterJson(
                "filter json is invalid".to_string(),
            ))
        }
    }
}

pub fn filter_value_from_bson_value(value: &Bson) -> std::result::Result<Value, NanoError> {
    match value {
        Bson::Boolean(b) => Ok(Value {
            value_type: Some(ValueType::BooleanValue(*b)),
        }),
        Bson::Int32(n) => Ok(Value {
            value_type: Some(ValueType::IntegerValue(*n as i64)),
        }),
        Bson::Int64(n) => Ok(Value {
            value_type: Some(ValueType::IntegerValue(*n)),
        }),
        Bson::String(s) => Ok(Value {
            value_type: Some(ValueType::StringValue(s.to_string())),
        }),
        _ => Err(NanoError::InvalidFilterValue(format!(
            "type {:?} un-support for filter value",
            value.element_type()
        ))),
    }
}
