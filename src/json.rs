pub type JsonObject = serde_json::Map<String, serde_json::Value>;

#[macro_export]
macro_rules! json_object {
    ($($key:expr => $value:expr),*) => {{
        let mut object = JsonObject::new();
        $(object.insert($key, $value);)*
        object
    }};
}
