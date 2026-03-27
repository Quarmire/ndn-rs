use serde::{Deserialize, Serialize};

/// A management command sent over the Unix socket.
///
/// Commands are JSON-encoded, newline-delimited on the socket.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ManagementRequest {
    /// Add a FIB route: `{"cmd":"add_route","prefix":"/ndn","face":1,"cost":10}`
    AddRoute {
        prefix: String,
        face:   u32,
        #[serde(default = "default_cost")]
        cost:   u32,
    },
    /// Remove a FIB route: `{"cmd":"remove_route","prefix":"/ndn","face":1}`
    RemoveRoute {
        prefix: String,
        face:   u32,
    },
    /// List all FIB routes.
    ListRoutes,
    /// List all registered faces.
    ListFaces,
    /// Get engine statistics (PIT size, CS stats).
    GetStats,
    /// Graceful shutdown.
    Shutdown,
}

/// Response to a management command.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ManagementResponse {
    Ok,
    OkData { data: serde_json::Value },
    Error { message: String },
}

fn default_cost() -> u32 { 10 }

/// Unix-socket management server.
///
/// Listens on a Unix socket path and dispatches `ManagementRequest` JSON
/// objects to handler callbacks. Each connection is a single request–response
/// pair (newline-delimited JSON).
pub struct ManagementServer {
    socket_path: std::path::PathBuf,
}

impl ManagementServer {
    /// Create a new management server bound to `socket_path`.
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self { socket_path: socket_path.into() }
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Decode a JSON management request from a line of text.
    pub fn decode_request(line: &str) -> Result<ManagementRequest, String> {
        serde_json::from_str(line).map_err(|e| e.to_string())
    }

    /// Encode a management response to a JSON string.
    pub fn encode_response(resp: &ManagementResponse) -> String {
        serde_json::to_string(resp).unwrap_or_else(|_| {
            r#"{"status":"error","message":"serialization failed"}"#.to_owned()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_add_route() {
        let json = r#"{"cmd":"add_route","prefix":"/ndn","face":1,"cost":20}"#;
        let req = ManagementServer::decode_request(json).unwrap();
        assert!(matches!(req, ManagementRequest::AddRoute { prefix, face: 1, cost: 20 } if prefix == "/ndn"));
    }

    #[test]
    fn decode_add_route_default_cost() {
        let json = r#"{"cmd":"add_route","prefix":"/local","face":0}"#;
        let req = ManagementServer::decode_request(json).unwrap();
        assert!(matches!(req, ManagementRequest::AddRoute { cost: 10, .. }));
    }

    #[test]
    fn decode_remove_route() {
        let json = r#"{"cmd":"remove_route","prefix":"/ndn","face":2}"#;
        let req = ManagementServer::decode_request(json).unwrap();
        assert!(matches!(req, ManagementRequest::RemoveRoute { face: 2, .. }));
    }

    #[test]
    fn decode_list_routes() {
        let req = ManagementServer::decode_request(r#"{"cmd":"list_routes"}"#).unwrap();
        assert!(matches!(req, ManagementRequest::ListRoutes));
    }

    #[test]
    fn decode_get_stats() {
        let req = ManagementServer::decode_request(r#"{"cmd":"get_stats"}"#).unwrap();
        assert!(matches!(req, ManagementRequest::GetStats));
    }

    #[test]
    fn decode_shutdown() {
        let req = ManagementServer::decode_request(r#"{"cmd":"shutdown"}"#).unwrap();
        assert!(matches!(req, ManagementRequest::Shutdown));
    }

    #[test]
    fn decode_invalid_json_returns_error() {
        let result = ManagementServer::decode_request("{bad json}");
        assert!(result.is_err());
    }

    #[test]
    fn encode_ok_response() {
        let s = ManagementServer::encode_response(&ManagementResponse::Ok);
        assert!(s.contains("ok"));
    }

    #[test]
    fn encode_error_response() {
        let s = ManagementServer::encode_response(&ManagementResponse::Error {
            message: "not found".into(),
        });
        assert!(s.contains("not found"));
    }

    #[test]
    fn management_server_stores_path() {
        let srv = ManagementServer::new("/tmp/ndn-mgmt.sock");
        assert_eq!(srv.socket_path(), std::path::Path::new("/tmp/ndn-mgmt.sock"));
    }
}
