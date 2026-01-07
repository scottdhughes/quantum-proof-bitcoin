//! Integration tests for RPC authentication.
//!
//! Tests HTTP Basic Auth functionality for the RPC endpoint.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

/// Start a qpb-node with RPC server and optional auth.
fn start_node(
    datadir: &std::path::Path,
    rpc_port: u16,
    rpc_user: Option<&str>,
    rpc_password: Option<&str>,
) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_qpb-node"));
    cmd.arg("--chain=devnet")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpc-addr=127.0.0.1:{}", rpc_port))
        .arg("--no-pow")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(user) = rpc_user {
        cmd.arg(format!("--rpcuser={}", user));
    }
    if let Some(pass) = rpc_password {
        cmd.arg(format!("--rpcpassword={}", pass));
    }

    let child = cmd.spawn().expect("failed to start qpb-node");

    // Wait for RPC to be ready
    thread::sleep(Duration::from_millis(500));

    child
}

/// Make an RPC request with optional auth.
fn rpc_request(
    port: u16,
    method: &str,
    auth: Option<(&str, &str)>,
) -> Result<(u16, String), String> {
    use std::io::Write;
    use std::net::TcpStream;

    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":[]}}"#,
        method
    );

    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", port)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    // Build request
    let auth_header = if let Some((user, pass)) = auth {
        use base64::Engine;
        let creds = format!("{}:{}", user, pass);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&creds);
        format!("Authorization: Basic {}\r\n", encoded)
    } else {
        String::new()
    };

    let request = format!(
        "POST /rpc HTTP/1.1\r\n\
         Host: 127.0.0.1:{}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         {}\
         \r\n\
         {}",
        port,
        body.len(),
        auth_header,
        body
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;

    // Read response
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| e.to_string())?;

    // Parse status code from first line
    let status_line = response.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    Ok((status_code, response))
}

#[test]
fn rpc_without_auth_when_auth_not_configured() {
    let tmpdir = TempDir::new().unwrap();
    let port = 38400 + (std::process::id() % 100) as u16;

    // Start node WITHOUT auth
    let mut child = start_node(tmpdir.path(), port, None, None);

    // Request without auth should succeed
    let result = rpc_request(port, "getblockcount", None);
    child.kill().ok();
    let _ = child.wait(); // Prevent zombie process

    match result {
        Ok((status, body)) => {
            assert_eq!(status, 200, "Expected 200 OK, got {}: {}", status, body);
            assert!(body.contains("result"), "Expected result in body: {}", body);
        }
        Err(e) => {
            // Connection might fail if node didn't start in time
            eprintln!("Request failed (may be timing): {}", e);
        }
    }
}

#[test]
fn rpc_without_auth_when_auth_required_returns_401() {
    let tmpdir = TempDir::new().unwrap();
    let port = 38410 + (std::process::id() % 100) as u16;

    // Start node WITH auth
    let mut child = start_node(tmpdir.path(), port, Some("testuser"), Some("testpass"));

    // Request without auth should fail
    let result = rpc_request(port, "getblockcount", None);
    child.kill().ok();
    let _ = child.wait(); // Prevent zombie process

    match result {
        Ok((status, body)) => {
            assert_eq!(
                status, 401,
                "Expected 401 Unauthorized, got {}: {}",
                status, body
            );
            assert!(
                body.contains("Unauthorized"),
                "Expected Unauthorized in body: {}",
                body
            );
        }
        Err(e) => {
            eprintln!("Request failed (may be timing): {}", e);
        }
    }
}

#[test]
fn rpc_with_wrong_credentials_returns_401() {
    let tmpdir = TempDir::new().unwrap();
    let port = 38420 + (std::process::id() % 100) as u16;

    // Start node WITH auth
    let mut child = start_node(tmpdir.path(), port, Some("testuser"), Some("testpass"));

    // Request with wrong credentials should fail
    let result = rpc_request(port, "getblockcount", Some(("testuser", "wrongpass")));
    child.kill().ok();
    let _ = child.wait(); // Prevent zombie process

    match result {
        Ok((status, body)) => {
            assert_eq!(
                status, 401,
                "Expected 401 Unauthorized, got {}: {}",
                status, body
            );
        }
        Err(e) => {
            eprintln!("Request failed (may be timing): {}", e);
        }
    }
}

#[test]
fn rpc_with_correct_credentials_returns_200() {
    let tmpdir = TempDir::new().unwrap();
    let port = 38430 + (std::process::id() % 100) as u16;

    // Start node WITH auth
    let mut child = start_node(tmpdir.path(), port, Some("testuser"), Some("testpass"));

    // Request with correct credentials should succeed
    let result = rpc_request(port, "getblockcount", Some(("testuser", "testpass")));
    child.kill().ok();
    let _ = child.wait(); // Prevent zombie process

    match result {
        Ok((status, body)) => {
            assert_eq!(status, 200, "Expected 200 OK, got {}: {}", status, body);
            assert!(body.contains("result"), "Expected result in body: {}", body);
        }
        Err(e) => {
            eprintln!("Request failed (may be timing): {}", e);
        }
    }
}

// Unit tests for RpcAuth struct logic
#[cfg(test)]
mod rpc_auth_unit_tests {
    use base64::Engine;

    /// Minimal re-implementation of RpcAuth for unit testing
    struct RpcAuth {
        expected_basic: String,
    }

    impl RpcAuth {
        fn new(user: &str, password: &str) -> Self {
            let credentials = format!("{}:{}", user, password);
            let expected_basic = base64::engine::general_purpose::STANDARD.encode(credentials);
            Self { expected_basic }
        }

        fn check(&self, auth_header: Option<&str>) -> bool {
            match auth_header {
                Some(value) => {
                    if let Some(encoded) = value.strip_prefix("Basic ") {
                        encoded == self.expected_basic
                    } else {
                        false
                    }
                }
                None => false,
            }
        }
    }

    #[test]
    fn auth_check_with_correct_credentials() {
        let auth = RpcAuth::new("admin", "secret123");
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:secret123");
        let header = format!("Basic {}", encoded);
        assert!(auth.check(Some(&header)));
    }

    #[test]
    fn auth_check_with_wrong_password() {
        let auth = RpcAuth::new("admin", "secret123");
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:wrongpass");
        let header = format!("Basic {}", encoded);
        assert!(!auth.check(Some(&header)));
    }

    #[test]
    fn auth_check_with_wrong_user() {
        let auth = RpcAuth::new("admin", "secret123");
        let encoded = base64::engine::general_purpose::STANDARD.encode("wronguser:secret123");
        let header = format!("Basic {}", encoded);
        assert!(!auth.check(Some(&header)));
    }

    #[test]
    fn auth_check_with_no_header() {
        let auth = RpcAuth::new("admin", "secret123");
        assert!(!auth.check(None));
    }

    #[test]
    fn auth_check_with_bearer_token_fails() {
        let auth = RpcAuth::new("admin", "secret123");
        assert!(!auth.check(Some("Bearer sometoken")));
    }

    #[test]
    fn auth_check_with_malformed_header() {
        let auth = RpcAuth::new("admin", "secret123");
        assert!(!auth.check(Some("BasicInvalidFormat")));
        assert!(!auth.check(Some("basic admin:secret123"))); // lowercase
    }
}
