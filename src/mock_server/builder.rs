use crate::mock_server::bare_server::{BareMockServer, RequestRecording};
use crate::mock_server::exposed_server::InnerServer;
use crate::MockServer;
use rustls::{PrivateKey, ServerConfig};
use std::{fs::File, io::BufReader, net::TcpListener};

/// A builder providing a fluent API to assemble a [`MockServer`] step-by-step.  
/// Use [`MockServer::builder`] to get started.
pub struct MockServerBuilder {
    listener: Option<TcpListener>,
    tls_paths: Option<(String, String)>,
    record_incoming_requests: bool,
}

impl MockServerBuilder {
    pub(super) fn new() -> Self {
        Self {
            listener: None,
            tls_paths: None,
            record_incoming_requests: true,
        }
    }

    /// Each instance of [`MockServer`] is, by default, running on a random
    /// port available on your local machine.
    /// With `MockServerBuilder::listener` you can choose to start the `MockServer`
    /// instance on a specific port you have already bound.
    ///
    /// ### Example:
    /// ```rust
    /// use wiremock::MockServer;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Arrange
    ///     let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    ///     let expected_server_address = listener
    ///         .local_addr()
    ///         .expect("Failed to get server address.");
    ///
    ///     // Act
    ///     let mock_server = MockServer::builder().listener(listener).start().await;
    ///
    ///     // Assert
    ///     assert_eq!(&expected_server_address, mock_server.address());
    /// }
    /// ```
    pub fn listener(mut self, listener: TcpListener) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Use TLS with certificate
    pub fn with_cert(mut self, tls_cert_path: &str, tls_key_path: &str) -> Self {
        self.tls_paths = Some((tls_cert_path.to_string(), tls_key_path.to_string()));
        self
    }

    /// By default, [`MockServer`] will record all incoming requests to display
    /// more meaningful error messages when your expectations are not verified.
    ///
    /// This can sometimes be undesirable (e.g. a long-lived server serving
    /// high volumes of traffic) - you can disable request recording using
    /// `MockServerBuilder::disable_request_recording`.
    ///
    /// ### Example (Request recording disabled):
    ///
    /// ```rust
    /// use wiremock::MockServer;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Arrange
    ///     let mock_server = MockServer::builder().disable_request_recording().start().await;
    ///
    ///     // Act
    ///     let received_requests = mock_server.received_requests().await;
    ///     
    ///     // Assert
    ///     assert!(received_requests.is_none());
    /// }
    /// ```
    pub fn disable_request_recording(mut self) -> Self {
        self.record_incoming_requests = false;
        self
    }

    /// Finalise the builder to get an instance of a [`BareMockServer`].
    pub(super) async fn build_bare(self) -> BareMockServer {
        let listener = if let Some(listener) = self.listener {
            listener
        } else {
            TcpListener::bind("127.0.0.1:0").expect("Failed to bind an OS port for a mock server.")
        };
        let tls_cfg = self.tls_paths.and_then(|(ca_path, key_path)| {
            //TODO: Move this to file

            // Open certificate file.
            let certfile = File::open(&ca_path)
                .expect(format!("Failed to open tls cert file {}", &ca_path).as_str());
            let mut reader = BufReader::new(certfile);
            // Load and return certificate.
            let certs = rustls_pemfile::certs(&mut reader)
                .expect("Failed to read cert file")
                .into_iter()
                .map(rustls::Certificate)
                .collect();

            // Open private key file.
            let certfile = File::open(&key_path)
                .expect(format!("Failed to open tls key file {}", &key_path).as_str());
            let mut reader = BufReader::new(certfile);
            // Load and return certificate.
            let priv_keys =
                rustls_pemfile::pkcs8_private_keys(&mut reader).expect("Failed to read key file");

            assert!(priv_keys.len() == 1, "Only one private key accepted");
            let tls_config = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, PrivateKey(priv_keys[0].clone()))
                .expect("Failed to build server tls config");

            Some(tls_config)
        });

        let recording = if self.record_incoming_requests {
            RequestRecording::Enabled
        } else {
            RequestRecording::Disabled
        };
        BareMockServer::start(listener, recording, tls_cfg).await
    }

    /// Finalise the builder and launch the [`MockServer`] instance!
    pub async fn start(self) -> MockServer {
        MockServer::new(InnerServer::Bare(self.build_bare().await))
    }
}
