use crate::{
    config::ServerConfig,
    error::{OpenMcpGdbError, Result},
    gdb::RealGdbBackendFactory,
    server::{OpenMcpGdbServer, OpenMcpGdbServerFactory},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{ServiceExt, transport};
use std::{path::Path, sync::Arc};
use tokio_util::sync::CancellationToken;
use url::Url;

pub async fn run_from_config_file(config_path: &Path) -> Result<()> {
    let config = ServerConfig::from_file(config_path)?;
    run_from_config(config).await
}

pub async fn run_from_config(mut config: ServerConfig) -> Result<()> {
    config.validate()?;

    let backend_factory = Arc::new(RealGdbBackendFactory);
    let server_factory = OpenMcpGdbServerFactory::new(config.clone(), backend_factory);

    if config.mcp_server_url.starts_with("stdio://") {
        return run_stdio_server(server_factory.build()).await;
    }

    let url = Url::parse(&config.mcp_server_url)
        .map_err(|err| OpenMcpGdbError::InvalidUrl(err.to_string()))?;
    match url.scheme() {
        "http" | "https" => run_http_server(url, server_factory).await,
        _ => Err(OpenMcpGdbError::InvalidUrl(
            "mcp_server_url must use stdio://, http://, or https://".to_string(),
        )),
    }
}

pub async fn run_stdio_server(server: OpenMcpGdbServer) -> Result<()> {
    // Stdio transport is the standard mode for Codex/Claude/opencode MCP clients.
    let transport = transport::stdio();
    let running = server
        .serve(transport)
        .await
        .map_err(|err| OpenMcpGdbError::Worker(err.to_string()))?;
    running
        .waiting()
        .await
        .map_err(|err| OpenMcpGdbError::Worker(err.to_string()))?;
    Ok(())
}

async fn run_http_server(url: Url, factory: OpenMcpGdbServerFactory) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| OpenMcpGdbError::InvalidUrl("missing host in mcp_server_url".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| OpenMcpGdbError::InvalidUrl("missing port in mcp_server_url".to_string()))?;

    // `Url::path()` returns "/" (never empty) for bare hosts like
    // `http://localhost:9443`, so treat both as "no path given".
    let raw_path = url.path();
    let normalized = if raw_path.is_empty() || raw_path == "/" {
        "/".to_string()
    } else {
        let trimmed = raw_path.trim_end_matches('/');
        if trimmed.is_empty() {
            "/".to_string()
        } else {
            trimmed.to_string()
        }
    };
    // Bare host serves at root via fallback; an explicit path (e.g. `/mcp`)
    // is nested. Default to `/mcp` only when needed by callers expecting it.
    let path = normalized;
    let bind_addr = format!("{host}:{port}");

    // rmcp manages per-client sessions for streamable-http mode.
    let cancellation_token = CancellationToken::new();
    let shutdown_token = cancellation_token.clone();
    let config = StreamableHttpServerConfig::default()
        .with_json_response(true)
        .with_cancellation_token(cancellation_token.child_token());

    let service: StreamableHttpService<OpenMcpGdbServer, LocalSessionManager> =
        StreamableHttpService::new(move || Ok(factory.build()), Default::default(), config);
    let router = if path == "/" {
        // axum disallows nesting at root; attach MCP service as router fallback.
        axum::Router::new().fallback_service(service)
    } else {
        axum::Router::new().nest_service(&path, service)
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(OpenMcpGdbError::Io)?;

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(shutdown_token))
        .await
        .map_err(OpenMcpGdbError::Io)?;
    Ok(())
}

async fn shutdown_signal(token: CancellationToken) {
    let _ = tokio::signal::ctrl_c().await;
    token.cancel();
}
