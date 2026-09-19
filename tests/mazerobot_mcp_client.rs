use anyhow::Result;
use openmcpgdb::{ServerConfig, gdb::RealGdbBackendFactory, server::OpenMcpGdbServerFactory};
use rmcp::{
    ClientHandler, ServiceExt,
    model::{CallToolRequestParams, ClientConfig, ContentBlock},
};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::process::Command;

fn maze_codebase_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/mazerobot")
}

fn maze_binary_path() -> std::path::PathBuf {
    maze_codebase_dir().join("maze_robot")
}

fn maze_main_c() -> std::path::PathBuf {
    maze_codebase_dir().join("src/main.c")
}

#[derive(Debug, Clone, Default)]
struct MazeTestClient;

impl ClientHandler for MazeTestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

fn mazerobot_config() -> ServerConfig {
    ServerConfig {
        gdb_path: "/usr/bin/gdb".into(),
        gdb_options: String::new(),
        gdbserver_path: "gdbserver".into(),
        codebase_dir: maze_codebase_dir(),
        executable_path: maze_binary_path(),
        mcp_server_name: "MCP GDB Server".to_string(),
        mcp_server_url: "https://localhost:9443".to_string(),
        display_lines_before_current: 7,
        display_lines_after_current: 8,
        display_backtrace: 6,
        display_variable_list: 9,
        display_join_current_code: false,
    }
}

fn has_required_paths() -> bool {
    Path::new("/usr/bin/gdb").exists()
        && maze_codebase_dir().exists()
        && maze_binary_path().exists()
}

async fn ensure_mazerobot_executable() -> Result<()> {
    // Ensure the binary's DWARF comp_dir matches the current checkout path.
    // The committed binary was built at /home/brosnan/...; rebuild so absolute
    // breakpoint locations (maze_main_c():55) match the debug info.
    let _ = Command::new("make")
        .arg("-C")
        .arg(maze_codebase_dir())
        .arg("-B")
        .status()
        .await;

    let status = Command::new("chmod")
        .arg("+x")
        .arg(maze_binary_path())
        .status()
        .await?;

    anyhow::ensure!(
        status.success(),
        "chmod +x ./examples/mazerobot/maze_robot failed"
    );
    Ok(())
}

#[tokio::test]
async fn test_mcp_server_with_mazerobot_binary() -> Result<()> {
    if !has_required_paths() {
        eprintln!("Skipping test_mcp_server_with_mazerobot_binary: required paths missing");
        return Ok(());
    }

    ensure_mazerobot_executable().await?;

    let mut config = mazerobot_config();
    config.validate()?;

    let factory = OpenMcpGdbServerFactory::new(config, Arc::new(RealGdbBackendFactory));
    let server = factory.build();

    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_transport).await {
            let _ = running.waiting().await;
        }
    });

    let client = MazeTestClient.serve(client_transport).await?;

    let tools = client.list_all_tools().await?;
    assert!(
        tools.iter().any(|tool| tool.name == "gdb_execute"),
        "gdb_execute tool should be registered"
    );

    let binary = maze_binary_path().display().to_string();
    let execute_result = client
        .call_tool(
            CallToolRequestParams::new("gdb_execute").with_arguments(
                serde_json::json!({ "executable_path": binary })
                    .as_object()
                    .expect("execute args should be object")
                    .clone(),
            ),
        )
        .await?;

    assert_eq!(execute_result.is_error, Some(false));
    assert!(
        !execute_result.content.is_empty(),
        "execute tool should return debugger response"
    );

    let state_result = client
        .call_tool(CallToolRequestParams::new("gdb_debugger_state"))
        .await?;

    assert_eq!(state_result.is_error, Some(false));
    assert!(
        !state_result.content.is_empty(),
        "debugger_state tool should return debugger response"
    );

    let _ = client
        .call_tool(CallToolRequestParams::new("gdb_quit"))
        .await?;

    client.cancel().await?;
    let _ = server_task.await;
    Ok(())
}

fn parse_debugger_response(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    if let Some(structured) = &result.structured_content {
        return structured.clone();
    }

    for item in &result.content {
        if let ContentBlock::Text(text) = item
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text.text)
        {
            return value;
        }
    }

    serde_json::Value::Null
}

#[tokio::test]
async fn test_bug_invalid_print_symbol_is_recoverable_without_reset() -> Result<()> {
    if !has_required_paths() {
        eprintln!(
            "Skipping test_bug_invalid_print_symbol_is_recoverable_without_reset: required paths missing"
        );
        return Ok(());
    }

    ensure_mazerobot_executable().await?;

    let mut config = mazerobot_config();
    config.validate()?;

    let factory = OpenMcpGdbServerFactory::new(config, Arc::new(RealGdbBackendFactory));
    let server = factory.build();

    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_transport).await {
            let _ = running.waiting().await;
        }
    });

    let client = MazeTestClient.serve(client_transport).await?;

    let binary = maze_binary_path().display().to_string();
    let breakpoint_loc = format!("{}:55", maze_main_c().display());
    let execute_result = client
        .call_tool(
            CallToolRequestParams::new("gdb_execute").with_arguments(
                serde_json::json!({ "executable_path": binary })
                    .as_object()
                    .expect("execute args should be object")
                    .clone(),
            ),
        )
        .await?;
    assert_eq!(execute_result.is_error, Some(false));

    let breakpoint_result = client
        .call_tool(
            CallToolRequestParams::new("gdb_add_breakpoint").with_arguments(
                serde_json::json!({
                    "location": breakpoint_loc
                })
                .as_object()
                .expect("breakpoint args should be object")
                .clone(),
            ),
        )
        .await?;
    assert_eq!(breakpoint_result.is_error, Some(false));

    let run_result = client
        .call_tool(CallToolRequestParams::new("gdb_run"))
        .await?;
    assert_eq!(run_result.is_error, Some(false));

    let bad_print_result = client
        .call_tool(
            CallToolRequestParams::new("gdb_print").with_arguments(
                serde_json::json!({ "expression": "this_var_does_not_exist_anywhere" })
                    .as_object()
                    .expect("print args should be object")
                    .clone(),
            ),
        )
        .await?;
    let print_payload = parse_debugger_response(&bad_print_result);
    assert_eq!(
        print_payload
            .get("debugger_state")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "stopped at breakpoint",
        "invalid print symbol should be recoverable and keep prior stop state"
    );
    assert!(
        print_payload
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("no symbol"),
        "invalid print symbol should still return detailed error text"
    );

    let state_result = client
        .call_tool(CallToolRequestParams::new("gdb_debugger_state"))
        .await?;
    let state_payload = parse_debugger_response(&state_result);
    assert_eq!(
        state_payload
            .get("debugger_state")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "stopped at breakpoint",
        "debugger_state should not be globally poisoned after invalid print"
    );

    let _ = client
        .call_tool(CallToolRequestParams::new("gdb_quit"))
        .await?;

    client.cancel().await?;
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn test_bug_continue_while_running_returns_running_state() -> Result<()> {
    if !has_required_paths() {
        eprintln!(
            "Skipping test_bug_continue_while_running_returns_running_state: required paths missing"
        );
        return Ok(());
    }

    ensure_mazerobot_executable().await?;

    let mut config = mazerobot_config();
    config.validate()?;

    let factory = OpenMcpGdbServerFactory::new(config, Arc::new(RealGdbBackendFactory));
    let server = factory.build();

    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_transport).await {
            let _ = running.waiting().await;
        }
    });

    let client = MazeTestClient.serve(client_transport).await?;

    let binary = maze_binary_path().display().to_string();
    let breakpoint_loc = format!("{}:55", maze_main_c().display());
    let execute_result = client
        .call_tool(
            CallToolRequestParams::new("gdb_execute").with_arguments(
                serde_json::json!({ "executable_path": binary })
                    .as_object()
                    .expect("execute args should be object")
                    .clone(),
            ),
        )
        .await?;
    assert_eq!(execute_result.is_error, Some(false));

    let breakpoint_result = client
        .call_tool(
            CallToolRequestParams::new("gdb_add_breakpoint").with_arguments(
                serde_json::json!({
                    "location": breakpoint_loc
                })
                .as_object()
                .expect("breakpoint args should be object")
                .clone(),
            ),
        )
        .await?;
    assert_eq!(breakpoint_result.is_error, Some(false));

    let run_result = client
        .call_tool(CallToolRequestParams::new("gdb_run"))
        .await?;
    assert_eq!(run_result.is_error, Some(false));

    let clear_result = client
        .call_tool(
            CallToolRequestParams::new("gdb_clear_breakpoint").with_arguments(
                serde_json::json!({
                    "target": breakpoint_loc
                })
                .as_object()
                .expect("clear args should be object")
                .clone(),
            ),
        )
        .await?;
    assert_eq!(clear_result.is_error, Some(false));

    let continue_result = tokio::time::timeout(
        Duration::from_secs(10),
        client.call_tool(CallToolRequestParams::new("gdb_continue")),
    )
    .await
    .expect("gdb_continue should not hang")?;
    assert_eq!(continue_result.is_error, Some(false));

    let continue_payload = parse_debugger_response(&continue_result);
    assert_eq!(
        continue_payload
            .get("debugger_state")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "running",
        "continue without an immediate stop should return running state"
    );

    let _ = client
        .call_tool(CallToolRequestParams::new("gdb_kill"))
        .await?;
    let _ = client
        .call_tool(CallToolRequestParams::new("gdb_quit"))
        .await?;

    client.cancel().await?;
    let _ = server_task.await;
    Ok(())
}
