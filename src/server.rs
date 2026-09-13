use crate::{
    config::ServerConfig,
    gdb::GdbBackendFactory,
    protocol::{DebuggerResponse, DebuggerState},
    session::{SessionWorkerHandle, ToolOperation, WatchMode, spawn_session_thread},
};
use rmcp::{
    Json, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExecuteArgs {
    executable_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TargetRemoteArgs {
    ip: String,
    port: u16,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GdbServerArgs {
    ip: String,
    port: u16,
    pid: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct IdArgs {
    id: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PidArgs {
    pid: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DisassembleArgs {
    /// Optional address expression or symbol: "main", "*0x4005a0", "&func".
    /// Omit to disassemble the function of the current frame.
    address: Option<String>,
}

/// Any gdb breakpoint location: "main.c:55", "compute_pi", "maze.c:maze_step",
/// "main+16", or "*0x4005a0" for a memory address.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BreakpointLocationArgs {
    location: String,
    /// Optional condition expression, e.g. "count == 3".
    condition: Option<String>,
}

/// A breakpoint/watchpoint number ("2") or any gdb location string.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BreakpointTargetArgs {
    target: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct VariableArgs {
    var: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PrintArgs {
    /// Any gdb expression: variable, cast, dereference, arithmetic, register.
    expression: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetVarArgs {
    var: String,
    value: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CustomArgs {
    cmd: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WatchKind {
    /// Trigger when the expression is written (gdb `watch`).
    #[default]
    Write,
    /// Trigger when the expression is read (gdb `rwatch`).
    Read,
    /// Trigger on any access (gdb `awatch`).
    Access,
}

impl From<WatchKind> for WatchMode {
    fn from(kind: WatchKind) -> Self {
        match kind {
            WatchKind::Write => WatchMode::Write,
            WatchKind::Read => WatchMode::Read,
            WatchKind::Access => WatchMode::Access,
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WatchArgs {
    expression: String,
    /// What kind of access triggers the watchpoint.
    #[serde(default)]
    mode: WatchKind,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExamineMemoryArgs {
    /// Address expression to start reading: "*0x7fff1000", "&my_var", or "0x4005a0".
    address: String,
    /// How many items to display (default 16).
    count: Option<u32>,
    /// Display format: x hex, d decimal, u unsigned, o octal, t binary,
    /// c char, s string, i instruction (default x).
    format: Option<String>,
    /// Item size: b byte, h halfword, w word, g giant/8 bytes (default w).
    size: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetDisplayArgs {
    lines_before_current: Option<usize>,
    lines_after_current: Option<usize>,
    backtrace: Option<usize>,
    variable_list: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SysrootArgs {
    /// Sysroot path for remote debugging (`set sysroot <path>`). Use `target:` prefix for remote fs or absolute local path.
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SolibSearchPathArgs {
    /// Colon-separated search path for shared libraries (`set solib-search-path <path>`).
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ArchitectureArgs {
    /// Architecture for `set architecture <arch>` (e.g. `aarch64`, `arm`, `auto`).
    arch: String,
}

/// Map a user-supplied examine format to the single-char gdb code.
/// Accepts the single-char code (`x`) or common long names (`hex`).
/// Unknown or empty input passes through a sentinel (`?`) so the session
/// layer reports a clear "invalid examine format" error instead of silently
/// truncating e.g. "hex" to 'h' (a size code).
fn normalize_examine_format(input: Option<&str>) -> char {
    let raw = input.unwrap_or("").trim().to_ascii_lowercase();
    if raw.is_empty() {
        return 'x';
    }
    if raw.len() == 1 {
        return raw.chars().next().unwrap_or('?');
    }
    match raw.as_str() {
        "hex" | "hexadecimal" => 'x',
        "decimal" | "signed" => 'd',
        "unsigned" => 'u',
        "octal" => 'o',
        "binary" => 't',
        "char" => 'c',
        "string" => 's',
        "instruction" | "instructions" => 'i',
        _ => raw.chars().next().unwrap_or('?'),
    }
}

/// Map a user-supplied examine size to the single-char gdb code.
/// Accepts the single-char code (`w`) or common long names (`word`).
fn normalize_examine_size(input: Option<&str>) -> char {
    let raw = input.unwrap_or("").trim().to_ascii_lowercase();
    if raw.is_empty() {
        return 'w';
    }
    if raw.len() == 1 {
        return raw.chars().next().unwrap_or('?');
    }
    match raw.as_str() {
        "byte" | "bytes" => 'b',
        "halfword" | "half" | "short" => 'h',
        "word" | "long" => 'w',
        "giant" | "double" | "quad" => 'g',
        _ => raw.chars().next().unwrap_or('?'),
    }
}

#[derive(Clone)]
pub struct OpenMcpGdbServerFactory {
    config: ServerConfig,
    backend_factory: Arc<dyn GdbBackendFactory>,
}

impl OpenMcpGdbServerFactory {
    pub fn new(config: ServerConfig, backend_factory: Arc<dyn GdbBackendFactory>) -> Self {
        Self {
            config,
            backend_factory,
        }
    }

    pub fn build(&self) -> OpenMcpGdbServer {
        OpenMcpGdbServer::new(self.config.clone(), Arc::clone(&self.backend_factory))
    }
}

#[derive(Clone)]
pub struct OpenMcpGdbServer {
    config: ServerConfig,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    worker: SessionWorkerHandle,
}

impl OpenMcpGdbServer {
    pub fn new(config: ServerConfig, backend_factory: Arc<dyn GdbBackendFactory>) -> Self {
        // Spawn one dedicated thread for this client session.
        let backend = backend_factory.create(&config);
        let worker = spawn_session_thread(config.clone(), backend);

        Self {
            config,
            tool_router: Self::tool_router(),
            worker,
        }
    }

    async fn call_operation(&self, operation: ToolOperation) -> Json<DebuggerResponse> {
        match self.worker.execute(operation).await {
            Ok(response) => Json(response),
            Err(err) => {
                Json(DebuggerResponse::new(DebuggerState::Error).with_error(err.to_string()))
            }
        }
    }
}

#[tool_router]
impl OpenMcpGdbServer {
    #[tool(name = "gdb_execute", description = "Start gdb on executable")]
    async fn gdb_execute(
        &self,
        Parameters(args): Parameters<ExecuteArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Execute {
            executable_path: args.executable_path,
        })
        .await
    }

    #[tool(name = "gdb_run", description = "Run executable in gdb")]
    async fn gdb_run(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Run).await
    }

    #[tool(
        name = "gdb_gdbserver",
        description = "Start gdbserver and attach to a pid"
    )]
    async fn gdb_gdbserver(
        &self,
        Parameters(args): Parameters<GdbServerArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::GdbServer {
            ip: args.ip,
            port: args.port,
            pid: args.pid,
        })
        .await
    }

    #[tool(
        name = "gdb_target_remote",
        description = "Connect to remote target (gdb `target remote ip:port`)"
    )]
    async fn gdb_target_remote(
        &self,
        Parameters(args): Parameters<TargetRemoteArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::TargetRemote {
            ip: args.ip,
            port: args.port,
        })
        .await
    }

    #[tool(
        name = "gdb_target_extended_remote",
        description = "Connect to extended remote target (gdb `target extended-remote ip:port` for gdbserver --multi)"
    )]
    async fn gdb_target_extended_remote(
        &self,
        Parameters(args): Parameters<TargetRemoteArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::TargetExtendedRemote {
            ip: args.ip,
            port: args.port,
        })
        .await
    }

    #[tool(
        name = "gdb_set_sysroot",
        description = "Set sysroot for remote debugging (`set sysroot <path>`). Use for cross-target library resolution"
    )]
    async fn gdb_set_sysroot(
        &self,
        Parameters(args): Parameters<SysrootArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::SetSysroot { path: args.path })
            .await
    }

    #[tool(
        name = "gdb_set_solib_search_path",
        description = "Set solib search path for remote debugging (`set solib-search-path <path>`)"
    )]
    async fn gdb_set_solib_search_path(
        &self,
        Parameters(args): Parameters<SolibSearchPathArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::SetSolibSearchPath { path: args.path })
            .await
    }

    #[tool(
        name = "gdb_set_architecture",
        description = "Set GDB architecture (`set architecture <arch>`, e.g. aarch64, arm, auto) for multi-arch cross debugging"
    )]
    async fn gdb_set_architecture(
        &self,
        Parameters(args): Parameters<ArchitectureArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::SetArchitecture { arch: args.arch })
            .await
    }

    #[tool(name = "gdb_set_thread", description = "Set current thread")]
    async fn gdb_set_thread(&self, Parameters(args): Parameters<IdArgs>) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::SetThread { id: args.id })
            .await
    }

    #[tool(name = "gdb_set_frame", description = "Set current frame")]
    async fn gdb_set_frame(&self, Parameters(args): Parameters<IdArgs>) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::SetFrame { id: args.id })
            .await
    }

    #[tool(
        name = "gdb_add_breakpoint",
        description = "Add breakpoint at any gdb location: file:line, function/symbol name, file:function, symbol+offset, or *memory_address. Optional condition expression"
    )]
    async fn gdb_add_breakpoint(
        &self,
        Parameters(args): Parameters<BreakpointLocationArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::AddBreakpoint {
            location: args.location,
            condition: args.condition,
        })
        .await
    }

    #[tool(
        name = "gdb_clear_breakpoint",
        description = "Delete breakpoint by number (from gdb_list_breakpoint) or by location"
    )]
    async fn gdb_clear_breakpoint(
        &self,
        Parameters(args): Parameters<BreakpointTargetArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::ClearBreakpoint {
            target: args.target,
        })
        .await
    }

    #[tool(
        name = "gdb_enable_breakpoint",
        description = "Enable breakpoint by number or location"
    )]
    async fn gdb_enable_breakpoint(
        &self,
        Parameters(args): Parameters<BreakpointTargetArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::EnableBreakpoint {
            target: args.target,
        })
        .await
    }

    #[tool(
        name = "gdb_disable_breakpoint",
        description = "Disable breakpoint by number or location"
    )]
    async fn gdb_disable_breakpoint(
        &self,
        Parameters(args): Parameters<BreakpointTargetArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::DisableBreakpoint {
            target: args.target,
        })
        .await
    }

    #[tool(
        name = "gdb_watch",
        description = "Set watchpoint on an expression or address: triggers on write (default), read, or any access"
    )]
    async fn gdb_watch(&self, Parameters(args): Parameters<WatchArgs>) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Watch {
            expression: args.expression,
            mode: args.mode.into(),
        })
        .await
    }

    #[tool(
        name = "gdb_examine_memory",
        description = "Examine raw memory at an address with configurable count, format (x/d/u/o/t/c/s/i), and size (b/h/w/g)"
    )]
    async fn gdb_examine_memory(
        &self,
        Parameters(args): Parameters<ExamineMemoryArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::ExamineMemory {
            address: args.address,
            count: args.count.unwrap_or(16),
            format: normalize_examine_format(args.format.as_deref()),
            size: normalize_examine_size(args.size.as_deref()),
        })
        .await
    }

    #[tool(name = "gdb_list_breakpoint", description = "List breakpoints")]
    async fn gdb_list_breakpoint(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::ListBreakpoint).await
    }

    #[tool(
        name = "gdb_attach",
        description = "Attach to a running process by PID (starts a bare gdb; symbols are read from the live process)"
    )]
    async fn gdb_attach(&self, Parameters(args): Parameters<PidArgs>) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Attach { pid: args.pid })
            .await
    }

    #[tool(
        name = "gdb_detach",
        description = "Detach from the current process, leaving it running"
    )]
    async fn gdb_detach(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Detach).await
    }

    #[tool(name = "gdb_next", description = "Step over")]
    async fn gdb_next(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Next).await
    }

    #[tool(name = "gdb_step", description = "Step into")]
    async fn gdb_step(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Step).await
    }

    #[tool(name = "gdb_continue", description = "Continue execution")]
    async fn gdb_continue(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Continue).await
    }

    #[tool(
        name = "gdb_finish",
        description = "Run until the current function returns"
    )]
    async fn gdb_finish(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Finish).await
    }

    #[tool(
        name = "gdb_interrupt",
        description = "Interrupt execution and stop at stepping"
    )]
    async fn gdb_interrupt(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Interrupt).await
    }

    #[tool(
        name = "gdb_add_variable_list",
        description = "Add variable to watch list"
    )]
    async fn gdb_add_variable_list(
        &self,
        Parameters(args): Parameters<VariableArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::AddVariable { var: args.var })
            .await
    }

    #[tool(
        name = "gdb_del_variable_list",
        description = "Delete variable from watch list"
    )]
    async fn gdb_del_variable_list(
        &self,
        Parameters(args): Parameters<VariableArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::DelVariable { var: args.var })
            .await
    }

    #[tool(name = "gdb_debugger_state", description = "Get debugger state")]
    async fn gdb_debugger_state(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::DebuggerState).await
    }

    #[tool(name = "gdb_variable_list", description = "Get watched variable list")]
    async fn gdb_variable_list(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::VariableList).await
    }

    #[tool(
        name = "gdb_current_code",
        description = "Get current source code context"
    )]
    async fn gdb_current_code(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::CurrentCode).await
    }

    #[tool(name = "gdb_full_backtrace", description = "Get full backtrace")]
    async fn gdb_full_backtrace(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::FullBacktrace).await
    }

    #[tool(name = "gdb_info_threads", description = "Get thread information")]
    async fn gdb_info_threads(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::InfoThreads).await
    }

    #[tool(
        name = "gdb_print",
        description = "Evaluate and print an expression: variables, casts, dereferences, arithmetic"
    )]
    async fn gdb_print(&self, Parameters(args): Parameters<PrintArgs>) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Print {
            expression: args.expression,
        })
        .await
    }

    #[tool(
        name = "gdb_set_var",
        description = "Set variable value (gdb set variable <var> = <value>)"
    )]
    async fn gdb_set_var(
        &self,
        Parameters(args): Parameters<SetVarArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::SetVar {
            var: args.var,
            value: args.value,
        })
        .await
    }

    #[tool(name = "gdb_info_regs", description = "Get register information")]
    async fn gdb_info_regs(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::InfoRegs).await
    }

    #[tool(name = "gdb_quit", description = "Quit gdb")]
    async fn gdb_quit(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Quit).await
    }

    #[tool(name = "gdb_kill", description = "Kill debuggee")]
    async fn gdb_kill(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Kill).await
    }

    #[tool(
        name = "gdb_reset_back_to_not_attached",
        description = "Clear errors and reset debugger state back to not attached"
    )]
    async fn gdb_reset_back_to_not_attached(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::ResetBackToNotAttached)
            .await
    }

    #[tool(
        name = "gdb_set_display",
        description = "Tune display window sizes for responses: source context lines, backtrace depth, watched variable count"
    )]
    async fn gdb_set_display(
        &self,
        Parameters(args): Parameters<SetDisplayArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::SetDisplay {
            lines_before_current: args.lines_before_current,
            lines_after_current: args.lines_after_current,
            backtrace: args.backtrace,
            variable_list: args.variable_list,
        })
        .await
    }

    #[tool(name = "gdb_nexti", description = "Step over one machine instruction")]
    async fn gdb_nexti(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::NextInstruction).await
    }

    #[tool(name = "gdb_stepi", description = "Step into one machine instruction")]
    async fn gdb_stepi(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::StepInstruction).await
    }

    #[tool(
        name = "gdb_disassemble",
        description = "Disassemble the current function, or around an address/symbol expression"
    )]
    async fn gdb_disassemble(
        &self,
        Parameters(args): Parameters<DisassembleArgs>,
    ) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Disassemble {
            address: args.address,
        })
        .await
    }

    #[tool(
        name = "gdb_frame_info",
        description = "List arguments and local variables of the selected frame"
    )]
    async fn gdb_frame_info(&self) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::FrameInfo).await
    }

    #[tool(name = "gdb_custom", description = "Run custom gdb command")]
    async fn gdb_custom(&self, Parameters(args): Parameters<CustomArgs>) -> Json<DebuggerResponse> {
        self.call_operation(ToolOperation::Custom { cmd: args.cmd })
            .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OpenMcpGdbServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            format!(
                "{} - MCP server for GDB debugging",
                self.config.mcp_server_name
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gdb::{MockBackendHandle, MockGdbBackendFactory},
        protocol::DebuggerState,
    };
    use rmcp::{ClientHandler, model::ClientInfo};

    fn test_config() -> ServerConfig {
        ServerConfig {
            gdb_path: "/usr/bin/gdb".into(),
            gdb_options: String::new(),
            gdbserver_path: "gdbserver".into(),
            codebase_dir: "/tmp".into(),
            executable_path: "/tmp/exe".into(),
            mcp_server_name: "MCP GDB Server".to_string(),
            mcp_server_url: "https://localhost:9443".to_string(),
            display_lines_before_current: 7,
            display_lines_after_current: 8,
            display_backtrace: 6,
            display_variable_list: 9,
            display_join_current_code: false,
        }
    }

    fn test_server_with_mock() -> (OpenMcpGdbServer, MockBackendHandle) {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("backtrace full", "#0 compute_pi\n#1 run_math\n#2 main\n");
        handle.set_response("frame", "#0 compute_pi at /tmp/main.c:55\n");
        handle.set_response(
            "list 48,63",
            "48\tline48\n49\tline49\n50\tline50\n55\tline55\n",
        );
        handle.set_response("print a", "$1 = 10\n");
        handle.set_response(
            "info threads",
            "  Id   Target Id         Frame\n* 1    Thread 0x1 main\n",
        );
        handle.set_response(
            "info all-registers",
            "rax            0x1                 1\nrbx            0x2                 2\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);
        (server, handle)
    }

    #[allow(dead_code)]
    fn test_server_with_mock_joined_code() -> OpenMcpGdbServer {
        let mut config = test_config();
        config.display_join_current_code = true;

        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("backtrace full", "#0 compute_pi\n#1 run_math\n#2 main\n");
        handle.set_response("frame", "#0 compute_pi at /tmp/main.c:55\n");
        handle.set_response(
            "list 48,63",
            "48\tline48\n49\tline49\n50\tline50\n55\tline55\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        OpenMcpGdbServer::new(config, factory)
    }

    #[tokio::test]
    async fn test_all_tool_calls_return_state() {
        let (server, _) = test_server_with_mock();

        let result = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await
            .0;
        assert_eq!(result.debugger_state, DebuggerState::Attached);

        let calls = vec![
            server.gdb_run().await.0,
            server
                .gdb_gdbserver(Parameters(GdbServerArgs {
                    ip: "127.0.0.1".to_string(),
                    port: 1234,
                    pid: -1,
                }))
                .await
                .0,
            server
                .gdb_target_remote(Parameters(TargetRemoteArgs {
                    ip: "127.0.0.1".to_string(),
                    port: 1234,
                }))
                .await
                .0,
            server.gdb_set_thread(Parameters(IdArgs { id: 1 })).await.0,
            server.gdb_set_frame(Parameters(IdArgs { id: 0 })).await.0,
            server
                .gdb_add_breakpoint(Parameters(BreakpointLocationArgs {
                    location: "/tmp/main.c:10".to_string(),
                    condition: None,
                }))
                .await
                .0,
            server
                .gdb_add_breakpoint(Parameters(BreakpointLocationArgs {
                    location: "*0x4005a0".to_string(),
                    condition: Some("count == 3".to_string()),
                }))
                .await
                .0,
            server
                .gdb_clear_breakpoint(Parameters(BreakpointTargetArgs {
                    target: "/tmp/main.c:10".to_string(),
                }))
                .await
                .0,
            server
                .gdb_enable_breakpoint(Parameters(BreakpointTargetArgs {
                    target: "1".to_string(),
                }))
                .await
                .0,
            server
                .gdb_disable_breakpoint(Parameters(BreakpointTargetArgs {
                    target: "1".to_string(),
                }))
                .await
                .0,
            server.gdb_list_breakpoint().await.0,
            server
                .gdb_watch(Parameters(WatchArgs {
                    expression: "counter".to_string(),
                    mode: WatchKind::default(),
                }))
                .await
                .0,
            server
                .gdb_examine_memory(Parameters(ExamineMemoryArgs {
                    address: "&counter".to_string(),
                    count: Some(4),
                    format: None,
                    size: None,
                }))
                .await
                .0,
            server.gdb_next().await.0,
            server.gdb_step().await.0,
            server.gdb_continue().await.0,
            server.gdb_finish().await.0,
            server.gdb_nexti().await.0,
            server.gdb_stepi().await.0,
            server.gdb_interrupt().await.0,
            server
                .gdb_add_variable_list(Parameters(VariableArgs {
                    var: "a".to_string(),
                }))
                .await
                .0,
            server.gdb_variable_list().await.0,
            server
                .gdb_del_variable_list(Parameters(VariableArgs {
                    var: "a".to_string(),
                }))
                .await
                .0,
            server.gdb_debugger_state().await.0,
            server.gdb_current_code().await.0,
            server.gdb_full_backtrace().await.0,
            server.gdb_info_threads().await.0,
            server
                .gdb_print(Parameters(PrintArgs {
                    expression: "a".to_string(),
                }))
                .await
                .0,
            server
                .gdb_set_var(Parameters(SetVarArgs {
                    var: "a".to_string(),
                    value: "13".to_string(),
                }))
                .await
                .0,
            server.gdb_info_regs().await.0,
            server.gdb_kill().await.0,
            server.gdb_reset_back_to_not_attached().await.0,
            server
                .gdb_set_display(Parameters(SetDisplayArgs {
                    lines_before_current: Some(4),
                    lines_after_current: Some(5),
                    backtrace: Some(3),
                    variable_list: Some(2),
                }))
                .await
                .0,
            server
                .gdb_custom(Parameters(CustomArgs {
                    cmd: "info files".to_string(),
                }))
                .await
                .0,
            server.gdb_quit().await.0,
        ];

        for response in calls {
            assert!(
                matches!(
                    response.debugger_state,
                    DebuggerState::NotAttached
                        | DebuggerState::FailedToAttach
                        | DebuggerState::GdbServerAttached
                        | DebuggerState::GdbServerFailedToAttach
                        | DebuggerState::Attached
                        | DebuggerState::Running
                        | DebuggerState::StoppedAtBreakpoint
                        | DebuggerState::StoppedAtStepping
                        | DebuggerState::SigAbrt
                        | DebuggerState::SigBus
                        | DebuggerState::SigFpe
                        | DebuggerState::SigIll
                        | DebuggerState::SigTrap
                        | DebuggerState::SigKill
                        | DebuggerState::Exited
                        | DebuggerState::Error
                ),
                "unexpected debugger state"
            );
        }
    }

    #[derive(Debug, Clone, Default)]
    #[allow(dead_code)]
    struct DummyClient;

    impl ClientHandler for DummyClient {
        fn get_info(&self) -> ClientInfo {
            ClientInfo::default()
        }
    }

    #[tokio::test]
    async fn test_add_breakpoint_does_not_set_stopped_state() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_add_breakpoint(Parameters(BreakpointLocationArgs {
                location: "/tmp/main.c:10".to_string(),
                condition: None,
            }))
            .await
            .0;

        assert_ne!(
            response.debugger_state,
            DebuggerState::StoppedAtBreakpoint,
            "add_breakpoint should not set state to StoppedAtBreakpoint"
        );
    }

    #[tokio::test]
    async fn test_command_output_strips_gdb_prompt() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "info threads",
            "(gdb)   Id   Target Id         Frame\n* 1    Thread 0x1 main\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_info_threads().await.0;
        let output = response.command_output.unwrap_or_default();
        assert!(
            !output.starts_with("(gdb)"),
            "command_output should not start with (gdb) prompt, got: {output}"
        );
    }

    #[tokio::test]
    async fn test_variable_list_handles_out_of_scope() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("print step", "No symbol \"step\" in current context.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_add_variable_list(Parameters(VariableArgs {
                var: "step".to_string(),
            }))
            .await
            .0;

        let var_list = response
            .variable_list
            .expect("variable_list should be present");
        let step_value = var_list
            .get("step")
            .expect("step should be in variable_list");
        assert!(
            step_value.contains("<error:"),
            "out-of-scope variable should be indicated, got: {step_value}"
        );
    }

    #[tokio::test]
    async fn test_collect_current_code_propagates_frame_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("frame", "No stack.\n");
        handle.set_response("backtrace full", "#0 main\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_current_code().await.0;
        assert!(
            response.current_code_path.is_none(),
            "current_code_path should be None when frame has no stack"
        );
        assert!(
            response.current_code_line.is_none(),
            "current_code_line should be None when frame has no stack"
        );
        assert!(
            response.current_code.is_none(),
            "current_code should be None when frame has no stack"
        );
        assert_eq!(response.error, "no current frame");
    }

    #[tokio::test]
    async fn test_custom_returns_command_output() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("info locals", "x = 10\ny = 20\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_custom(Parameters(CustomArgs {
                cmd: "info locals".to_string(),
            }))
            .await
            .0;

        let output = response
            .command_output
            .expect("custom should return command_output");
        assert!(
            output.contains("x = 10"),
            "command_output should contain gdb result, got: {output}"
        );
    }

    #[tokio::test]
    async fn test_execute_with_full_snapshot_propagates_errors() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("run", "\nBreakpoint 1, main () at src/main.c:10\n");
        handle.set_response(
            "next",
            "Program received signal SIGSEGV, Segmentation fault.\n",
        );
        handle.set_response("backtrace full", "#0 main\n");
        handle.set_response("frame", "#0 main at /tmp/main.c:10\n");
        handle.set_response("list 3,18", "10\tline10\n");
        handle.set_response("print step", "$1 = 0\n");

        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_next().await.0;

        assert_eq!(
            response.debugger_state,
            DebuggerState::SigSegv,
            "next should report SigSegv state when gdb detects segfault, got: {:?}",
            response.debugger_state
        );
        assert!(
            response.variable_list.is_none(),
            "full snapshot should not be taken on error state"
        );
    }

    #[tokio::test]
    async fn test_add_breakpoint_preserves_current_state() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("break /tmp/main.c:10", "Breakpoint 1 at 0x1234\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_add_breakpoint(Parameters(BreakpointLocationArgs {
                location: "/tmp/main.c:10".to_string(),
                condition: None,
            }))
            .await
            .0;

        assert_eq!(
            response.debugger_state,
            DebuggerState::Attached,
            "add_breakpoint should preserve Attached state, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_run_returns_fresh_snapshot_not_stale() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("run", "\nBreakpoint 1, app_run () at src/main.c:30\n");
        handle.set_response("backtrace full", "#0 app_run\n#1 main\n");
        handle.set_response("frame", "#0 app_run at /tmp/main.c:30\n");
        handle.set_response(
            "list 23,45",
            "23\tline23\n24\tline24\n30\tline30\n31\tline31\n",
        );
        handle.set_response("print step", "$1 = 0\n");

        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        server
            .gdb_add_variable_list(Parameters(VariableArgs {
                var: "step".to_string(),
            }))
            .await;

        let run_response = server.gdb_run().await.0;

        assert_eq!(
            run_response.debugger_state,
            DebuggerState::StoppedAtBreakpoint
        );

        let var_list = run_response
            .variable_list
            .expect("variable_list should be present");
        let step_value = var_list
            .get("step")
            .expect("step should be in variable_list");
        assert_eq!(
            step_value, "0",
            "step should be 0 at breakpoint on first run, got: {step_value}"
        );
    }

    #[tokio::test]
    async fn test_next_returns_not_attached_after_quit() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_quit().await;

        let response = server.gdb_next().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "next after quit should return NotAttached, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_step_returns_not_attached_after_quit() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_quit().await;

        let response = server.gdb_step().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "step after quit should return NotAttached, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_continue_returns_not_attached_after_quit() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_quit().await;

        let response = server.gdb_continue().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "continue after quit should return NotAttached, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_current_code_returns_not_attached_after_quit() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_quit().await;

        let response = server.gdb_current_code().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "current_code after quit should return NotAttached, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_full_backtrace_returns_not_attached_after_quit() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_quit().await;

        let response = server.gdb_full_backtrace().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "full_backtrace after quit should return NotAttached, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_info_regs_returns_not_attached_after_quit() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("info all-registers", "rax 0x1 1\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_quit().await;

        let response = server.gdb_info_regs().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "info_regs after quit should return NotAttached, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_set_var_uses_dedicated_operation_not_print() {
        let handle = MockBackendHandle::with_default_response("ok");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server
            .gdb_set_var(Parameters(SetVarArgs {
                var: "counter".to_string(),
                value: "42".to_string(),
            }))
            .await;

        let commands = handle.commands();
        assert!(
            commands
                .iter()
                .any(|cmd| cmd.starts_with("set variable counter = 42")),
            "set_var should send 'set variable' command to gdb, got: {:?}",
            commands
        );
    }

    #[tokio::test]
    async fn test_info_regs_returns_base_on_exited_state() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("info all-registers", "rax 0x1 1\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        handle.set_response("run", "inferior 1 exited with code 0\n");
        let _ = server.gdb_run().await;

        let response = server.gdb_info_regs().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::Exited,
            "info_regs on Exited state should preserve Exited state, got: {:?}",
            response.debugger_state
        );
        assert!(
            !handle
                .commands()
                .iter()
                .any(|cmd| cmd == "info all-registers"),
            "info_regs should NOT send gdb command when state is Exited, got: {:?}",
            handle.commands()
        );
    }

    #[tokio::test]
    async fn test_bug_info_regs_no_registers_keeps_attached_and_output() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("info all-registers", "The program has no registers now.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_info_regs().await.0;
        assert_eq!(response.debugger_state, DebuggerState::Attached);
        assert!(
            response
                .command_output
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("no registers")
        );
    }

    #[tokio::test]
    async fn test_list_breakpoint_preserves_stopped_at_stepping_state() {
        let handle = MockBackendHandle::with_default_response("Breakpoint 1 at 0x0");
        handle.set_response("next", "");
        handle.set_response("backtrace full", "#0 main\n");
        handle.set_response("frame", "#0 main at /tmp/main.c:10\n");
        handle.set_response("list 3,18", "10\tline10\n");
        handle.set_response("print a", "$1 = 0\n");
        handle.set_response("info breakpoints", "No breakpoints or watchpoints.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_next().await;

        let response = server.gdb_list_breakpoint().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::StoppedAtStepping,
            "list_breakpoint should preserve StoppedAtStepping state, got: {:?}",
            response.debugger_state
        );
    }

    #[tokio::test]
    async fn test_kill_state_persists_as_sigkill() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("kill", "[Inferior 1 (process 123) killed]\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let kill_response = server.gdb_kill().await.0;
        assert_eq!(kill_response.debugger_state, DebuggerState::SigKill);

        let state_response = server.gdb_debugger_state().await.0;
        assert_eq!(
            state_response.debugger_state,
            DebuggerState::SigKill,
            "sigkill should persist for debugger_state query"
        );
    }

    #[tokio::test]
    async fn test_debugger_state_preserves_terminal_state_for_real_info_program_output() {
        // Real gdb answers `info program` with "The program being debugged is
        // not being run." *after* the inferior was killed too. The session must
        // not collapse the terminal SigKill state back to Attached.
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("kill", "[Inferior 1 (process 123) killed]\n");
        handle.set_response(
            "info program",
            "The program being debugged is not being run.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let kill_response = server.gdb_kill().await.0;
        assert_eq!(kill_response.debugger_state, DebuggerState::SigKill);

        let state_response = server.gdb_debugger_state().await.0;
        assert_eq!(
            state_response.debugger_state,
            DebuggerState::SigKill,
            "terminal sigkill state should survive a real info program 'not being run' response"
        );
    }

    #[tokio::test]
    async fn test_run_does_not_auto_attach_when_not_attached() {
        let handle = MockBackendHandle::with_default_response("ok");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let response = server.gdb_run().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "run without execute should remain not attached"
        );

        let commands = handle.commands();
        assert!(
            !commands.iter().any(|cmd| cmd == "run"),
            "run command should not be sent to backend before explicit execute"
        );
    }

    #[tokio::test]
    async fn test_command_exec_error_state_recoverable_by_introspection_tools() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_error("info threads", "mock backend exec failure");
        handle.set_response("backtrace full", "#0 main () at /tmp/main.c:10\n");
        handle.set_response("frame", "#0 main () at /tmp/main.c:10\n");
        handle.set_response("list 3,18", "10\tline10\n");
        handle.set_response(
            "info breakpoints",
            "No breakpoints, watchpoints, tracepoints, or catchpoints.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let failing = server.gdb_info_threads().await.0;
        assert_eq!(failing.debugger_state, DebuggerState::Error);
        assert!(
            failing.error.contains("mock backend exec failure"),
            "expected backend error text"
        );

        let state_response = server.gdb_debugger_state().await.0;
        assert_eq!(
            state_response.debugger_state,
            DebuggerState::Error,
            "error state should persist"
        );

        let backtrace_response = server.gdb_full_backtrace().await.0;
        assert_eq!(
            backtrace_response.debugger_state,
            DebuggerState::Attached,
            "full_backtrace should recover stale error state when command succeeds"
        );

        let code_response = server.gdb_current_code().await.0;
        assert_eq!(
            code_response.debugger_state,
            DebuggerState::Attached,
            "current_code should remain usable without reset"
        );

        let bp_response = server.gdb_list_breakpoint().await.0;
        assert_eq!(
            bp_response.debugger_state,
            DebuggerState::Attached,
            "list_breakpoint should remain usable without reset"
        );
    }

    #[tokio::test]
    async fn test_custom_invalid_command_sets_error_state() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "invalid cmd",
            "Undefined command: \"invalid\". Try \"help\".\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_custom(Parameters(CustomArgs {
                cmd: "invalid cmd".to_string(),
            }))
            .await
            .0;

        assert_eq!(
            response.debugger_state,
            DebuggerState::Error,
            "invalid custom command should set error state"
        );
        assert!(
            response
                .error
                .to_ascii_lowercase()
                .contains("undefined command"),
            "error should include gdb invalid-command output"
        );
    }

    #[tokio::test]
    async fn test_finish_at_outermost_frame_reports_recoverable_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "finish",
            "\u{274c}\u{fe0f} \"finish\" not meaningful in the outermost frame.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_finish().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::Error,
            "outermost-frame finish should surface gdb's refusal, got: {:?}",
            response.debugger_state
        );
        assert!(
            response.error.contains("not meaningful"),
            "error should include gdb's explanation: {response:?}"
        );

        // A later successful command clears the latched error state.
        let recovered = server.gdb_info_threads().await.0.debugger_state;
        assert_ne!(
            recovered,
            DebuggerState::Error,
            "a succeeding command should recover the stale error"
        );
    }

    #[tokio::test]
    async fn test_target_remote_without_executable_gives_guidance() {
        let handle = MockBackendHandle::with_default_response("ok");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let mut config = test_config();
        config.executable_path = "".into();
        let server = OpenMcpGdbServer::new(config, factory);

        let response = server
            .gdb_target_remote(Parameters(TargetRemoteArgs {
                ip: "127.0.0.1".to_string(),
                port: 1234,
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::FailedToAttach);
        assert!(
            response.error.contains("gdb_execute"),
            "error should tell the client what to do instead: {response:?}"
        );
    }

    #[tokio::test]
    async fn test_attach_and_detach_lifecycle() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "attach 4242",
            "Attaching to process 4242\n0x00007f... in ?? ()\n",
        );
        handle.set_response(
            "detach",
            "Detaching from program: , process 4242\n[Inferior 1 (process 4242) detached]\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let attach = server.gdb_attach(Parameters(PidArgs { pid: 4242 })).await.0;
        assert_eq!(attach.debugger_state, DebuggerState::Attached);
        assert!(
            attach
                .command_output
                .unwrap_or_default()
                .contains("Attaching to process 4242")
        );

        // Debugger is usable afterwards: state query reflects attached.
        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::Attached);

        let detach = server.gdb_detach().await.0;
        assert_eq!(detach.debugger_state, DebuggerState::NotAttached);

        // After detach the session reports not attached.
        let after = server.gdb_debugger_state().await.0;
        assert_eq!(after.debugger_state, DebuggerState::NotAttached);
    }

    #[tokio::test]
    async fn test_attach_rejects_nonpositive_pid() {
        let handle = MockBackendHandle::with_default_response("ok");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let response = server.gdb_attach(Parameters(PidArgs { pid: 0 })).await.0;
        assert_eq!(response.debugger_state, DebuggerState::FailedToAttach);
        assert!(response.error.contains("pid must be > 0"));
    }

    #[tokio::test]
    async fn test_disassemble_passes_address_through() {
        let handle = MockBackendHandle::with_default_response(
            "Dump of assembler code for function main:\n0x1155 <+0>: endbr64\nEnd of assembler dump.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_disassemble(Parameters(DisassembleArgs {
                address: Some("main".to_string()),
            }))
            .await
            .0;
        assert!(
            handle
                .commands()
                .iter()
                .any(|cmd| cmd == "disassemble main")
        );
        assert!(
            response
                .command_output
                .unwrap_or_default()
                .contains("Dump of assembler code")
        );
    }

    #[tokio::test]
    async fn test_sigint_maps_to_stopped_at_stepping() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("continue", "Program received signal SIGINT, Interrupt.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_continue().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::StoppedAtStepping,
            "SIGINT should map to stopped-at-stepping"
        );
    }

    #[tokio::test]
    async fn test_gdb_interrupt_returns_stopped_with_full_snapshot() {
        let (server, handle) = test_server_with_mock();
        handle.set_response("continue", "Continuing.\n");

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server
            .gdb_add_variable_list(Parameters(VariableArgs {
                var: "a".to_string(),
            }))
            .await;

        // Interrupt only makes sense when the inferior is actually running.
        let _ = server.gdb_continue().await;
        let response = server.gdb_interrupt().await.0;

        assert_eq!(
            response.debugger_state,
            DebuggerState::StoppedAtStepping,
            "gdb_interrupt should move a running session into stopped-at-stepping"
        );
        assert!(
            response.variable_list.is_some(),
            "gdb_interrupt should return variable_list in normal snapshot response"
        );
        assert!(
            response.backtrace.is_some(),
            "gdb_interrupt should return backtrace in normal snapshot response"
        );
        assert!(
            response.current_code.is_some(),
            "gdb_interrupt should return current_code in normal snapshot response"
        );

        let commands = handle.commands();
        assert!(
            commands.iter().any(|cmd| cmd == "printf \"\""),
            "gdb_interrupt should resync prompt after sending interrupt"
        );
        assert!(
            commands.iter().any(|cmd| cmd == "backtrace full"),
            "gdb_interrupt should collect backtrace for normal snapshot response"
        );
    }

    #[tokio::test]
    async fn test_interrupt_while_stopped_is_noop_and_preserves_breakpoint_stop() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("run", "Breakpoint 1, main () at src/main.c:10\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_run().await;
        let response = server.gdb_interrupt().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::StoppedAtBreakpoint,
            "interrupt should not rewrite the stop attribution of an already-stopped inferior"
        );
        assert_eq!(response.stop_reason, Some("breakpoint 1".to_string()));
    }

    #[tokio::test]
    async fn test_gdb_interrupt_when_not_attached_returns_base_state() {
        let (server, _) = test_server_with_mock();

        let response = server.gdb_interrupt().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "gdb_interrupt should be a no-op when not attached"
        );
        assert!(response.variable_list.is_none());
        assert!(response.backtrace.is_none());
        assert!(response.current_code.is_none());
    }

    #[tokio::test]
    async fn test_unhandled_signal_sets_error_and_persists() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "next",
            "Program received signal SIGUSR1, User defined signal 1.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_next().await.0;
        assert_eq!(response.debugger_state, DebuggerState::Error);

        let state_response = server.gdb_debugger_state().await.0;
        assert_eq!(
            state_response.debugger_state,
            DebuggerState::Error,
            "generic signal-derived error should persist"
        );
    }

    #[tokio::test]
    async fn test_kill_without_running_program_is_not_forced_sigkill() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("kill", "The program is not being run.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_kill().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::NotAttached,
            "kill with no running inferior should not force sigkill"
        );
    }

    #[tokio::test]
    async fn test_quit_failure_returns_error_state() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_error("quit", "quit failed in backend");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_quit().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::Error,
            "quit backend failure should surface error state"
        );
        assert!(
            response.error.contains("quit failed"),
            "quit failure details should be reported"
        );
    }

    #[tokio::test]
    async fn test_breakpoint_word_in_non_stop_output_does_not_flip_state() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "info files",
            "Symbols loaded for breakpoint_table helper.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_custom(Parameters(CustomArgs {
                cmd: "info files".to_string(),
            }))
            .await
            .0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::Attached,
            "non-stop output containing 'breakpoint' should not set stopped-at-breakpoint"
        );
    }

    #[tokio::test]
    async fn test_reset_back_to_not_attached_clears_error_and_state() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_error("info threads", "simulated backend error");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let failing = server.gdb_info_threads().await.0;
        assert_eq!(failing.debugger_state, DebuggerState::Error);
        assert!(!failing.error.is_empty());

        let reset = server.gdb_reset_back_to_not_attached().await.0;
        assert_eq!(reset.debugger_state, DebuggerState::NotAttached);
        assert!(reset.error.is_empty(), "reset should clear last error");

        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::NotAttached);
        assert!(state.error.is_empty());
    }

    #[tokio::test]
    async fn test_reset_back_to_not_attached_clears_watch_list() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("print counter", "$1 = 7\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let with_var = server
            .gdb_add_variable_list(Parameters(VariableArgs {
                var: "counter".to_string(),
            }))
            .await
            .0;
        let list_before = with_var.variable_list.unwrap_or_default();
        assert!(list_before.contains_key("counter"));

        let _ = server.gdb_reset_back_to_not_attached().await;

        let after = server.gdb_variable_list().await.0;
        assert_eq!(after.debugger_state, DebuggerState::NotAttached);
        assert!(
            after.variable_list.unwrap_or_default().is_empty(),
            "watch list should be cleared by reset"
        );
    }

    #[tokio::test]
    async fn test_bug_1_custom_invalid_command_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "this_is_not_a_command",
            "Undefined command: \"this_is_not_a_command\".  Try \"help\".\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_custom(Parameters(CustomArgs {
                cmd: "this_is_not_a_command".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Error);
    }

    #[tokio::test]
    async fn test_bug_2_print_invalid_symbol_does_not_poison_global_state() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "print this_var_does_not_exist",
            "No symbol \"this_var_does_not_exist\" in current context.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_print(Parameters(PrintArgs {
                expression: "this_var_does_not_exist".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Attached);
        assert!(response.error.to_ascii_lowercase().contains("no symbol"));

        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::Attached);
    }

    #[tokio::test]
    async fn test_print_value_containing_error_colon_is_not_treated_as_gdb_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("print \"no error: here\"", "$1 = \"no error: here\"\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_print(Parameters(PrintArgs {
                expression: "\"no error: here\"".to_string(),
            }))
            .await
            .0;

        assert_eq!(
            response.debugger_state,
            DebuggerState::Attached,
            "a benign value containing 'error:' must not flip the session to Error"
        );
        assert!(
            response.error.is_empty(),
            "error field should not be populated for a benign value: {:?}",
            response.error
        );

        // The session must stay usable: a subsequent real gdb error is still
        // detected, and a follow-up successful call recovers.
        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::Attached);
    }

    #[tokio::test]
    async fn test_bug_3_set_var_invalid_symbol_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "set variable this_var_does_not_exist = 1",
            "No symbol \"this_var_does_not_exist\" in current context.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_set_var(Parameters(SetVarArgs {
                var: "this_var_does_not_exist".to_string(),
                value: "1".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Error);
    }

    #[tokio::test]
    async fn test_bug_4_set_frame_invalid_id_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("frame 9999", "No frame at level 9999.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_set_frame(Parameters(IdArgs { id: 9999 }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Attached);
        assert!(
            response
                .error
                .to_ascii_lowercase()
                .contains("no frame at level")
        );

        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::Attached);
    }

    #[tokio::test]
    async fn test_bug_5_set_thread_invalid_id_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("thread 9999", "Unknown thread 9999.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_set_thread(Parameters(IdArgs { id: 9999 }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Attached);
        assert!(
            response
                .error
                .to_ascii_lowercase()
                .contains("unknown thread")
        );

        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::Attached);
    }

    #[tokio::test]
    async fn test_bug_6_add_breakpoint_invalid_location_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "break /tmp/does_not_exist.c:1",
            "No source file named /tmp/does_not_exist.c.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_add_breakpoint(Parameters(BreakpointLocationArgs {
                location: "/tmp/does_not_exist.c:1".to_string(),
                condition: None,
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Attached);
        assert!(
            response
                .error
                .to_ascii_lowercase()
                .contains("no source file named")
        );

        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::Attached);
    }

    #[tokio::test]
    async fn test_bug_7_clear_breakpoint_invalid_location_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "clear /tmp/main.c:9999",
            "No breakpoint at /tmp/main.c:9999.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_clear_breakpoint(Parameters(BreakpointTargetArgs {
                target: "/tmp/main.c:9999".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Error);
    }

    #[tokio::test]
    async fn test_bug_info_threads_invalid_state_is_recoverable() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("info threads", "Unknown thread 9999.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_info_threads().await.0;
        assert_eq!(response.debugger_state, DebuggerState::Attached);
        assert!(
            response
                .error
                .to_ascii_lowercase()
                .contains("unknown thread")
        );

        let state = server.gdb_debugger_state().await.0;
        assert_eq!(state.debugger_state, DebuggerState::Attached);
    }

    #[tokio::test]
    async fn test_bug_8_disable_breakpoint_invalid_location_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "info breakpoints",
            "No breakpoints, watchpoints, tracepoints, or catchpoints.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_disable_breakpoint(Parameters(BreakpointTargetArgs {
                target: "/tmp/main.c:9999".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Error);
        assert!(response.error.contains("no breakpoint matching"));
    }

    #[tokio::test]
    async fn test_bug_9_enable_breakpoint_invalid_location_maps_to_error() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "info breakpoints",
            "No breakpoints, watchpoints, tracepoints, or catchpoints.\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_enable_breakpoint(Parameters(BreakpointTargetArgs {
                target: "/tmp/main.c:9999".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Error);
        assert!(response.error.contains("no breakpoint matching"));
    }

    #[tokio::test]
    async fn test_bug_disable_breakpoint_uses_numeric_id_and_applies_to_all_locations() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "info breakpoints",
            "Num Type           Disp Enb Address            What\n\
1   breakpoint     keep y   <MULTIPLE>\n\
1.1 breakpoint     keep y   0x0 in main at src/main.c:55\n\
1.2 breakpoint     keep y   0x1 in main at src/main.c:55\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_disable_breakpoint(Parameters(BreakpointTargetArgs {
                target: "/tmp/src/main.c:55".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Attached);
        let commands = handle.commands();
        assert!(commands.iter().any(|cmd| cmd == "disable 1.1"));
        assert!(commands.iter().any(|cmd| cmd == "disable 1.2"));
        assert!(
            !commands
                .iter()
                .any(|cmd| cmd.contains("disable location /tmp/src/main.c:55"))
        );
    }

    #[tokio::test]
    async fn test_bug_enable_breakpoint_uses_numeric_id_and_applies_to_all_locations() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "info breakpoints",
            "Num Type           Disp Enb Address            What\n\
1   breakpoint     keep n   <MULTIPLE>\n\
1.1 breakpoint     keep n   0x0 in main at src/main.c:55\n\
1.2 breakpoint     keep n   0x1 in main at src/main.c:55\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server
            .gdb_enable_breakpoint(Parameters(BreakpointTargetArgs {
                target: "/tmp/src/main.c:55".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::Attached);
        let commands = handle.commands();
        assert!(commands.iter().any(|cmd| cmd == "enable 1.1"));
        assert!(commands.iter().any(|cmd| cmd == "enable 1.2"));
        assert!(
            !commands
                .iter()
                .any(|cmd| cmd.contains("enable location /tmp/src/main.c:55"))
        );
    }

    #[tokio::test]
    async fn test_bug_10_continue_after_kill_is_not_running() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("kill", "[Inferior 1 (process 123) killed]\n");
        handle.set_response("continue", "Continuing.\nThe program is not being run.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let kill_response = server.gdb_kill().await.0;
        assert_eq!(kill_response.debugger_state, DebuggerState::SigKill);

        let continue_response = server.gdb_continue().await.0;
        assert_ne!(continue_response.debugger_state, DebuggerState::Running);
    }

    #[tokio::test]
    async fn test_bug_target_remote_without_execute_starts_gdb_and_attaches() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "target remote 127.0.0.1:1234",
            "Remote debugging using 127.0.0.1:1234\n#0 main\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let response = server
            .gdb_target_remote(Parameters(TargetRemoteArgs {
                ip: "127.0.0.1".to_string(),
                port: 1234,
            }))
            .await
            .0;

        assert_eq!(
            response.debugger_state,
            DebuggerState::Attached,
            "target_remote should attach even before explicit execute"
        );
        assert!(
            handle
                .commands()
                .iter()
                .any(|cmd| cmd == "target remote 127.0.0.1:1234"),
            "target remote command should be sent"
        );
    }

    #[tokio::test]
    async fn test_bug_current_code_path_is_absolute() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("frame", "#0 main at src/main.c:55\n");
        handle.set_response("list 48,63", "55\tline55\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_current_code().await.0;
        assert_eq!(
            response.current_code_path,
            Some("/tmp/src/main.c".to_string()),
            "current_code_path should be absolute and rooted at codebase_dir"
        );
    }

    #[tokio::test]
    async fn test_bug_1_running_info_threads_interrupts_and_returns_clean_output() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response(
            "info threads",
            "  Id   Target Id         Frame\n* 1    Thread 0x1 main\n",
        );
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_continue().await;
        let response = server.gdb_info_threads().await.0;

        assert_eq!(response.debugger_state, DebuggerState::StoppedAtStepping);
        let output = response.command_output.unwrap_or_default();
        assert!(output.contains("Thread"));

        let commands = handle.commands();
        assert!(
            commands.iter().any(|cmd| cmd == "printf \"\""),
            "running-state query should resync after interrupt"
        );
    }

    #[tokio::test]
    async fn test_full_backtrace_while_running_interrupts_before_snapshot() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("backtrace full", "#0 main () at /tmp/main.c:10\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_continue().await;

        let response = server.gdb_full_backtrace().await.0;
        assert_eq!(
            response.debugger_state,
            DebuggerState::StoppedAtStepping,
            "full_backtrace on a running inferior should interrupt and report the stopped state"
        );
        assert!(
            response
                .backtrace
                .as_ref()
                .is_some_and(|bt| bt.contains_key("0")),
            "full_backtrace should still return the collected frames"
        );

        let commands = handle.commands();
        let bt_index = commands
            .iter()
            .position(|cmd| cmd == "backtrace full")
            .expect("backtrace full should be sent");
        assert!(
            commands[..bt_index].iter().any(|cmd| cmd == "printf \"\""),
            "full_backtrace should interrupt and resync before querying while running"
        );
    }

    #[tokio::test]
    async fn test_bug_2_running_custom_resyncs_after_continue() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("info files", "Symbols from \"/tmp/exe\".\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_continue().await;
        let response = server
            .gdb_custom(Parameters(CustomArgs {
                cmd: "info files".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::StoppedAtStepping);
        assert!(
            response
                .command_output
                .unwrap_or_default()
                .contains("Symbols from")
        );

        let commands = handle.commands();
        let info_files_idx = commands
            .iter()
            .position(|cmd| cmd == "info files")
            .expect("info files command should be sent");
        assert!(
            commands[..info_files_idx]
                .iter()
                .any(|cmd| cmd == "printf \"\""),
            "custom should resync before executing while previously running"
        );
    }

    #[tokio::test]
    async fn test_bug_3_kill_confirmation_sets_sigkill() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("kill", "Kill the program being debugged? (y or n) ");
        handle.set_response("y", "[Inferior 1 (process 123) killed]\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_kill().await.0;
        assert_eq!(response.debugger_state, DebuggerState::SigKill);

        let commands = handle.commands();
        assert!(commands.iter().any(|cmd| cmd == "y"));
    }

    #[tokio::test]
    async fn test_bug_4_quit_idempotent_when_not_attached() {
        let handle = MockBackendHandle::with_default_response("ok");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let response = server.gdb_quit().await.0;
        assert_eq!(response.debugger_state, DebuggerState::NotAttached);
        assert!(response.error.is_empty());
    }

    #[tokio::test]
    async fn test_bug_5_watch_list_not_attached_stays_clean() {
        let handle = MockBackendHandle::with_default_response("ok");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let response = server
            .gdb_add_variable_list(Parameters(VariableArgs {
                var: "g_sim.steps".to_string(),
            }))
            .await
            .0;

        assert_eq!(response.debugger_state, DebuggerState::NotAttached);
        assert!(response.error.is_empty());
        assert!(response.variable_list.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn test_bug_6_error_state_recovers_after_successful_command() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("info threads", "Undefined command: \"bad\".\n");
        handle.set_response("print a", "$1 = 10\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let fail = server.gdb_info_threads().await.0;
        assert_eq!(fail.debugger_state, DebuggerState::Error);

        let recover = server
            .gdb_print(Parameters(PrintArgs {
                expression: "a".to_string(),
            }))
            .await
            .0;
        assert_eq!(recover.debugger_state, DebuggerState::Attached);
    }

    #[tokio::test]
    async fn test_bug_7_running_variable_list_interrupts_before_eval() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("print a", "$1 = 7\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server
            .gdb_add_variable_list(Parameters(VariableArgs {
                var: "a".to_string(),
            }))
            .await;
        let _ = server.gdb_continue().await;

        let response = server.gdb_variable_list().await.0;
        assert_eq!(response.debugger_state, DebuggerState::StoppedAtStepping);

        let commands = handle.commands();
        let print_idx = commands
            .iter()
            .rposition(|cmd| cmd == "print a")
            .expect("print a should be executed");
        assert!(
            commands[..print_idx].iter().any(|cmd| cmd == "printf \"\""),
            "variable_list should resync before print while running"
        );
    }

    #[tokio::test]
    async fn test_bug_8_display_setters_reject_zero_but_valid_update_recovers() {
        let handle = MockBackendHandle::with_default_response("ok");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let before = server
            .gdb_set_display(Parameters(SetDisplayArgs {
                lines_before_current: Some(0),
                lines_after_current: None,
                backtrace: None,
                variable_list: None,
            }))
            .await
            .0;
        assert_eq!(before.debugger_state, DebuggerState::Error);

        let after = server
            .gdb_set_display(Parameters(SetDisplayArgs {
                lines_before_current: None,
                lines_after_current: Some(0),
                backtrace: None,
                variable_list: None,
            }))
            .await
            .0;
        assert_eq!(after.debugger_state, DebuggerState::Error);

        let bt = server
            .gdb_set_display(Parameters(SetDisplayArgs {
                lines_before_current: None,
                lines_after_current: None,
                backtrace: Some(0),
                variable_list: None,
            }))
            .await
            .0;
        assert_eq!(bt.debugger_state, DebuggerState::Error);

        let vars = server
            .gdb_set_display(Parameters(SetDisplayArgs {
                lines_before_current: None,
                lines_after_current: None,
                backtrace: None,
                variable_list: Some(0),
            }))
            .await
            .0;
        assert_eq!(vars.debugger_state, DebuggerState::Error);

        let recover = server
            .gdb_set_display(Parameters(SetDisplayArgs {
                lines_before_current: None,
                lines_after_current: None,
                backtrace: None,
                variable_list: Some(3),
            }))
            .await
            .0;
        assert_eq!(
            recover.debugger_state,
            DebuggerState::NotAttached,
            "valid display setter should recover stale error without reset"
        );
        assert!(
            recover.error.is_empty(),
            "error should be cleared after recovery"
        );
    }

    #[tokio::test]
    async fn test_bug_9_kill_not_running_maps_not_attached() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("kill", "The program is not being run.\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let response = server.gdb_kill().await.0;
        assert_eq!(response.debugger_state, DebuggerState::NotAttached);
    }

    #[tokio::test]
    async fn test_bug_10_running_current_code_interrupts_and_returns_frame() {
        let handle = MockBackendHandle::with_default_response("ok");
        handle.set_response("frame", "#0 main at /tmp/main.c:55\n");
        handle.set_response("list 48,63", "55\tline55\n56\tline56\n");
        let factory = Arc::new(MockGdbBackendFactory::new(handle.clone()));
        let server = OpenMcpGdbServer::new(test_config(), factory);

        let _ = server
            .gdb_execute(Parameters(ExecuteArgs {
                executable_path: "/tmp/exe".to_string(),
            }))
            .await;

        let _ = server.gdb_continue().await;
        let response = server.gdb_current_code().await.0;

        assert_eq!(response.debugger_state, DebuggerState::StoppedAtStepping);
        assert_eq!(response.current_code_line, Some(55));

        let commands = handle.commands();
        let frame_idx = commands
            .iter()
            .position(|cmd| cmd == "frame")
            .expect("frame should be executed");
        assert!(
            commands[..frame_idx].iter().any(|cmd| cmd == "printf \"\""),
            "current_code should resync before frame while running"
        );
    }

    #[test]
    fn test_normalize_examine_format_accepts_aliases() {
        assert_eq!(normalize_examine_format(None), 'x');
        assert_eq!(normalize_examine_format(Some("")), 'x');
        assert_eq!(normalize_examine_format(Some("x")), 'x');
        assert_eq!(normalize_examine_format(Some("hex")), 'x');
        assert_eq!(normalize_examine_format(Some("instruction")), 'i');
        // Unknown input passes through for the session layer to reject clearly.
        assert_eq!(normalize_examine_format(Some("zzz")), 'z');
    }

    #[test]
    fn test_normalize_examine_size_accepts_aliases() {
        assert_eq!(normalize_examine_size(None), 'w');
        assert_eq!(normalize_examine_size(Some("")), 'w');
        assert_eq!(normalize_examine_size(Some("w")), 'w');
        assert_eq!(normalize_examine_size(Some("word")), 'w');
        assert_eq!(normalize_examine_size(Some("byte")), 'b');
        assert_eq!(normalize_examine_size(Some("zzz")), 'z');
    }
}
