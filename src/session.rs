use crate::{
    config::ServerConfig,
    error::{OpenMcpGdbError, Result},
    gdb::GdbBackend,
    protocol::{BreakpointEntry, CurrentCodePayload, DebuggerResponse, DebuggerState},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    thread,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep};

#[derive(Debug)]
pub enum ToolOperation {
    Execute {
        executable_path: String,
    },
    Run,
    GdbServer {
        ip: String,
        port: u16,
        pid: i64,
    },
    TargetRemote {
        ip: String,
        port: u16,
    },
    TargetExtendedRemote {
        ip: String,
        port: u16,
    },
    SetSysroot {
        path: String,
    },
    SetSolibSearchPath {
        path: String,
    },
    SetArchitecture {
        arch: String,
    },
    SetThread {
        id: i64,
    },
    SetFrame {
        id: i64,
    },
    /// location accepts any gdb breakpoint location: file:line, symbol,
    /// function, file:function, symbol+offset, or *memory_address.
    AddBreakpoint {
        location: String,
        condition: Option<String>,
    },
    /// target is a breakpoint number or any gdb location string.
    ClearBreakpoint {
        target: String,
    },
    EnableBreakpoint {
        target: String,
    },
    DisableBreakpoint {
        target: String,
    },
    ListBreakpoint,
    /// Attach to a running process by PID (bare gdb, symbols from /proc).
    Attach {
        pid: i64,
    },
    Detach,
    Next,
    Step,
    Continue,
    Finish,
    Interrupt,
    AddVariable {
        var: String,
    },
    DelVariable {
        var: String,
    },
    DebuggerState,
    VariableList,
    CurrentCode,
    FullBacktrace,
    InfoThreads,
    Print {
        expression: String,
    },
    SetVar {
        var: String,
        value: String,
    },
    InfoRegs,
    Quit,
    Kill,
    ResetBackToNotAttached,
    SetDisplay {
        lines_before_current: Option<usize>,
        lines_after_current: Option<usize>,
        backtrace: Option<usize>,
        variable_list: Option<usize>,
    },
    Watch {
        expression: String,
        mode: WatchMode,
    },
    ExamineMemory {
        address: String,
        count: u32,
        format: char,
        size: char,
    },
    NextInstruction,
    StepInstruction,
    /// Disassemble the current function, or around an address/symbol.
    Disassemble {
        address: Option<String>,
    },
    /// List arguments and locals of the selected frame.
    FrameInfo,
    Custom {
        cmd: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchMode {
    Write,
    Read,
    Access,
}

impl WatchMode {
    fn command(&self) -> &'static str {
        match self {
            Self::Write => "watch",
            Self::Read => "rwatch",
            Self::Access => "awatch",
        }
    }
}

enum WorkerMessage {
    Execute {
        operation: ToolOperation,
        response_tx: oneshot::Sender<Result<DebuggerResponse>>,
    },
}

#[derive(Clone)]
pub struct SessionWorkerHandle {
    request_tx: mpsc::Sender<WorkerMessage>,
}

impl SessionWorkerHandle {
    pub async fn execute(&self, operation: ToolOperation) -> Result<DebuggerResponse> {
        let (response_tx, response_rx) = oneshot::channel();
        self.request_tx
            .send(WorkerMessage::Execute {
                operation,
                response_tx,
            })
            .await
            .map_err(|_| OpenMcpGdbError::SessionClosed)?;
        response_rx
            .await
            .map_err(|_| OpenMcpGdbError::SessionClosed)?
    }
}

pub fn spawn_session_thread(
    config: ServerConfig,
    mut backend: Box<dyn GdbBackend>,
) -> SessionWorkerHandle {
    let (request_tx, mut request_rx) = mpsc::channel::<WorkerMessage>(64);

    // Every client gets a dedicated worker thread and runtime for isolation.
    if let Err(err) = thread::Builder::new()
        .name("openmcpgdb-session".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    eprintln!("[openmcpgdb] failed to build session runtime: {err}");
                    return;
                }
            };

            runtime.block_on(async move {
                let mut core = SessionCore::new(config, &mut backend);
                while let Some(message) = request_rx.recv().await {
                    match message {
                        WorkerMessage::Execute {
                            operation,
                            response_tx,
                        } => {
                            let result = core.execute(operation).await;
                            let result = core.enrich_crash_response_result(result).await;
                            let _ = response_tx.send(result);
                        }
                    }
                }
                let _ = core.shutdown().await;
                let _ = backend.stop().await;
            });
        })
    {
        eprintln!("[openmcpgdb] failed to spawn session thread: {err}");
    }

    SessionWorkerHandle { request_tx }
}

struct SessionCore<'a> {
    config: ServerConfig,
    backend: &'a mut Box<dyn GdbBackend>,
    debugger_state: DebuggerState,
    /// Cause of the most recent stop, e.g. "breakpoint 1" or "sigsegv".
    stop_reason: Option<String>,
    watched_variables: Vec<String>,
    executable_path: Option<PathBuf>,
    gdbserver_child: Option<tokio::process::Child>,
    /// Background tasks that drain gdbserver's stdout/stderr pipes so a
    /// 64KB pipe buffer fill cannot block the inferior. Aborted on stop.
    gdbserver_tasks: Vec<tokio::task::JoinHandle<()>>,
    last_error: String,
    /// True after a successful `target remote` / `extended-remote` until quit/detach/reset.
    is_remote: bool,
}

impl<'a> SessionCore<'a> {
    async fn enrich_crash_response_result(
        &mut self,
        result: Result<DebuggerResponse>,
    ) -> Result<DebuggerResponse> {
        match result {
            Ok(response) => self.enrich_crash_response(response).await,
            Err(err) => Err(err),
        }
    }

    async fn enrich_crash_response(
        &mut self,
        mut response: DebuggerResponse,
    ) -> Result<DebuggerResponse> {
        if !matches!(
            response.debugger_state,
            DebuggerState::SigSegv | DebuggerState::SigFpe | DebuggerState::SigIll
        ) {
            return Ok(response);
        }

        if response.backtrace.is_some() {
            return Ok(response);
        }

        if self.executable_path.is_none() {
            return Ok(response);
        }

        let (backtrace, current_func) = self.collect_backtrace(true).await?;
        response.backtrace = Some(backtrace);
        if response.current_func.is_none() {
            response.current_func = current_func;
        }
        Ok(response)
    }

    fn recover_error_state_without_restart(&mut self) {
        if self.debugger_state == DebuggerState::Error {
            self.debugger_state = self.recoverable_base_state();
        }
        self.last_error.clear();
    }

    fn recoverable_base_state(&self) -> DebuggerState {
        if self.executable_path.is_some() {
            DebuggerState::Attached
        } else {
            DebuggerState::NotAttached
        }
    }

    /// True when the inferior process has ended (exited, or killed by a
    /// signal). `info program` answers "not being run" in that case too, so
    /// gdb_debugger_state must not collapse these terminal states to Attached.
    fn is_dead_or_exited_state(state: DebuggerState) -> bool {
        matches!(
            state,
            DebuggerState::Exited
                | DebuggerState::SigSegv
                | DebuggerState::SigAbrt
                | DebuggerState::SigBus
                | DebuggerState::SigFpe
                | DebuggerState::SigIll
                | DebuggerState::SigTrap
                | DebuggerState::SigTerm
                | DebuggerState::SigKill
        )
    }

    fn new(config: ServerConfig, backend: &'a mut Box<dyn GdbBackend>) -> Self {
        Self {
            config,
            backend,
            debugger_state: DebuggerState::NotAttached,
            stop_reason: None,
            watched_variables: Vec::new(),
            executable_path: None,
            gdbserver_child: None,
            gdbserver_tasks: Vec::new(),
            last_error: String::new(),
            is_remote: false,
        }
    }

    async fn execute(&mut self, operation: ToolOperation) -> Result<DebuggerResponse> {
        match operation {
            ToolOperation::Execute { executable_path } => {
                eprintln!(
                    "[gdb_execute] requested executable_path={}",
                    executable_path
                );
                self.execute_attach(executable_path).await
            }
            ToolOperation::Run => {
                eprintln!("[gdb_run] requested");
                self.execute_run().await
            }
            ToolOperation::GdbServer { ip, port, pid } => {
                self.execute_gdbserver(ip, port, pid).await
            }
            ToolOperation::TargetRemote { ip, port } => {
                self.execute_target_remote(ip, port, false).await
            }
            ToolOperation::TargetExtendedRemote { ip, port } => {
                self.execute_target_remote(ip, port, true).await
            }
            ToolOperation::SetSysroot { path } => self.execute_set_sysroot(&path).await,
            ToolOperation::SetSolibSearchPath { path } => {
                self.execute_set_solib_search_path(&path).await
            }
            ToolOperation::SetArchitecture { arch } => self.execute_set_architecture(&arch).await,
            ToolOperation::SetThread { id } => {
                self.execute_recoverable_command_with_output(&format!("thread {id}"), None)
                    .await
            }
            ToolOperation::SetFrame { id } => {
                self.execute_recoverable_command_with_output(&format!("frame {id}"), None)
                    .await
            }
            ToolOperation::AddBreakpoint {
                location,
                condition,
            } => {
                let mut command = format!("break {}", sanitize_gdb_input(&location));
                if let Some(condition) = condition
                    .as_deref()
                    .map(str::trim)
                    .filter(|condition| !condition.is_empty())
                {
                    command.push_str(&format!(" if {}", sanitize_gdb_input(condition)));
                }
                self.execute_recoverable_command_with_output(&command, None)
                    .await
            }
            ToolOperation::ClearBreakpoint { target } => {
                self.execute_breakpoint_delete(target).await
            }
            ToolOperation::EnableBreakpoint { target } => {
                self.execute_breakpoint_toggle(BreakpointToggle::Enable, &target)
                    .await
            }
            ToolOperation::DisableBreakpoint { target } => {
                self.execute_breakpoint_toggle(BreakpointToggle::Disable, &target)
                    .await
            }
            ToolOperation::ListBreakpoint => self.list_breakpoint_response().await,
            ToolOperation::Attach { pid } => self.execute_attach_pid(pid).await,
            ToolOperation::Detach => self.execute_detach().await,
            ToolOperation::Next => {
                self.execute_with_full_snapshot("next", DebuggerState::StoppedAtStepping)
                    .await
            }
            ToolOperation::Step => {
                self.execute_with_full_snapshot("step", DebuggerState::StoppedAtStepping)
                    .await
            }
            ToolOperation::Continue => {
                self.execute_with_full_snapshot("continue", DebuggerState::Running)
                    .await
            }
            ToolOperation::Finish => self.execute_finish().await,
            ToolOperation::Interrupt => self.execute_interrupt().await,
            ToolOperation::AddVariable { var } => {
                if !self
                    .watched_variables
                    .iter()
                    .any(|existing| existing == &var)
                {
                    self.watched_variables.push(var);
                }
                self.variable_list_response().await
            }
            ToolOperation::DelVariable { var } => {
                self.watched_variables.retain(|existing| existing != &var);
                self.variable_list_response().await
            }
            ToolOperation::DebuggerState => self.debugger_state_response().await,
            ToolOperation::VariableList => self.variable_list_response().await,
            ToolOperation::CurrentCode => self.current_code_response().await,
            ToolOperation::FullBacktrace => self.full_backtrace_response().await,
            ToolOperation::InfoThreads => {
                self.execute_recoverable_command_with_output("info threads", None)
                    .await
            }
            ToolOperation::Print { expression } => self.execute_print(&expression).await,
            ToolOperation::SetVar { var, value } => {
                self.execute_command(
                    &format!(
                        "set variable {} = {}",
                        sanitize_gdb_input(&var),
                        sanitize_gdb_input(&value)
                    ),
                    None,
                )
                .await
            }
            ToolOperation::InfoRegs => {
                if self.debugger_state == DebuggerState::NotAttached
                    || self.debugger_state == DebuggerState::FailedToAttach
                    || self.debugger_state == DebuggerState::GdbServerFailedToAttach
                    || self.debugger_state == DebuggerState::Exited
                {
                    return Ok(self.base_response());
                }
                self.execute_info_regs().await
            }
            ToolOperation::Quit => {
                if self.executable_path.is_none() {
                    let _ = self.stop_gdbserver_process().await;
                    let _ = self.backend.stop().await;
                    self.debugger_state = DebuggerState::NotAttached;
                    self.is_remote = false;
                    self.last_error.clear();
                    self.watched_variables.clear();
                    return Ok(self.base_response());
                }
                let _ = self.stop_gdbserver_process().await;
                // Interrupt running debuggee before sending quit command.
                if self.debugger_state == DebuggerState::Running {
                    let _ = self.backend.interrupt().await;
                }
                let quit_result = self.backend.exec("quit").await;
                let stop_result = self.backend.stop().await;

                match (quit_result, stop_result) {
                    (Ok(_), Ok(_)) => {
                        self.debugger_state = DebuggerState::NotAttached;
                        self.executable_path = None;
                        self.is_remote = false;
                        self.watched_variables.clear();
                        self.last_error.clear();
                        self.stop_reason = None;
                        Ok(self.base_response())
                    }
                    (quit_err, stop_err) => {
                        let mut errors = Vec::new();
                        if let Err(err) = quit_err {
                            errors.push(format!("quit failed: {err}"));
                        }
                        if let Err(err) = stop_err {
                            errors.push(format!("stop failed: {err}"));
                        }
                        self.debugger_state = DebuggerState::Error;
                        self.last_error = errors.join("; ");
                        Ok(self.base_response().with_error(self.last_error.clone()))
                    }
                }
            }
            ToolOperation::Kill => self.execute_kill().await,
            ToolOperation::ResetBackToNotAttached => {
                let _ = self.stop_gdbserver_process().await;
                let _ = self.backend.stop().await;
                self.debugger_state = DebuggerState::NotAttached;
                self.executable_path = None;
                self.is_remote = false;
                self.watched_variables.clear();
                self.last_error.clear();
                self.stop_reason = None;
                Ok(self.base_response())
            }
            ToolOperation::SetDisplay {
                lines_before_current,
                lines_after_current,
                backtrace,
                variable_list,
            } => {
                self.execute_set_display(
                    lines_before_current,
                    lines_after_current,
                    backtrace,
                    variable_list,
                )
                .await
            }
            ToolOperation::Watch { expression, mode } => {
                self.execute_watch(&expression, mode).await
            }
            ToolOperation::ExamineMemory {
                address,
                count,
                format,
                size,
            } => {
                self.execute_examine_memory(&address, count, format, size)
                    .await
            }
            ToolOperation::NextInstruction => {
                self.execute_with_full_snapshot("nexti", DebuggerState::StoppedAtStepping)
                    .await
            }
            ToolOperation::StepInstruction => {
                self.execute_with_full_snapshot("stepi", DebuggerState::StoppedAtStepping)
                    .await
            }
            ToolOperation::Disassemble { address } => {
                self.execute_disassemble(address.as_deref()).await
            }
            ToolOperation::FrameInfo => self.execute_frame_info().await,
            ToolOperation::Custom { cmd } => {
                let trimmed = cmd.trim_start().to_ascii_lowercase();
                let is_remote_cmd = trimmed.starts_with("target remote")
                    || trimmed.starts_with("target extended-remote");
                let resp = self.execute_command_with_output(&cmd, None).await?;
                if is_remote_cmd && resp.debugger_state != DebuggerState::Error {
                    // Custom remote target succeeded; track remote mode for run guards.
                    // GDB's success prints "Remote debugging using ..." and state stays Attached.
                    if resp.debugger_state == DebuggerState::Attached
                        || resp.debugger_state == DebuggerState::StoppedAtBreakpoint
                        || resp.debugger_state == DebuggerState::StoppedAtStepping
                    {
                        self.is_remote = true;
                    }
                }
                // Clearing remote flag on disconnect/detach via custom.
                if (trimmed.starts_with("detach") || trimmed.starts_with("disconnect"))
                    && resp.debugger_state == DebuggerState::NotAttached
                {
                    self.is_remote = false;
                }
                Ok(resp)
            }
        }
    }

    async fn execute_recoverable_command_with_output(
        &mut self,
        command: &str,
        fallback_state: Option<DebuggerState>,
    ) -> Result<DebuggerResponse> {
        let previous_state = self.debugger_state;
        let response = self
            .execute_command_with_output(command, fallback_state)
            .await?;
        if response.debugger_state != DebuggerState::Error {
            return Ok(response);
        }

        let error_text = response.error.to_ascii_lowercase();
        if !is_recoverable_command_error(&error_text) {
            return Ok(response);
        }

        let recovered_state = if previous_state == DebuggerState::Running {
            // A recoverable command issued while the inferior was running has
            // already interrupted it, so the inferior is actually stopped now.
            DebuggerState::StoppedAtStepping
        } else if previous_state == DebuggerState::Error {
            self.recoverable_base_state()
        } else {
            previous_state
        };
        self.debugger_state = recovered_state;
        self.last_error.clear();

        let mut soft_error_response = self.base_response();
        soft_error_response.error = response.error;
        soft_error_response.command_output = response.command_output;
        Ok(soft_error_response)
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.stop_gdbserver_process().await
    }

    async fn execute_attach(&mut self, executable_path: String) -> Result<DebuggerResponse> {
        let executable = PathBuf::from(executable_path.clone());
        if !executable.is_absolute() {
            self.debugger_state = DebuggerState::FailedToAttach;
            self.last_error = "executable_path must be absolute".to_string();
            eprintln!(
                "[gdb_execute] failed: executable path is not absolute: {}",
                executable_path
            );
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        match self.backend.start(&executable).await {
            Ok(_) => {
                self.executable_path = Some(executable);
                self.debugger_state = DebuggerState::Attached;
                self.is_remote = false;
                self.last_error.clear();
                self.stop_reason = None;
                eprintln!("[gdb_execute] success: gdb started for {}", executable_path);
                Ok(self.base_response())
            }
            Err(err) => {
                self.debugger_state = DebuggerState::FailedToAttach;
                self.last_error = err.to_string();
                eprintln!(
                    "[gdb_execute] failed to start gdb for {}: {}",
                    executable_path, self.last_error
                );
                Ok(self.base_response().with_error(self.last_error.clone()))
            }
        }
    }

    async fn execute_command(
        &mut self,
        command: &str,
        fallback_state: Option<DebuggerState>,
    ) -> Result<DebuggerResponse> {
        self.execute_command_internal(command, fallback_state, false)
            .await
    }

    async fn execute_command_with_output(
        &mut self,
        command: &str,
        fallback_state: Option<DebuggerState>,
    ) -> Result<DebuggerResponse> {
        self.execute_command_internal(command, fallback_state, true)
            .await
    }

    async fn execute_command_internal(
        &mut self,
        command: &str,
        fallback_state: Option<DebuggerState>,
        include_output: bool,
    ) -> Result<DebuggerResponse> {
        if self.executable_path.is_none() {
            // Tool commands must not implicitly attach/start gdb. Call execute first.
            return Ok(self.base_response());
        }

        if self.debugger_state == DebuggerState::Running && command != "continue" {
            // Re-sync command stream before issuing interactive queries after continue.
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }

        let previous_state = self.debugger_state;
        let result = self.backend.exec(command).await;
        match result {
            Ok(output) => {
                self.update_state_from_output(&output, fallback_state);
                if self.debugger_state == DebuggerState::Error {
                    self.last_error = normalized_command_output(&output)
                        .unwrap_or_else(|| "gdb command failed".to_string());
                } else {
                    self.last_error.clear();
                }
                if self.debugger_state == DebuggerState::Error
                    && previous_state == DebuggerState::Error
                    && !looks_like_gdb_error(&output)
                {
                    // Allow recovery from previous Error state when a command succeeds.
                    self.debugger_state = self.recoverable_base_state();
                    self.last_error.clear();
                }
                // Make successful tool calls recoverable after stale error state.
                if self.debugger_state != DebuggerState::Error
                    && self.debugger_state != DebuggerState::FailedToAttach
                    && self.debugger_state != DebuggerState::GdbServerFailedToAttach
                {
                    self.last_error.clear();
                }
                if command == "run" {
                    eprintln!(
                        "[gdb_run] success: debugger_state={:?}, gdb_output={}",
                        self.debugger_state,
                        output.trim()
                    );
                }
                let mut response = self.base_response();
                if include_output {
                    response.command_output = normalized_command_output(&output);
                }
                Ok(response)
            }
            Err(err) => {
                self.last_error = err.to_string();
                self.debugger_state = DebuggerState::Error;
                if command == "run" {
                    eprintln!("[gdb_run] failed: {}", self.last_error);
                }
                let response = self.base_response().with_error(self.last_error.clone());
                Ok(response)
            }
        }
    }

    async fn execute_print(&mut self, var: &str) -> Result<DebuggerResponse> {
        let previous_state = self.debugger_state;
        let response = self
            .execute_command_with_output(&format!("print {}", sanitize_gdb_input(var)), None)
            .await?;

        if response.debugger_state != DebuggerState::Error {
            return Ok(response);
        }

        // Printing a symbol out of scope should be recoverable: keep session state and return
        // the command error text without forcing a global debugger error latch.
        let recovered_state = if previous_state == DebuggerState::Running {
            // Attempting a print while the inferior is running interrupts it
            // (via the resync in execute_command_internal), so the inferior is
            // actually stopped now. Do not report the stale Running status.
            DebuggerState::StoppedAtStepping
        } else if previous_state == DebuggerState::Error {
            if self.executable_path.is_some() {
                DebuggerState::Attached
            } else {
                DebuggerState::NotAttached
            }
        } else {
            previous_state
        };

        self.debugger_state = recovered_state;
        self.last_error.clear();

        let mut soft_error_response = self.base_response();
        soft_error_response.command_output = response.command_output;
        soft_error_response.error = response.error;
        Ok(soft_error_response)
    }

    async fn execute_info_regs(&mut self) -> Result<DebuggerResponse> {
        let response = self
            .execute_command_with_output("info all-registers", None)
            .await?;
        let output = response
            .command_output
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();

        if output.contains("no registers") || output.contains("has no registers") {
            // Keep session attached even when inferior is not currently stopped in a frame.
            self.debugger_state = DebuggerState::Attached;
            self.last_error.clear();
            let mut adjusted = self.base_response();
            adjusted.command_output = response.command_output;
            return Ok(adjusted);
        }

        Ok(response)
    }

    async fn execute_breakpoint_toggle(
        &mut self,
        action: BreakpointToggle,
        target: &str,
    ) -> Result<DebuggerResponse> {
        if self.executable_path.is_none() {
            return Ok(self.base_response());
        }

        if self.debugger_state == DebuggerState::Running {
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }

        let ids = if let Some(id) = parse_breakpoint_number(target) {
            vec![id.to_string()]
        } else {
            match self.resolve_breakpoint_ids_by_location(target).await {
                Ok(ids) => ids,
                Err(err) => {
                    self.debugger_state = DebuggerState::Error;
                    self.last_error = err.to_string();
                    return Ok(self.base_response().with_error(self.last_error.clone()));
                }
            }
        };

        if ids.is_empty() {
            self.debugger_state = DebuggerState::Error;
            self.last_error = format!("no breakpoint matching {target:?} found");
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        for id in ids {
            let command = action.command_for_id(&id);
            let output = self.backend.exec(&command).await?;
            self.update_state_from_output(&output, None);
            if self.debugger_state == DebuggerState::Error {
                self.last_error = normalized_command_output(&output)
                    .unwrap_or_else(|| "gdb breakpoint operation failed".to_string());
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
        }

        self.recover_error_state_without_restart();
        Ok(self.base_response())
    }

    /// Delete a breakpoint by gdb's breakpoint number or by any location form.
    async fn execute_breakpoint_delete(&mut self, target: String) -> Result<DebuggerResponse> {
        if self.executable_path.is_none() {
            return Ok(self.base_response());
        }

        if self.debugger_state == DebuggerState::Running {
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }

        // Numbers go straight to `delete N`; locations resolve to numbers first
        // so watchpoints and symbol locations delete reliably.
        if let Some(id) = parse_breakpoint_number(&target) {
            return self
                .execute_command_with_output(&format!("delete {id}"), None)
                .await;
        }

        let ids = match self.resolve_breakpoint_ids_by_location(&target).await {
            Ok(ids) => ids,
            Err(err) => {
                self.debugger_state = DebuggerState::Error;
                self.last_error = err.to_string();
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
        };

        if ids.is_empty() {
            self.debugger_state = DebuggerState::Error;
            self.last_error = format!("no breakpoint matching {target:?} found");
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        // GDB's `delete 1.1` fails with "bad breakpoint number", but `delete 1`
        // correctly removes all sub-breakpoints (1.1, 1.2). Collapse sub-ids to parents.
        let mut parents = std::collections::BTreeSet::new();
        for id in ids {
            let parent = id.split('.').next().unwrap_or(&id).to_string();
            parents.insert(parent);
        }
        let command = format!(
            "delete {}",
            parents.into_iter().collect::<Vec<_>>().join(" ")
        );
        self.execute_command_with_output(&command, None).await
    }

    /// Resolve a location string against the current breakpoint listing,
    /// returning the owning breakpoint numbers.
    async fn resolve_breakpoint_ids_by_location(&mut self, location: &str) -> Result<Vec<String>> {
        let output = self.backend.exec("info breakpoints").await?;
        Ok(resolve_breakpoint_ids_from_listing(&output, location))
    }

    async fn execute_set_display(
        &mut self,
        lines_before_current: Option<usize>,
        lines_after_current: Option<usize>,
        backtrace: Option<usize>,
        variable_list: Option<usize>,
    ) -> Result<DebuggerResponse> {
        let updates = [
            ("display_lines_before_current", lines_before_current),
            ("display_lines_after_current", lines_after_current),
            ("display_backtrace", backtrace),
            ("display_variable_list", variable_list),
        ];
        for (name, value) in updates {
            if value == Some(0) {
                self.last_error = format!("{name} must be > 0");
                self.debugger_state = DebuggerState::Error;
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
        }
        if let Some(size) = lines_before_current {
            self.config.display_lines_before_current = size;
        }
        if let Some(size) = lines_after_current {
            self.config.display_lines_after_current = size;
        }
        if let Some(size) = backtrace {
            self.config.display_backtrace = size;
        }
        if let Some(size) = variable_list {
            self.config.display_variable_list = size;
        }
        self.recover_error_state_without_restart();
        Ok(self.base_response())
    }

    /// Set a watchpoint on an expression: write (default), read, or access.
    async fn execute_watch(
        &mut self,
        expression: &str,
        mode: WatchMode,
    ) -> Result<DebuggerResponse> {
        let command = format!("{} {}", mode.command(), sanitize_gdb_input(expression));
        self.execute_recoverable_command_with_output(&command, None)
            .await
    }

    /// Examine memory at an address using gdb's x command with explicit
    /// count/format/size controls; returns parsed rows in `memory`.
    async fn execute_examine_memory(
        &mut self,
        address: &str,
        count: u32,
        format: char,
        size: char,
    ) -> Result<DebuggerResponse> {
        const VALID_FORMATS: [char; 8] = ['x', 'd', 'u', 'o', 't', 'c', 's', 'i'];
        const VALID_SIZES: [char; 4] = ['b', 'h', 'w', 'g'];
        if !VALID_FORMATS.contains(&format) {
            self.debugger_state = DebuggerState::Error;
            self.last_error = format!(
                "invalid examine format {format:?}; expected one of {}",
                VALID_FORMATS.iter().collect::<String>()
            );
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        if !VALID_SIZES.contains(&size) {
            self.debugger_state = DebuggerState::Error;
            self.last_error = format!(
                "invalid examine size {size:?}; expected one of {}",
                VALID_SIZES.iter().collect::<String>()
            );
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        if count == 0 {
            self.debugger_state = DebuggerState::Error;
            self.last_error = "examine count must be > 0".to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        let command = format!("x/{count}{format}{size} {}", sanitize_gdb_input(address));
        let response = self
            .execute_recoverable_command_with_output(&command, None)
            .await?;

        if response.debugger_state == DebuggerState::Error {
            return Ok(response);
        }

        // Surface parsed address->values rows alongside the raw output.
        if let Some(output) = &response.command_output {
            let memory = parse_examine_memory_rows(output);
            if !memory.is_empty() {
                let mut enriched = response;
                enriched.memory = Some(memory);
                return Ok(enriched);
            }
        }
        Ok(response)
    }

    /// Run until the current function returns.
    async fn execute_finish(&mut self) -> Result<DebuggerResponse> {
        if self.executable_path.is_none() {
            return Ok(self.base_response());
        }
        self.execute_with_full_snapshot("finish", DebuggerState::StoppedAtStepping)
            .await
    }

    /// Attach to a running process by PID. Starts a bare gdb (no symbol
    /// file required; gdb reads the live binary from /proc).
    async fn execute_attach_pid(&mut self, pid: i64) -> Result<DebuggerResponse> {
        if pid <= 0 {
            self.debugger_state = DebuggerState::FailedToAttach;
            self.last_error = "pid must be > 0".to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        match self.backend.start(Path::new("")).await {
            Ok(_) => {}
            Err(err) => {
                self.debugger_state = DebuggerState::FailedToAttach;
                self.last_error = err.to_string();
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
        }

        let attach_output = match self.backend.exec(&format!("attach {pid}")).await {
            Ok(output) => output,
            Err(err) => {
                self.debugger_state = DebuggerState::Error;
                self.last_error = err.to_string();
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
        };

        self.update_state_from_output(&attach_output, Some(DebuggerState::Attached));
        if matches!(
            self.debugger_state,
            DebuggerState::Error | DebuggerState::FailedToAttach
        ) {
            self.last_error = normalized_command_output(&attach_output)
                .unwrap_or_else(|| format!("failed to attach to pid {pid}"));
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        // Record a truthful absolute path so "attached" invariants hold.
        self.executable_path = Some(PathBuf::from(format!("/proc/{pid}/exe")));
        self.debugger_state = DebuggerState::Attached;
        self.is_remote = false;
        self.last_error.clear();
        self.stop_reason = None;
        let mut enriched = self.base_response();
        enriched.command_output = normalized_command_output(&attach_output);
        Ok(enriched)
    }

    /// Detach from the current process, leaving it running.
    async fn execute_detach(&mut self) -> Result<DebuggerResponse> {
        if self.executable_path.is_none() {
            return Ok(self.base_response());
        }

        if self.debugger_state == DebuggerState::Running {
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }

        let response = self.execute_command_with_output("detach", None).await?;
        if !matches!(
            response.debugger_state,
            DebuggerState::NotAttached | DebuggerState::Error
        ) {
            // gdb reports "Detaching from program ..." -> NotAttached via state mapping.
            self.debugger_state = DebuggerState::NotAttached;
        }
        if self.debugger_state == DebuggerState::NotAttached {
            self.executable_path = None;
            self.is_remote = false;
            self.watched_variables.clear();
            self.last_error.clear();
            self.stop_reason = None;
        } else if self.is_remote && response.debugger_state != DebuggerState::Error {
            // Successful detach from remote target clears remote flag.
            let out_lower = response
                .command_output
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if out_lower.contains("detaching") || out_lower.contains("disconnected") {
                self.is_remote = false;
            }
        }
        let mut final_response = self.base_response();
        final_response.command_output = response.command_output;
        Ok(final_response)
    }

    /// Disassemble the current function or around an address/symbol.
    async fn execute_disassemble(&mut self, address: Option<&str>) -> Result<DebuggerResponse> {
        let command = match address.map(str::trim).filter(|a| !a.is_empty()) {
            Some(address) => format!("disassemble {}", sanitize_gdb_input(address)),
            None => "disassemble".to_string(),
        };
        self.execute_recoverable_command_with_output(&command, None)
            .await
    }

    /// List arguments and locals of the selected frame as labeled text.
    async fn execute_frame_info(&mut self) -> Result<DebuggerResponse> {
        let args = self.execute_command_with_output("info args", None).await?;
        let locals = self
            .execute_command_with_output("info locals", None)
            .await?;

        let mut combined = String::new();
        combined.push_str("--- args ---\n");
        combined.push_str(args.command_output.as_deref().unwrap_or_default().trim());
        combined.push_str("\n--- locals ---\n");
        combined.push_str(locals.command_output.as_deref().unwrap_or_default().trim());

        let mut response = self.base_response();
        if !args.error.is_empty() && !locals.error.is_empty() {
            response.error = format!("{}; {}", args.error, locals.error);
        } else if !args.error.is_empty() {
            response.error = args.error;
        } else if !locals.error.is_empty() {
            response.error = locals.error;
        }
        response.command_output = Some(combined);
        Ok(response)
    }

    async fn execute_run(&mut self) -> Result<DebuggerResponse> {
        if self.is_remote {
            self.debugger_state = DebuggerState::Error;
            self.last_error = "run is not valid for remote targets; use gdb_continue (and gdb_target_remote / gdb_target_extended_remote was used for remote debugging)".to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        let response = self
            .execute_command("run", Some(DebuggerState::Running))
            .await?;

        // Per spec, when run stops at a breakpoint, return the full normal response.
        if response.debugger_state == DebuggerState::StoppedAtBreakpoint {
            return self.full_snapshot_response().await;
        }

        Ok(response)
    }

    async fn execute_gdbserver(
        &mut self,
        ip: String,
        port: u16,
        pid: i64,
    ) -> Result<DebuggerResponse> {
        if pid <= 0 {
            self.debugger_state = DebuggerState::GdbServerFailedToAttach;
            self.last_error = "pid must be > 0".to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        let _ = self.stop_gdbserver_process().await;

        let endpoint = format!("{ip}:{port}");
        let mut command = tokio::process::Command::new(&self.config.gdbserver_path);
        command
            .arg("--attach")
            .arg(&endpoint)
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child_result = command.spawn();
        let mut child = match child_result {
            Ok(child) => child,
            Err(err) => {
                self.debugger_state = DebuggerState::GdbServerFailedToAttach;
                self.last_error = format!(
                    "failed to start gdbserver ({}): {err}",
                    self.config.gdbserver_path.display()
                );
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
        };

        // Give gdbserver time to bind and fail fast if port is busy.
        // Poll for up to ~600ms and capture stderr on early exit.
        let mut early_status = None;
        for _ in 0..6 {
            sleep(Duration::from_millis(100)).await;
            match child.try_wait().map_err(OpenMcpGdbError::Io)? {
                Some(status) => {
                    early_status = Some(status);
                    break;
                }
                None => continue,
            }
        }
        if let Some(status) = early_status {
            // Try to collect stderr for diagnostics.
            let mut stderr_buf = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                use tokio::io::AsyncReadExt as _;
                let mut buf = Vec::new();
                let _ =
                    tokio::time::timeout(Duration::from_millis(200), stderr.read_to_end(&mut buf))
                        .await;
                stderr_buf = String::from_utf8_lossy(&buf).trim().to_string();
            }
            // Reap the exited child so it does not linger as a zombie.
            let _ = child.wait().await;
            self.debugger_state = DebuggerState::GdbServerFailedToAttach;
            if stderr_buf.is_empty() {
                self.last_error = format!("gdbserver exited early with status: {status}");
            } else {
                self.last_error =
                    format!("gdbserver exited early with status: {status}: {stderr_buf}");
            }
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        self.stop_reason = None;
        // gdbserver runs a real inferior in the background whose stdout/stderr
        // land in these pipes. Drain them continuously (to a sink), otherwise
        // the kernel pipe buffer (~64KB) fills up and blocks the inferior.
        let child_stdout = child.stdout.take();
        let child_stderr = child.stderr.take();
        self.gdbserver_child = Some(child);
        if let Some(stream) = child_stdout {
            let handle = tokio::spawn(async move {
                let mut reader = stream;
                let mut sink = tokio::io::sink();
                let _ = tokio::io::copy(&mut reader, &mut sink).await;
            });
            self.gdbserver_tasks.push(handle);
        }
        if let Some(stream) = child_stderr {
            let handle = tokio::spawn(async move {
                let mut reader = stream;
                let mut sink = tokio::io::sink();
                let _ = tokio::io::copy(&mut reader, &mut sink).await;
            });
            self.gdbserver_tasks.push(handle);
        }
        self.debugger_state = DebuggerState::GdbServerAttached;
        self.last_error.clear();
        Ok(self.base_response())
    }

    async fn execute_target_remote(
        &mut self,
        ip: String,
        port: u16,
        extended: bool,
    ) -> Result<DebuggerResponse> {
        // Remote attach still requires a local gdb process. If it is not started yet,
        // start gdb with configured executable for symbols before target remote.
        if self.executable_path.is_none() {
            if self.config.executable_path.as_os_str().is_empty() {
                // executable_path is optional in the config; without a default
                // binary we cannot start gdb for symbols here.
                // For remote debugging the local symbol file should match the remote binary.
                self.debugger_state = DebuggerState::FailedToAttach;
                self.last_error = "no executable attached: run gdb_execute first with the local symbol file that matches the remote binary, or set executable_path in the config".to_string();
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
            match self.backend.start(&self.config.executable_path).await {
                Ok(_) => {
                    self.executable_path = Some(self.config.executable_path.clone());
                    self.debugger_state = DebuggerState::Attached;
                    self.last_error.clear();
                }
                Err(err) => {
                    self.debugger_state = DebuggerState::FailedToAttach;
                    self.last_error = err.to_string();
                    return Ok(self.base_response().with_error(self.last_error.clone()));
                }
            }
        }

        let cmd = if extended {
            format!("target extended-remote {ip}:{port}")
        } else {
            format!("target remote {ip}:{port}")
        };
        let response = self
            .execute_command(&cmd, Some(DebuggerState::Attached))
            .await?;
        // Track remote mode only on success; errors should not flip the flag.
        // update_state_from_output will have set Error for connection failures.
        if response.debugger_state == DebuggerState::Attached
            || response.debugger_state == DebuggerState::StoppedAtBreakpoint
            || response.debugger_state == DebuggerState::StoppedAtStepping
        {
            // GDB prints "Remote debugging using ..." on success.
            // If we see Error, keep previous is_remote=false.
            self.is_remote = true;
        } else if response.debugger_state == DebuggerState::Error {
            // Do not mark as remote on failure.
        }
        // Return response with possibly updated base state (is_remote tracked separately).
        Ok(response)
    }

    async fn execute_set_sysroot(&mut self, path: &str) -> Result<DebuggerResponse> {
        let sanitized = sanitize_gdb_input(path.trim());
        if sanitized.is_empty() {
            self.debugger_state = DebuggerState::Error;
            self.last_error = "sysroot path must not be empty".to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        self.execute_command(&format!("set sysroot {sanitized}"), None)
            .await
    }

    async fn execute_set_solib_search_path(&mut self, path: &str) -> Result<DebuggerResponse> {
        let sanitized = sanitize_gdb_input(path.trim());
        if sanitized.is_empty() {
            self.debugger_state = DebuggerState::Error;
            self.last_error = "solib-search-path must not be empty".to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        self.execute_command(&format!("set solib-search-path {sanitized}"), None)
            .await
    }

    async fn execute_set_architecture(&mut self, arch: &str) -> Result<DebuggerResponse> {
        let sanitized = sanitize_gdb_input(arch.trim());
        if sanitized.is_empty() {
            self.debugger_state = DebuggerState::Error;
            self.last_error = "architecture must not be empty".to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }
        // `set architecture auto` lets GDB pick from ELF; explicit `aarch64` etc. forces it.
        self.execute_command(&format!("set architecture {sanitized}"), None)
            .await
    }

    async fn debugger_state_response(&mut self) -> Result<DebuggerResponse> {
        // If not attached nothing to query.
        if self.executable_path.is_none()
            || matches!(
                self.debugger_state,
                DebuggerState::NotAttached
                    | DebuggerState::FailedToAttach
                    | DebuggerState::GdbServerFailedToAttach
            )
        {
            return Ok(self.base_response());
        }
        // When the inferior is Running, GDB's synchronous CLI is busy and
        // `info program` would block until the program stops (or timeout).
        // To avoid a 10s stall on every poll, return the cached Running state
        // quickly. Clients that need to detect a stop should poll via
        // `gdb_full_backtrace` / `gdb_info_threads` (which will interrupt and
        // resync) or wait for `gdb_continue` to report the stop.
        if self.debugger_state == DebuggerState::Running {
            return Ok(self.base_response());
        }
        // Query GDB for actual state without interrupting a running target if possible.
        // `info program` is cheap and reflects exit / signal conditions.
        let previous = self.debugger_state;
        let query_result = self.backend.exec("info program").await;
        match query_result {
            Ok(output) => {
                let lower = output.to_ascii_lowercase();
                let saved_state = self.debugger_state;
                let saved_reason = self.stop_reason.clone();
                self.update_state_from_output(&output, Some(saved_state));
                let new_state = self.debugger_state;
                if new_state == DebuggerState::Error && !looks_like_gdb_error(&output) {
                    self.debugger_state = previous;
                    self.stop_reason = saved_reason;
                } else if lower.contains("not being run") || lower.contains("no program") {
                    // Real gdb answers `info program` with "The program being
                    // debugged is not being run." both *before* the inferior
                    // starts and *after* it ended (killed / exited / crashed).
                    // Keep terminal process states instead of collapsing them
                    // back to Attached.
                    if !Self::is_dead_or_exited_state(saved_state) {
                        self.debugger_state = DebuggerState::Attached;
                    }
                } else if lower.contains("is executing") || lower.contains("is running") {
                    self.debugger_state = DebuggerState::Running;
                    self.stop_reason = None;
                } else if new_state != saved_state && new_state != DebuggerState::Error {
                    // keep inferred meaningful change (e.g., sigsegv)
                } else {
                    self.debugger_state = previous;
                    self.stop_reason = saved_reason;
                    if previous != DebuggerState::Error {
                        self.last_error.clear();
                    }
                }
                if !looks_like_gdb_error(&output) && self.debugger_state != DebuggerState::Error {
                    self.last_error.clear();
                }
            }
            Err(err) => {
                self.debugger_state = DebuggerState::Error;
                self.last_error = err.to_string();
                return Ok(self.base_response().with_error(self.last_error.clone()));
            }
        }
        Ok(self.base_response())
    }

    async fn execute_with_full_snapshot(
        &mut self,
        command: &str,
        fallback_state: DebuggerState,
    ) -> Result<DebuggerResponse> {
        // Do not auto-restart backend after quit; return current state instead.
        if self.debugger_state == DebuggerState::NotAttached
            || self.debugger_state == DebuggerState::FailedToAttach
            || self.debugger_state == DebuggerState::GdbServerFailedToAttach
        {
            return Ok(self.base_response());
        }
        let response = self.execute_command(command, Some(fallback_state)).await?;
        match response.debugger_state {
            DebuggerState::Error
            | DebuggerState::SigSegv
            | DebuggerState::SigAbrt
            | DebuggerState::SigBus
            | DebuggerState::SigFpe
            | DebuggerState::SigIll
            | DebuggerState::SigTrap
            | DebuggerState::SigTerm
            | DebuggerState::SigKill
            | DebuggerState::Exited
            | DebuggerState::Running
            | DebuggerState::NotAttached
            | DebuggerState::FailedToAttach
            | DebuggerState::GdbServerFailedToAttach => return Ok(response),
            _ => {}
        }
        self.full_snapshot_response().await
    }

    async fn execute_interrupt(&mut self) -> Result<DebuggerResponse> {
        if self.debugger_state == DebuggerState::NotAttached
            || self.debugger_state == DebuggerState::FailedToAttach
            || self.debugger_state == DebuggerState::GdbServerFailedToAttach
            || self.debugger_state == DebuggerState::Exited
        {
            return Ok(self.base_response());
        }

        if self.debugger_state != DebuggerState::Running {
            // The inferior is already stopped (e.g. at a breakpoint) or gdb is
            // idle. There is nothing to interrupt: return the current state
            // without rewriting the stop attribution or fabricating a fresh
            // "stopped at stepping" snapshot.
            return Ok(self.base_response());
        }

        let interrupt_result = self.backend.interrupt().await;
        if let Err(err) = interrupt_result {
            self.debugger_state = DebuggerState::Error;
            self.last_error = err.to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        // Force prompt resynchronization after SIGINT before issuing follow-up queries.
        let sync_result = self.backend.exec("printf \"\"").await;
        if let Err(err) = sync_result {
            self.debugger_state = DebuggerState::Error;
            self.last_error = err.to_string();
            return Ok(self.base_response().with_error(self.last_error.clone()));
        }

        self.debugger_state = DebuggerState::StoppedAtStepping;
        self.stop_reason = Some("interrupt".to_string());
        self.last_error.clear();
        self.full_snapshot_response().await
    }

    async fn full_snapshot_response(&mut self) -> Result<DebuggerResponse> {
        let mut response = self.base_response();
        response.variable_list = Some(self.collect_variable_list().await?);
        let (backtrace, current_func) = self.collect_backtrace(true).await?;
        response.backtrace = Some(backtrace);
        response.current_func = current_func;
        let code = self.collect_current_code().await?;
        response.current_code_path = code.0;
        response.current_code_line = code.1.and_then(|line| i64::try_from(line).ok());
        response.current_code = code.2.map(|lines| self.transform_current_code(lines));
        Ok(response)
    }

    async fn variable_list_response(&mut self) -> Result<DebuggerResponse> {
        if self.debugger_state == DebuggerState::NotAttached
            || self.debugger_state == DebuggerState::FailedToAttach
            || self.debugger_state == DebuggerState::GdbServerFailedToAttach
            || self.debugger_state == DebuggerState::Exited
        {
            let mut response = self.base_response();
            response.variable_list = Some(BTreeMap::new());
            return Ok(response);
        }
        if self.debugger_state == DebuggerState::Running {
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }
        self.recover_error_state_without_restart();
        let mut response = self.base_response();
        response.variable_list = Some(self.collect_variable_list().await?);
        Ok(response)
    }

    async fn full_backtrace_response(&mut self) -> Result<DebuggerResponse> {
        // Do not auto-restart backend after quit; return current state instead.
        if self.debugger_state == DebuggerState::NotAttached
            || self.debugger_state == DebuggerState::FailedToAttach
            || self.debugger_state == DebuggerState::GdbServerFailedToAttach
        {
            return Ok(self.base_response());
        }
        if self.debugger_state == DebuggerState::Running {
            // `backtrace full` on a running inferior would block gdb until the
            // program stops (or hits the exec timeout). Interrupt and resync
            // first, mirroring full_backtrace_response's sibling tools.
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }
        self.recover_error_state_without_restart();
        let mut response = self.base_response();
        let (backtrace, current_func) = self.collect_backtrace(true).await?;
        response.backtrace = Some(backtrace);
        response.current_func = current_func;
        Ok(response)
    }

    async fn list_breakpoint_response(&mut self) -> Result<DebuggerResponse> {
        if self.debugger_state == DebuggerState::NotAttached
            || self.debugger_state == DebuggerState::FailedToAttach
            || self.debugger_state == DebuggerState::GdbServerFailedToAttach
        {
            return Ok(self.base_response());
        }
        if self.debugger_state == DebuggerState::Running {
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }
        self.recover_error_state_without_restart();

        let output = self.backend.exec("info breakpoints").await;
        match output {
            Ok(output) => {
                let entries: Vec<BreakpointEntry> = parse_breakpoint_entries(&output)
                    .into_iter()
                    .map(|(number, text)| parse_breakpoint_entry(&number, &text))
                    .collect();

                let mut response = self.base_response();
                response.breakpoints = Some(entries);
                Ok(response)
            }
            Err(err) => {
                self.last_error = err.to_string();
                self.debugger_state = DebuggerState::Error;
                Ok(self.base_response().with_error(self.last_error.clone()))
            }
        }
    }

    async fn current_code_response(&mut self) -> Result<DebuggerResponse> {
        // Do not auto-restart backend after quit; return current state instead.
        if self.debugger_state == DebuggerState::NotAttached
            || self.debugger_state == DebuggerState::FailedToAttach
            || self.debugger_state == DebuggerState::GdbServerFailedToAttach
        {
            return Ok(self.base_response());
        }
        if self.debugger_state == DebuggerState::Running {
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }
        self.recover_error_state_without_restart();
        let mut response = self.base_response();
        let code = self.collect_current_code().await?;
        response.current_code_path = code.0;
        response.current_code_line = code.1.and_then(|line| i64::try_from(line).ok());
        response.current_code = code.2.map(|lines| self.transform_current_code(lines));
        if response.current_code_path.is_none()
            && response.current_code_line.is_none()
            && response.current_code.is_none()
            && response.error.is_empty()
        {
            response.error = "no current frame".to_string();
        }
        Ok(response)
    }

    async fn collect_variable_list(&mut self) -> Result<BTreeMap<String, String>> {
        let mut variables = BTreeMap::new();

        for variable in self
            .watched_variables
            .iter()
            .take(self.config.display_variable_list)
        {
            let output = self
                .backend
                .exec(&format!("print {}", sanitize_gdb_input(variable)))
                .await;
            match output {
                Ok(output) => {
                    let value = if looks_like_gdb_error(&output) {
                        let details = normalized_command_output(&output)
                            .unwrap_or_else(|| "gdb print failed".to_string());
                        format!("<error: {details}>")
                    } else {
                        normalize_gdb_value(&output)
                    };
                    variables.insert(variable.clone(), value);
                }
                Err(err) => {
                    variables.insert(variable.clone(), format!("<error: {err}>"));
                }
            }
        }

        Ok(variables)
    }

    async fn collect_backtrace(
        &mut self,
        full: bool,
    ) -> Result<(BTreeMap<String, (String, String)>, Option<String>)> {
        let command = if full { "backtrace full" } else { "backtrace" };
        let mut output = self.backend.exec(command).await?;
        let mut backtrace = BTreeMap::new();
        parse_backtrace_lines(&output, self.config.display_backtrace, &mut backtrace);

        // Some targets or GDB settings can yield sparse/empty "backtrace full" output.
        // Fall back to plain backtrace to keep frame info available to MCP clients.
        if full && backtrace.is_empty() {
            output = self.backend.exec("backtrace").await?;
            parse_backtrace_lines(&output, self.config.display_backtrace, &mut backtrace);
        }

        let current_func = if let Some((func, _)) = backtrace.get("0") {
            Some(func.clone())
        } else {
            let mut best: Option<(u64, String)> = None;
            for (frame_key, (func, _)) in &backtrace {
                if let Ok(frame_num) = frame_key.parse::<u64>() {
                    match &best {
                        Some((best_num, _)) if frame_num >= *best_num => {}
                        _ => {
                            best = Some((frame_num, func.clone()));
                        }
                    }
                }
            }
            best.map(|(_, func)| func)
                .or_else(|| backtrace.values().next().map(|(func, _)| func.clone()))
        };
        Ok((backtrace, current_func))
    }

    async fn collect_current_code(
        &mut self,
    ) -> Result<(Option<String>, Option<u64>, Option<BTreeMap<u64, String>>)> {
        let frame = self.backend.exec("frame").await?;
        let (path, line) = parse_path_and_line(&frame);

        let mut code_lines = BTreeMap::new();
        if let Some(line) = line {
            let before = self.config.display_lines_before_current as u64;
            let after = self.config.display_lines_after_current as u64;
            let start = std::cmp::max(1, line.saturating_sub(before));
            let end = line + after;
            let list_output = self.backend.exec(&format!("list {start},{end}")).await?;
            for raw_line in list_output.lines() {
                if let Some((number, source)) = parse_gdb_list_line(raw_line) {
                    code_lines.insert(number, source.to_string());
                }
            }
        }

        let current_code = if code_lines.is_empty() {
            None
        } else {
            Some(code_lines)
        };

        let normalized_path = path.map(|raw| {
            let path_obj = std::path::Path::new(&raw);
            if path_obj.is_absolute() {
                raw
            } else {
                self.config
                    .codebase_dir
                    .join(path_obj)
                    .to_string_lossy()
                    .to_string()
            }
        });

        Ok((normalized_path, line, current_code))
    }

    fn base_response(&self) -> DebuggerResponse {
        let mut response = DebuggerResponse::new(self.debugger_state);
        response.stop_reason = self.stop_reason.clone();
        if !self.last_error.is_empty() {
            response.error = self.last_error.clone();
        }
        response
    }

    fn update_state_from_output(&mut self, output: &str, fallback_state: Option<DebuggerState>) {
        let lower = output.to_ascii_lowercase();
        // A fresh command resets the previous stop cause unless a new one appears below.
        self.stop_reason = None;

        // GDB command failures should be surfaced as Error state.
        // Include remote Debugging failure strings so `target remote` mis-connects don't silently become Attached,
        // plus multiarch/mismatch strings so loading an aarch64 ELF with a native x64 GDB fails loudly.
        if lower.contains("undefined command")
            || lower.contains("ambiguous command")
            || lower.contains("not recognized")
            || lower.contains("a syntax error in expression")
            || lower.contains("cannot find bounds of current function")
            || lower.contains("no symbol")
            || lower.contains("unknown thread")
            || lower.contains("no frame at level")
            || lower.contains("no source file named")
            || lower.contains("no breakpoint at")
            || lower.contains("no breakpoint number")
            || lower.contains("not meaningful in the outermost frame")
            || lower.contains("can't attach")
            || lower.contains("unable to attach")
            || lower.contains("connection timed out")
            || lower.contains("connection refused")
            || lower.contains("no route to host")
            || lower.contains("remote communication error")
            || lower.contains("remote connection closed")
            || lower.contains("failed to connect")
            || lower.contains("unable to connect")
            || lower.contains("timed out trying")
            || lower.contains("could not connect to remote target")
            || lower.contains("connection closed by remote host")
            || lower.contains("already being debugged")
            || lower.contains("already attached")
            || lower.contains("file format not recognized")
            || lower.contains("not in executable format")
            || lower.contains("architecture of file not recognized")
            || lower.contains("exec format error")
            || lower.contains("cannot execute binary file")
            || output_mentions_error(&lower)
        {
            self.debugger_state = DebuggerState::Error;
            return;
        }

        // Signal detection: check both explicit signal names and descriptive messages.
        if lower.contains("sigsegv") || lower.contains("segmentation fault") {
            self.debugger_state = DebuggerState::SigSegv;
            self.stop_reason = Some("sigsegv".to_string());
            return;
        }
        if lower.contains("sigabrt")
            || (lower.contains("signal received") && lower.contains("sigabrt"))
            || lower.contains("program received signal sigabrt")
        {
            self.debugger_state = DebuggerState::SigAbrt;
            self.stop_reason = Some("sigabrt".to_string());
            return;
        }
        if lower.contains("sigbus") || lower.contains("bus error") {
            self.debugger_state = DebuggerState::SigBus;
            self.stop_reason = Some("sigbus".to_string());
            return;
        }
        if lower.contains("sigfpe") || lower.contains("floating point exception") {
            self.debugger_state = DebuggerState::SigFpe;
            self.stop_reason = Some("sigfpe".to_string());
            return;
        }
        if lower.contains("sigill") || lower.contains("illegal instruction") {
            self.debugger_state = DebuggerState::SigIll;
            self.stop_reason = Some("sigill".to_string());
            return;
        }
        if lower.contains("sigtrap") {
            self.debugger_state = DebuggerState::SigTrap;
            self.stop_reason = Some("sigtrap".to_string());
            return;
        }
        if lower.contains("sigterm") {
            self.debugger_state = DebuggerState::SigTerm;
            self.stop_reason = Some("sigterm".to_string());
            return;
        }
        if lower.contains("sigkill") {
            self.debugger_state = DebuggerState::SigKill;
            self.stop_reason = Some("sigkill".to_string());
            return;
        }
        if lower.contains("sigint") && !lower.contains("breakpoint") {
            self.debugger_state = DebuggerState::StoppedAtStepping;
            self.stop_reason = Some("interrupt".to_string());
            return;
        }

        // Generic "program received signal" pattern (catches any unhandled signal).
        if lower.contains("program received signal") {
            self.debugger_state = DebuggerState::Error;
            return;
        }
        if lower.contains("terminated with signal") {
            self.debugger_state = DebuggerState::Error;
            return;
        }

        // Breakpoint hit detection: "Breakpoint 1, ..." lines carry the id.
        if let Some(id) = parse_breakpoint_stop_id(output) {
            self.debugger_state = DebuggerState::StoppedAtBreakpoint;
            self.stop_reason = Some(format!("breakpoint {id}"));
            return;
        }
        if contains_breakpoint_creation(output) {
            return;
        }

        // Watchpoint hits report old/new values; creation only echoes the expression.
        if contains_watchpoint_trigger(output) {
            self.debugger_state = DebuggerState::StoppedAtBreakpoint;
            self.stop_reason = Some(
                parse_watchpoint_stop_id(output)
                    .map(|id| format!("watchpoint {id}"))
                    .unwrap_or_else(|| "watchpoint".to_string()),
            );
            return;
        }
        if contains_watchpoint_creation(output) {
            return;
        }
        if lower.contains("catchpoint") {
            self.debugger_state = DebuggerState::StoppedAtBreakpoint;
            return;
        }

        // Program termination and exit detection.
        if lower.contains("exited normally")
            || lower.contains("exited with code")
            || lower.contains("exited abnormally")
            || (lower.contains("inferior") && lower.contains("exited"))
        {
            self.debugger_state = DebuggerState::Exited;
            self.stop_reason = Some("exited".to_string());
            return;
        }

        // Program not running / no context detection.
        if lower.contains("no stack") || lower.contains("no registers") {
            self.debugger_state = DebuggerState::Exited;
            return;
        }
        if lower.contains("the program is not being run")
            || lower.contains("no inferior")
            || lower.contains("the program has no registers now")
        {
            self.debugger_state = DebuggerState::NotAttached;
            return;
        }

        // Running state detection from GDB output.
        if lower.contains("continuing") || lower.contains("starting program") {
            self.debugger_state = DebuggerState::Running;
            return;
        }

        // User interrupt detection.
        if lower.contains("interrupted") {
            self.debugger_state = DebuggerState::StoppedAtBreakpoint;
            self.stop_reason = Some("interrupt".to_string());
            return;
        }

        // Memory access error detection.
        if lower.contains("cannot access memory") {
            self.debugger_state = DebuggerState::Error;
            return;
        }

        // Detaching / process finished detection.
        if lower.contains("detaching") || lower.contains("process finished") {
            self.debugger_state = DebuggerState::NotAttached;
            return;
        }

        if (lower.contains("inferior") && lower.contains("killed"))
            || lower.contains("program received signal sigkill")
            || lower.contains("terminated with signal sigkill")
        {
            self.debugger_state = DebuggerState::SigKill;
            self.stop_reason = Some("sigkill".to_string());
            return;
        }

        if let Some(state) = fallback_state {
            self.debugger_state = state;
            if state == DebuggerState::StoppedAtStepping {
                self.stop_reason = Some("step".to_string());
            }
        }
    }

    fn transform_current_code(&self, lines: BTreeMap<u64, String>) -> CurrentCodePayload {
        if self.config.display_join_current_code {
            let mut joined = String::new();
            let mut first = true;
            for (line_no, source) in lines {
                if !first {
                    joined.push('\n');
                }
                first = false;
                joined.push_str(&format!("{line_no} | {source}"));
            }
            CurrentCodePayload::Joined(joined)
        } else {
            CurrentCodePayload::Lines(lines)
        }
    }

    async fn stop_gdbserver_process(&mut self) -> Result<()> {
        if let Some(mut child) = self.gdbserver_child.take() {
            let _ = child.kill().await;
            // Wait for the child so it gets reaped instead of lingering as a
            // zombie once the drain tasks end on EOF.
            let _ = child.wait().await;
        }
        for task in self.gdbserver_tasks.drain(..) {
            task.abort();
        }
        Ok(())
    }

    async fn execute_kill(&mut self) -> Result<DebuggerResponse> {
        if self.executable_path.is_none() {
            return Ok(self.base_response());
        }

        if self.debugger_state == DebuggerState::Running {
            let _ = self.backend.interrupt().await;
            let _ = self.backend.exec("printf \"\"").await;
            self.debugger_state = DebuggerState::StoppedAtStepping;
        }

        let output = self.backend.exec("kill").await;
        match output {
            Ok(output) => {
                let mut merged_output = output.clone();
                if output
                    .to_ascii_lowercase()
                    .contains("kill the program being debugged")
                {
                    let confirm = self.backend.exec("y").await;
                    match confirm {
                        Ok(confirm_output) => {
                            merged_output.push('\n');
                            merged_output.push_str(&confirm_output);
                        }
                        Err(err) => {
                            self.debugger_state = DebuggerState::Error;
                            self.last_error = err.to_string();
                            return Ok(self.base_response().with_error(self.last_error.clone()));
                        }
                    }
                }
                self.update_state_from_output(&merged_output, None);
                if self.debugger_state == DebuggerState::Error {
                    self.last_error = normalized_command_output(&output)
                        .unwrap_or_else(|| "gdb kill failed".to_string());
                    return Ok(self.base_response().with_error(self.last_error.clone()));
                }
                Ok(self.base_response())
            }
            Err(err) => {
                self.debugger_state = DebuggerState::Error;
                self.last_error = err.to_string();
                Ok(self.base_response().with_error(self.last_error.clone()))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BreakpointToggle {
    Enable,
    Disable,
}

impl BreakpointToggle {
    fn command_for_id(&self, id: &str) -> String {
        match self {
            Self::Enable => format!("enable {id}"),
            Self::Disable => format!("disable {id}"),
        }
    }
}

/// Parse a pure breakpoint number ("2", "2.1" sub-id allowed). Returns None
/// for location-style targets so callers can fall back to listing resolution.
fn parse_breakpoint_number(target: &str) -> Option<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('.');
    let first = parts.next()?;
    if first.is_empty() || !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if let Some(second) = parts.next()
        && (second.is_empty()
            || !second.chars().all(|c| c.is_ascii_digit())
            || parts.next().is_some())
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn resolve_breakpoint_ids_from_listing(listing: &str, location: &str) -> Vec<String> {
    let location = location.trim();
    let lower_location = location.to_ascii_lowercase();
    let mut ids = Vec::new();

    for (id, entry) in parse_breakpoint_entries(listing) {
        let lower_entry = entry.to_ascii_lowercase();

        // *address targets: compare hex addresses numerically so zero-padded
        // listing entries ("0x00000000004005a0") match "*0x4005a0".
        if let Some(address) = location.strip_prefix('*') {
            let target_value = u64::from_str_radix(address.trim_start_matches("0x"), 16).ok();
            let matches = entry_words(&entry).any(|word| {
                let hex = word.trim_start_matches("0x").trim_start_matches('*');
                match (u64::from_str_radix(hex, 16), target_value) {
                    (Ok(word_value), Some(target)) => word_value == target,
                    _ => false,
                }
            }) || target_value
                .map(|target| lower_entry.contains(&format!("{target:#x}")))
                .unwrap_or(false)
                || contains_word_boundaries(&lower_entry, &lower_location);
            if matches {
                ids.push(id);
            }
            continue;
        }

        if contains_word_boundaries(&lower_entry, &lower_location) {
            ids.push(id);
            continue;
        }

        // file:line targets may appear with an absolute path in the listing.
        if location.contains(':')
            && let Some((file_part, line_no)) = location.rsplit_once(':')
            && line_no.parse::<u64>().is_ok()
        {
            let file_name = std::path::Path::new(file_part)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            if !file_name.is_empty()
                && contains_word_boundaries(&lower_entry, &file_name.to_ascii_lowercase())
                && contains_line_number(&lower_entry, line_no)
            {
                ids.push(id);
            }
        }
    }

    ids
}

/// Substring match that requires word boundaries on both sides, so target
/// "app" does not match "dbg_app.c" and "main" does not match "domain".
fn contains_word_boundaries(haystack_lower: &str, needle_lower: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = haystack_lower[from..].find(needle_lower) {
        let start = from + pos;
        let end = start + needle_lower.len();
        let before_ok = haystack_lower[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let after_ok = haystack_lower[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// True if the entry references ":<line_no>" without being part of a longer
/// number (":5" must not match ":55").
fn contains_line_number(entry_lower: &str, line_no: &str) -> bool {
    let pattern = format!(":{line_no}");
    let mut from = 0;
    while let Some(pos) = entry_lower[from..].find(&pattern) {
        let start = from + pos;
        let end = start + pattern.len();
        let after_digit = entry_lower[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit());
        if !after_digit {
            return true;
        }
        from = end;
    }
    false
}

/// Convert one folded listing entry into a structured breakpoint record.
fn parse_breakpoint_entry(number: &str, text: &str) -> BreakpointEntry {
    // Layout: "<kind> keep|del <y|n> <address/what...>".
    for disp in [" keep ", " del "] {
        if let Some((kind, tail)) = text.split_once(disp) {
            let mut chars = tail.chars();
            let enabled = matches!(chars.next(), Some('y'));
            let detail = tail[1..].trim_start().to_string();
            return BreakpointEntry {
                number: number.to_string(),
                kind: kind.trim().to_string(),
                enabled,
                detail,
            };
        }
    }
    // Unknown layout: keep the raw remainder so nothing is lost.
    BreakpointEntry {
        number: number.to_string(),
        kind: text
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string(),
        enabled: false,
        detail: text.to_string(),
    }
}

/// Group `info breakpoints` output into (breakpoint-number, full-entry-text)
/// pairs, folding wrapped continuation lines into their owning entry.
fn parse_breakpoint_entries(listing: &str) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in listing.lines() {
        match split_breakpoint_listing_line(line) {
            Some((id, rest)) => entries.push((id, rest.to_string())),
            None => {
                if let Some((_, text)) = entries.last_mut() {
                    text.push(' ');
                    text.push_str(line.trim());
                }
            }
        }
    }
    entries
}

/// Split an `info breakpoints` data row into (breakpoint-number, rest-of-line).
/// Returns None for headers, blanks, and non-breakpoint rows.
fn split_breakpoint_listing_line(line: &str) -> Option<(String, &str)> {
    let trimmed = line.trim_start();
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let id = parts.next()?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    let rest = parts.next()?.trim_start();
    Some((id.to_string(), rest))
}

/// Yield the words of an entry line with common gdb decorations stripped.
fn entry_words(entry: &str) -> impl Iterator<Item = &str> {
    entry
        .split(|c: char| c.is_whitespace() || c == ',' || c == ':')
        .map(str::trim)
        .filter(|word| !word.is_empty())
}

/// Parse gdb examine-memory output rows into address -> values map.
/// Recognizes lines shaped like "0x7f...a3f0:\t0x00000001 0x00000002 ...".
fn parse_examine_memory_rows(output: &str) -> BTreeMap<String, String> {
    let mut rows = BTreeMap::new();
    for line in output.lines() {
        let trimmed = line.trim_start().trim_start_matches("(gdb) ").trim_start();
        if !trimmed.starts_with("0x") {
            continue;
        }
        let Some(colon_idx) = trimmed.find(':') else {
            continue;
        };
        // gdb may annotate addresses with a symbol: "0x404050 <counter>:".
        let mut address = &trimmed[..colon_idx];
        if let Some(symbol_idx) = address.find(" <") {
            address = &address[..symbol_idx];
        }
        if !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let values = trimmed[(colon_idx + 1)..].trim();
        if values.is_empty() {
            continue;
        }
        rows.insert(address.to_string(), values.to_string());
    }
    rows
}

fn sanitize_gdb_input(input: &str) -> String {
    // Trust boundary: MCP clients (local LLM agents) are trusted callers, and
    // `gdb_custom` intentionally bypasses this helper as the raw escape hatch.
    // For all other tools, block command chaining via newlines and `;`
    // (e.g. "main; shell rm ..."). GDB expressions themselves (e.g. `print
    // system("...")`) remain as powerful as GDB allows by design; do not
    // expose this server to untrusted clients.
    // `|`, `&`, `$`, backticks etc. are preserved because they are valid in
    // legitimate GDB expressions (bitwise ops, convenience vars, casts).
    let mut out = input.replace(['\n', '\r'], " ");
    // Replace suspicious GDB command chaining chars with space to avoid
    // `break main; shell` style injection via location/expression args.
    // We preserve them for `gdb_custom` which bypasses this helper.
    if out.contains(';') {
        out = out.replace(';', " ");
    }
    out
}

fn normalize_gdb_value(output: &str) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some((_, rhs)) = trimmed.split_once('=') {
        return rhs.trim().to_string();
    }
    trimmed.to_string()
}

fn normalized_command_output(output: &str) -> Option<String> {
    let trimmed = output.trim();
    let stripped = trimmed.strip_prefix("(gdb) ").unwrap_or(trimmed);
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_string())
    }
}

/// True if a line is gdb value output (`$1 = ...` print results or
/// `name = ...` assignments from `info locals`/`info args`) rather than an
/// error message. Such values can legitimately contain the substring
/// "error:" as program data and must not be mistaken for a gdb failure.
fn looks_like_value_assignment(line: &str) -> bool {
    let line = line
        .trim_start()
        .strip_prefix("(gdb) ")
        .unwrap_or(line.trim_start());
    let line = line.trim_start();
    let after_name = if let Some(rest) = line.strip_prefix('$') {
        rest.trim_start_matches(|c: char| c.is_ascii_digit())
    } else {
        let name_len = line
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.')
            .count();
        if name_len == 0 {
            return false;
        }
        &line[name_len..]
    };
    after_name.trim_start().starts_with('=')
}

/// True if any output line mentions "error:" in a context that looks like a
/// gdb error message, skipping value/assignment lines where the text is
/// program data.
fn output_mentions_error(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim_start();
        let line = line.strip_prefix("(gdb) ").unwrap_or(line);
        let line = line.trim_start();
        !line.is_empty()
            && !looks_like_value_assignment(line)
            && line.to_ascii_lowercase().contains("error:")
    })
}

fn looks_like_gdb_error(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("undefined command")
        || lower.contains("ambiguous command")
        || lower.contains("not recognized")
        || lower.contains("a syntax error in expression")
        || lower.contains("cannot find bounds of current function")
        || lower.contains("no symbol")
        || lower.contains("unknown thread")
        || lower.contains("no frame at level")
        || lower.contains("no source file named")
        || lower.contains("no breakpoint at")
        || lower.contains("no breakpoint number")
        || lower.contains("not meaningful in the outermost frame")
        || lower.contains("can't attach")
        || lower.contains("unable to attach")
        || lower.contains("connection timed out")
        || lower.contains("connection refused")
        || lower.contains("no route to host")
        || lower.contains("remote communication error")
        || lower.contains("remote connection closed")
        || lower.contains("failed to connect")
        || lower.contains("unable to connect")
        || lower.contains("timed out trying")
        || lower.contains("could not connect to remote target")
        || lower.contains("connection closed by remote host")
        || lower.contains("file format not recognized")
        || lower.contains("not in executable format")
        || lower.contains("architecture of file not recognized")
        || lower.contains("exec format error")
        || lower.contains("cannot execute binary file")
        || output_mentions_error(&lower)
        || lower.contains("cannot access memory")
}

fn is_recoverable_command_error(lower_error: &str) -> bool {
    lower_error.contains("no symbol")
        || lower_error.contains("unknown thread")
        || lower_error.contains("no frame at level")
        || lower_error.contains("no source file named")
        || lower_error.contains("no breakpoint at")
        || lower_error.contains("no breakpoint number")
        || lower_error.contains("a syntax error in expression")
        || lower_error.contains("cannot find bounds of current function")
        || lower_error.contains("not meaningful in the outermost frame")
        || lower_error.contains("can't attach")
        || lower_error.contains("unable to attach")
}

fn contains_breakpoint_creation(output: &str) -> bool {
    output.lines().any(|line| {
        let trimmed = line.trim_start().to_ascii_lowercase();
        if let Some(rest) = trimmed.strip_prefix("breakpoint ") {
            return rest.contains(" at 0x") || rest.contains(": file ") || rest.contains("pending");
        }
        false
    })
}

/// Extract the breakpoint id from a stop line like "Breakpoint 1, main () at ...".
/// Creation lines ("Breakpoint 1 at 0x1234") have no comma and are not stops.
fn parse_breakpoint_stop_id(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim_start();
        let rest = match trimmed
            .strip_prefix("Breakpoint ")
            .or_else(|| trimmed.strip_prefix("breakpoint "))
        {
            Some(rest) => rest,
            None => continue,
        };
        if let Some(comma_idx) = rest.find(',') {
            let id_part = rest[..comma_idx].trim();
            if parse_breakpoint_number(id_part).is_some() {
                return Some(id_part.to_string());
            }
        }
    }
    None
}

/// A watchpoint hit reports old/new values; a creation echo does not.
fn contains_watchpoint_trigger(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("watchpoint")
        && (lower.contains("old value") || lower.contains("new value") || lower.contains("value ="))
}

/// Watchpoint creation echoes like "Hardware watchpoint 2: x" or
/// "Hardware access (read/write) watchpoint 3: y" without value lines.
fn contains_watchpoint_creation(output: &str) -> bool {
    if contains_watchpoint_trigger(output) {
        return false;
    }
    output.lines().any(|line| {
        let trimmed = line.trim_start().to_ascii_lowercase();
        (trimmed.starts_with("hardware watchpoint ")
            || trimmed.starts_with("hardware access")
            || trimmed.starts_with("watchpoint "))
            && trimmed.contains(':')
    })
}

/// Extract the watchpoint id from trigger output like "Hardware watchpoint 2: x".
fn parse_watchpoint_stop_id(output: &str) -> Option<String> {
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(idx) = lower.find("watchpoint ") else {
            continue;
        };
        let rest = &line[idx + "watchpoint ".len()..];
        let id: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !id.is_empty() {
            return Some(id);
        }
    }
    None
}

fn parse_path_and_line(frame_output: &str) -> (Option<String>, Option<u64>) {
    for line in frame_output.lines() {
        if let Some(at_idx) = line.find(" at ") {
            let segment = line[(at_idx + 4)..].trim();
            if let Some((path, line_number)) = segment.rsplit_once(':')
                && let Ok(number) = line_number.parse::<u64>()
            {
                return (Some(path.to_string()), Some(number));
            }
        }
    }
    (None, None)
}

fn parse_gdb_list_line(line: &str) -> Option<(u64, &str)> {
    let trimmed = line.trim_start();
    let digits_len = trimmed
        .chars()
        .take_while(|char| char.is_ascii_digit())
        .count();
    if digits_len == 0 {
        return None;
    }

    let (digits, rest) = trimmed.split_at(digits_len);
    let number = digits.parse::<u64>().ok()?;
    // Preserve original source indentation: strip only the first field separator.
    let source = if let Some(stripped) = rest.strip_prefix('\t') {
        stripped
    } else if let Some(stripped) = rest.strip_prefix(' ') {
        stripped
    } else {
        rest
    };
    Some((number, source))
}

fn parse_backtrace_lines(
    output: &str,
    limit: usize,
    backtrace: &mut BTreeMap<String, (String, String)>,
) {
    for line in output.lines() {
        if backtrace.len() >= limit {
            break;
        }
        if let Some((frame_number, function, location)) = parse_backtrace_frame_line(line) {
            backtrace.insert(frame_number.to_string(), (function, location));
        }
    }
}

fn parse_backtrace_frame_line(line: &str) -> Option<(u64, String, String)> {
    let hash_idx = line.find('#')?;
    let frame_section = &line[(hash_idx + 1)..];
    let digits_len = frame_section
        .chars()
        .take_while(|char| char.is_ascii_digit())
        .count();
    if digits_len == 0 {
        return None;
    }

    let frame_number = frame_section[..digits_len].parse::<u64>().ok()?;
    let mut rest = frame_section[digits_len..].trim_start();

    if let Some(index) = rest.find(" in ") {
        rest = &rest[(index + 4)..];
    } else if let Some(stripped) = rest.strip_prefix("in ") {
        rest = stripped;
    }

    let mut function = rest.split_whitespace().next().unwrap_or("unknown");
    if function == "in" {
        function = rest.split_whitespace().nth(1).unwrap_or("unknown");
    }
    if let Some((name, _)) = function.split_once('(') {
        function = name;
    }

    let location = line
        .rsplit_once(" at ")
        .map(|(_, loc)| loc.trim().to_string())
        .unwrap_or_default();

    Some((frame_number, function.to_string(), location))
}

#[cfg(test)]
mod parse_tests {
    use super::{
        contains_watchpoint_creation, contains_watchpoint_trigger, parse_backtrace_frame_line,
        parse_breakpoint_entry, parse_breakpoint_stop_id, parse_examine_memory_rows,
        parse_gdb_list_line, resolve_breakpoint_ids_from_listing,
    };

    #[test]
    fn test_breakpoint_stop_id_matches_hits_not_creation() {
        let stop = "\nBreakpoint 1, app_run () at src/main.c:30\n";
        assert_eq!(parse_breakpoint_stop_id(stop).as_deref(), Some("1"));

        let creation = "Breakpoint 1 at 0x1234: file /tmp/main.c, line 10.\n";
        assert_eq!(parse_breakpoint_stop_id(creation), None);

        let none = "0x00005555 in compute_pi ()\n";
        assert_eq!(parse_breakpoint_stop_id(none), None);
    }

    #[test]
    fn test_resolve_ids_by_listing_number_and_location() {
        let listing = "Num Type           Disp Enb Address            What\n\
1   breakpoint     keep y   0x0001 in main at /tmp/src/main.c:55\n\
2   breakpoint     keep y   0x0002 in helper\n\
3   hw watchpoint  keep y                      counter\n";

        // Pure breakpoint numbers never reach the resolver: they are handled
        // directly by parse_breakpoint_number in the tool handlers, so a
        // location lookup for "1" correctly matches nothing here.
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "1"),
            Vec::<String>::new()
        );
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "/tmp/src/main.c:55"),
            vec!["1".to_string()]
        );
        // Relative path matching the same entry.
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "src/main.c:55"),
            vec!["1".to_string()]
        );
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "helper"),
            vec!["2".to_string()]
        );
        // Watchpoints are listed too and resolvable by expression.
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "counter"),
            vec!["3".to_string()]
        );
        assert!(resolve_breakpoint_ids_from_listing(listing, "*0xdeadbeef").is_empty());
    }

    #[test]
    fn test_resolve_ids_address_entry() {
        let listing = "Num Type           Disp Enb Address            What\n\
4   breakpoint     keep y   0x0004005a0 in _start\n";
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "*0x4005a0"),
            vec!["4".to_string()],
            "address target should match the Address column"
        );
    }

    #[test]
    fn test_resolve_ids_with_wrapped_listing_lines() {
        // Real gdb wraps long rows; the location sits on a continuation line.
        let listing = "Num     Type           Disp Enb Address            What\n\
1       breakpoint     keep y   0x000055db57319155 in main\n\
                                                   at /tmp/opencode/dbg_app.c:5\n\
\tbreakpoint already hit 1 time\n\
2       hw watchpoint  keep y                      counter\n";
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "dbg_app.c:5"),
            vec!["1".to_string()],
            "wrapped continuation lines must be folded into their entry"
        );
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "/tmp/opencode/dbg_app.c:5"),
            vec!["1".to_string()]
        );
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "counter"),
            vec!["2".to_string()]
        );
    }

    #[test]
    fn test_resolve_ids_word_boundaries_reject_substring_matches() {
        let listing = "Num Type           Disp Enb Address            What\n\
1   breakpoint     keep y   0x0001 in main at /tmp/opencode/dbg_app.c:55\n\
2   breakpoint     keep y   0x0002 in helper at /tmp/other.c:5\n";
        // "app" is a substring of dbg_app.c but not a word-boundary match.
        assert!(resolve_breakpoint_ids_from_listing(listing, "app").is_empty());
        // ":5" must not match ":55".
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "dbg_app.c:5"),
            Vec::<String>::new()
        );
        assert_eq!(
            resolve_breakpoint_ids_from_listing(listing, "dbg_app.c:55"),
            vec!["1".to_string()]
        );
    }

    #[test]
    fn test_parse_breakpoint_entry_columns() {
        let entry = parse_breakpoint_entry(
            "1",
            "breakpoint keep y 0x000055db57319155 in main at /tmp/dbg_app.c:5 breakpoint already hit 1 time",
        );
        assert_eq!(entry.number, "1");
        assert_eq!(entry.kind, "breakpoint");
        assert!(entry.enabled);
        assert!(entry.detail.contains("in main"));

        let disabled_watch = parse_breakpoint_entry("3", "hw watchpoint keep n counter");
        assert_eq!(disabled_watch.kind, "hw watchpoint");
        assert!(!disabled_watch.enabled);
        assert_eq!(disabled_watch.detail, "counter");
    }

    #[test]
    fn test_examine_memory_rows_parse() {
        let output = "(gdb) 0x404050 <counter>:\t0x00000005\t0x00000000\n\
0x404058:\t0xffffffff\t0x00000001\n";
        let rows = parse_examine_memory_rows(output);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.get("0x404050").map(String::as_str),
            Some("0x00000005\t0x00000000")
        );
        assert_eq!(
            rows.get("0x404058").map(String::as_str),
            Some("0xffffffff\t0x00000001")
        );
    }

    #[test]
    fn test_watchpoint_trigger_vs_creation() {
        let trigger = "Hardware watchpoint 2: counter\n\nOld value = 5\nNew value = 10\n";
        assert!(contains_watchpoint_trigger(trigger));
        assert!(!contains_watchpoint_creation(trigger));

        let creation = "Hardware watchpoint 2: counter\n(gdb) ";
        assert!(contains_watchpoint_creation(creation));
        assert!(!contains_watchpoint_trigger(creation));
    }

    #[test]
    fn test_parse_gdb_list_line_preserves_space_indentation() {
        let parsed = parse_gdb_list_line("23\t    simulator_init(&g_sim, rows, cols, seed);");
        assert!(parsed.is_some(), "line should parse");
        let (line_no, source) = parsed.expect("parsed line");
        assert_eq!(line_no, 23);
        assert_eq!(source, "    simulator_init(&g_sim, rows, cols, seed);");
    }

    #[test]
    fn test_parse_gdb_list_line_preserves_tab_indentation() {
        let parsed = parse_gdb_list_line("24\t\trobot_init(&g_robot, &g_sim);");
        assert!(parsed.is_some(), "line should parse");
        let (line_no, source) = parsed.expect("parsed line");
        assert_eq!(line_no, 24);
        assert_eq!(source, "\trobot_init(&g_robot, &g_sim);");
    }

    #[test]
    fn test_parse_backtrace_frame_line_with_address_and_in() {
        let parsed = parse_backtrace_frame_line(
            "#0  0x00005555555551cb in compute_pi (value=3) at /tmp/main.c:55",
        );
        assert!(parsed.is_some(), "frame should parse");
        let (frame_no, function, location) = parsed.expect("parsed frame");
        assert_eq!(frame_no, 0);
        assert_eq!(function, "compute_pi");
        assert_eq!(location, "/tmp/main.c:55");
    }

    #[test]
    fn test_list_breakpoint_strips_gdb_prompt() {
        let input = "(gdb) Num     Type           Disp Enb Address            What\n1       breakpoint     keep y   0x00005555555551cb in main at src/main.c:10\n";
        let lines: Vec<String> = input
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .map(|line| line.strip_prefix("(gdb) ").unwrap_or(line).to_string())
            .collect();

        assert_eq!(lines.len(), 2);
        assert!(!lines[0].starts_with("(gdb)"));
        assert!(!lines[1].starts_with("(gdb)"));
        assert_eq!(
            lines[0],
            "Num     Type           Disp Enb Address            What"
        );
    }
}
