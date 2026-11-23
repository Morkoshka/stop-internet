//! Named pipe between the service and its clients, the tray icon and the
//! CLI. The messages are defined in `stopinet_core::protocol`.
//!
//! Server ([`PipeServer`], run by the service):
//!
//! - It owns the only instance of the pipe: the instance is created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE` and a limit of one, so no other process
//!   can serve the same name while the service runs.
//! - The security descriptor admits SYSTEM, Administrators and interactive
//!   users. Interactive users may read and write, but not create instances
//!   of the pipe. Remote clients are rejected.
//! - One connection carries one request line and one response line, with
//!   time limits, so a client that hangs blocks others for a few seconds at
//!   most. The service stops the server through an event.
//! - It tells the handler whether the client holds an elevated
//!   administrator token, read from the client's identification token.
//!
//! Client ([`ask`]): it connects at the identification level, which lets
//! the service check its token but not act as the client, and it talks to
//! the pipe only if the pipe belongs to the process of the running service.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use stopinet_core::SERVICE_NAME;
use stopinet_core::protocol::{MAX_LINE, PIPE_NAME, ProtocolError, Request, Response};
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, RevertToSelf, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, TOKEN_QUERY, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_WRITE_DATA,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThread, INFINITE, OpenThreadToken, ResetEvent, SetEvent,
    WaitForMultipleObjects, WaitForSingleObject,
};
use windows_sys::core::BOOL;

use crate::adapter::Win32Error;
use crate::security::LocalDescriptor;
use crate::wide::WideString;

/// Full access for SYSTEM and Administrators. Interactive users get read,
/// write data and attributes, but not `FILE_CREATE_PIPE_INSTANCE` (which is
/// `FILE_APPEND_DATA`, part of `GENERIC_WRITE`), so they cannot add an
/// instance of their own.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";

/// Size of the pipe buffers in each direction.
const BUFFER: u32 = 4096;

/// How long a client may take to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a client may take to read the answer and close its end.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// Pause after a failed wait for a client, so that a persistent error does
/// not turn into a busy loop.
const RETRY_PAUSE: u32 = 200;

/// How long a client waits while another client is being served.
const BUSY_TIMEOUT: Duration = Duration::from_secs(3);
const BUSY_RETRY: Duration = Duration::from_millis(25);

const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// Who sent a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// The client holds an elevated administrator token, or runs as
    /// LocalSystem.
    pub admin: bool,
}

/// Server side of the pipe: answers requests on its own thread until it is
/// dropped.
#[derive(Debug)]
pub struct PipeServer {
    stop: Arc<OwnedHandle>,
    thread: Option<JoinHandle<()>>,
}

impl PipeServer {
    /// Creates the pipe and serves it. `handler` gets each request line,
    /// without the final `\n`, and returns the answer line. It runs on the
    /// thread of the server, one request at a time.
    ///
    /// Fails if the pipe cannot be created, for example because another
    /// process already serves this name.
    pub fn start(
        name: &str,
        handler: impl FnMut(&str, Caller) -> String + Send + 'static,
    ) -> Result<Self, Win32Error> {
        let pipe = create_pipe(name)?;
        let io = new_event()?;
        let stop = Arc::new(new_event()?);
        let server = Server {
            pipe,
            io,
            stop: Arc::clone(&stop),
        };
        let thread = thread::Builder::new()
            .name("pipe server".into())
            .spawn(move || server.run(handler))
            .map_err(|e| Win32Error {
                operation: "CreateThread",
                code: e.raw_os_error().unwrap_or_default() as u32,
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for PipeServer {
    /// Stops the server and waits for its thread. A request being handled
    /// is finished first.
    fn drop(&mut self) {
        // SAFETY: the event handle is valid while `self.stop` lives.
        unsafe { SetEvent(self.stop.as_raw_handle()) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn create_pipe(name: &str) -> Result<OwnedHandle, Win32Error> {
    let descriptor = LocalDescriptor::from_sddl(PIPE_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let name = WideString::new(name);
    // SAFETY: `name` is NUL-terminated, `attributes` and the descriptor it
    // points to outlive the call.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            BUFFER,
            BUFFER,
            0,
            &attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Win32Error::last("CreateNamedPipeW"));
    }
    // SAFETY: a new handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Manual-reset event, not signaled.
fn new_event() -> Result<OwnedHandle, Win32Error> {
    // SAFETY: no security attributes and no name; both may be null.
    let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if handle.is_null() {
        return Err(Win32Error::last("CreateEventW"));
    }
    // SAFETY: a new handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Result of one overlapped operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Io {
    /// Finished, with the number of bytes transferred.
    Done(u32),
    /// Failed with this error.
    Failed(u32),
    /// The time limit passed; the operation was cancelled.
    Timeout,
    /// The server is stopping; the operation was cancelled.
    Stopped,
}

/// Whether to go on with the next client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Next,
    Stop,
}

struct Server {
    /// The pipe instance, opened for overlapped I/O.
    pipe: OwnedHandle,
    /// Event for the overlapped operations on the pipe.
    io: OwnedHandle,
    /// Signaled when the server must stop.
    stop: Arc<OwnedHandle>,
}

impl Server {
    fn run(self, mut handler: impl FnMut(&str, Caller) -> String) {
        loop {
            let flow = match self.connect() {
                Io::Done(_) => self.serve(&mut handler),
                Io::Stopped => Flow::Stop,
                // A client that left before it was noticed, or an error:
                // start over after a pause.
                Io::Failed(_) | Io::Timeout => {
                    // SAFETY: the stop event is valid while `self` lives.
                    let stopped =
                        unsafe { WaitForSingleObject(self.stop.as_raw_handle(), RETRY_PAUSE) };
                    if stopped == WAIT_OBJECT_0 {
                        Flow::Stop
                    } else {
                        Flow::Next
                    }
                }
            };
            // SAFETY: the pipe handle is valid; disconnecting an instance
            // without a client fails harmlessly.
            unsafe { DisconnectNamedPipe(self.pipe()) };
            if flow == Flow::Stop {
                return;
            }
        }
    }

    /// One request and its answer.
    fn serve(&self, handler: &mut impl FnMut(&str, Caller) -> String) -> Flow {
        let line = match self.read_line(Instant::now() + REQUEST_TIMEOUT) {
            Ok(line) => line,
            Err(flow) => return flow,
        };
        let caller = Caller {
            admin: self.client_is_admin(),
        };
        let mut answer = handler(&line, caller).into_bytes();
        answer.push(b'\n');

        let deadline = Instant::now() + REPLY_TIMEOUT;
        let mut sent = 0;
        while sent < answer.len() {
            let rest = &answer[sent..];
            let io = self.overlapped(deadline, |overlapped| {
                // SAFETY: `rest` and `overlapped` stay valid until the
                // operation has finished: `overlapped` waits for it, also
                // when it cancels.
                unsafe {
                    WriteFile(
                        self.pipe(),
                        rest.as_ptr(),
                        rest.len() as u32,
                        ptr::null_mut(),
                        overlapped,
                    )
                }
            });
            match io {
                Io::Done(n) if n > 0 => sent += n as usize,
                Io::Stopped => return Flow::Stop,
                _ => return Flow::Next,
            }
        }

        // Disconnecting discards what the client has not read yet, so wait
        // until it has closed its end; it does so after reading the line.
        match self.read(&mut [0; 1], deadline) {
            Io::Stopped => Flow::Stop,
            _ => Flow::Next,
        }
    }

    /// Reads up to the first `\n`. Longer lines than [`MAX_LINE`], invalid
    /// text, a closed pipe and the time limit end the connection.
    fn read_line(&self, deadline: Instant) -> Result<String, Flow> {
        let mut buffer = [0u8; MAX_LINE + 1];
        let mut length = 0;
        loop {
            match self.read(&mut buffer[length..], deadline) {
                Io::Done(n) => {
                    let start = length;
                    length += n as usize;
                    if let Some(end) = buffer[start..length].iter().position(|&b| b == b'\n') {
                        let line = &buffer[..start + end];
                        return std::str::from_utf8(line)
                            .map(str::to_owned)
                            .map_err(|_| Flow::Next);
                    }
                    if length == buffer.len() {
                        return Err(Flow::Next);
                    }
                }
                Io::Stopped => return Err(Flow::Stop),
                Io::Failed(_) | Io::Timeout => return Err(Flow::Next),
            }
        }
    }

    fn read(&self, buffer: &mut [u8], deadline: Instant) -> Io {
        self.overlapped(deadline, |overlapped| {
            // SAFETY: `buffer` and `overlapped` stay valid until the
            // operation has finished: `overlapped` waits for it, also when
            // it cancels.
            unsafe {
                ReadFile(
                    self.pipe(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    overlapped,
                )
            }
        })
    }

    /// Waits for the next client, without a time limit.
    fn connect(&self) -> Io {
        self.wait(INFINITE, |overlapped| {
            // SAFETY: `overlapped` stays valid until the operation has
            // finished.
            unsafe { ConnectNamedPipe(self.pipe(), overlapped) }
        })
    }

    fn overlapped(&self, deadline: Instant, start: impl FnOnce(*mut OVERLAPPED) -> BOOL) -> Io {
        let left = deadline.saturating_duration_since(Instant::now());
        // INFINITE is u32::MAX, so stay below it.
        let millis = u32::try_from(left.as_millis()).unwrap_or(INFINITE - 1);
        self.wait(millis, start)
    }

    /// Starts an overlapped operation and waits until it finishes, the time
    /// passes or the server stops. It returns only when Windows no longer
    /// uses the `OVERLAPPED` or the buffer of the operation.
    fn wait(&self, millis: u32, start: impl FnOnce(*mut OVERLAPPED) -> BOOL) -> Io {
        // SAFETY: `OVERLAPPED` is plain data, all zeros is its initial state.
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        overlapped.hEvent = self.io.as_raw_handle();
        // SAFETY: the event handle is valid while `self` lives.
        unsafe { ResetEvent(overlapped.hEvent) };

        if start(&mut overlapped) == 0 {
            // SAFETY: no preconditions.
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => {}
                // A client connected before `ConnectNamedPipe`.
                ERROR_PIPE_CONNECTED => return Io::Done(0),
                code => return Io::Failed(code),
            }
        }

        let events = [self.io.as_raw_handle(), self.stop.as_raw_handle()];
        // SAFETY: both handles are valid events while `self` lives.
        let waited = unsafe { WaitForMultipleObjects(2, events.as_ptr(), 0, millis) };
        let mut transferred = 0;
        if waited == WAIT_OBJECT_0 {
            // SAFETY: the operation has finished, `overlapped` belongs to it.
            let done =
                unsafe { GetOverlappedResult(self.pipe(), &overlapped, &mut transferred, 0) };
            return if done != 0 {
                Io::Done(transferred)
            } else {
                // SAFETY: no preconditions.
                Io::Failed(unsafe { GetLastError() })
            };
        }

        // SAFETY: `overlapped` belongs to an operation on this pipe.
        unsafe { CancelIoEx(self.pipe(), &overlapped) };
        // SAFETY: waits until the cancelled operation has finished, after
        // which Windows no longer touches `overlapped` or the buffer.
        unsafe { GetOverlappedResult(self.pipe(), &overlapped, &mut transferred, 1) };
        match waited {
            WAIT_TIMEOUT => Io::Timeout,
            w if w == WAIT_OBJECT_0 + 1 => Io::Stopped,
            _ => Io::Failed(waited),
        }
    }

    /// Whether the connected client holds an elevated administrator token.
    /// Must be called after reading from the client.
    fn client_is_admin(&self) -> bool {
        // SAFETY: the pipe has a connected client that has sent data.
        if unsafe { ImpersonateNamedPipeClient(self.pipe()) } == 0 {
            return false;
        }
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: `token` is a valid out pointer. `OpenAsSelf` checks the
        // access with the identity of the service, which works with an
        // identification-level token of the client.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        // SAFETY: no preconditions.
        if unsafe { RevertToSelf() } == 0 {
            // The thread would go on as the client.
            std::process::abort();
        }
        if opened == 0 {
            return false;
        }
        // SAFETY: a new handle that nothing else owns.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        is_admin(&token)
    }

    fn pipe(&self) -> HANDLE {
        self.pipe.as_raw_handle()
    }
}

/// Whether the impersonation token has the Administrators group enabled.
/// In a filtered token of an administrator, without UAC elevation, the
/// group is for deny only and does not count.
fn is_admin(token: &OwnedHandle) -> bool {
    // `u32` elements keep the SID aligned.
    let mut sid = [0u32; SECURITY_MAX_SID_SIZE as usize / 4];
    let mut size = SECURITY_MAX_SID_SIZE;
    // SAFETY: the buffer holds the largest SID; a built-in group needs no
    // domain SID.
    let created = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if created == 0 {
        return false;
    }
    let mut member = 0;
    // SAFETY: `token` is an impersonation token opened with TOKEN_QUERY,
    // `sid` holds a valid SID.
    let checked = unsafe {
        CheckTokenMembership(token.as_raw_handle(), sid.as_mut_ptr().cast(), &mut member)
    };
    checked != 0 && member != 0
}

/// Why a client could not get an answer.
#[derive(Debug)]
pub enum ClientError {
    /// The service is not installed.
    NotInstalled,
    /// The service is not running.
    NotRunning,
    /// The service runs but does not serve the pipe, for example an older
    /// version of it.
    NoPipe,
    /// The pipe belongs to another process than the service.
    Impostor,
    /// Other clients kept the pipe busy.
    Busy,
    /// The service manager could not be asked about the service.
    Manager(windows_service::Error),
    /// Talking over the pipe failed.
    Io(io::Error),
    /// The answer does not follow the protocol.
    Protocol(ProtocolError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => f.write_str("the stop-internet service is not installed"),
            Self::NotRunning => f.write_str("the stop-internet service is not running"),
            Self::NoPipe => f.write_str(
                "the service does not answer on its named pipe; an older version may be \
                 installed, run `stopinet install` again",
            ),
            Self::Impostor => {
                f.write_str("the named pipe belongs to another program than the service")
            }
            Self::Busy => f.write_str("the service is busy, try again"),
            Self::Manager(e) => write!(f, "cannot ask the service manager: {e}"),
            Self::Io(e) => write!(f, "cannot talk to the service: {e}"),
            Self::Protocol(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ClientError {}

/// Sends a request to the running service and returns its answer.
pub fn ask(request: &Request) -> Result<Response, ClientError> {
    let server = service_process()?;
    let answer = exchange(PIPE_NAME, &request.to_string(), Some(server))?;
    Response::parse(&answer).map_err(ClientError::Protocol)
}

/// Process id of the running service.
fn service_process() -> Result<u32, ClientError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(ClientError::Manager)?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            return Err(ClientError::NotInstalled);
        }
        Err(e) => return Err(ClientError::Manager(e)),
    };
    let status = service.query_status().map_err(ClientError::Manager)?;
    match (status.current_state, status.process_id) {
        (ServiceState::Running, Some(pid)) => Ok(pid),
        _ => Err(ClientError::NotRunning),
    }
}

/// Sends one line over the pipe `name` and returns the answer line. With
/// `server`, the pipe must belong to that process.
pub fn exchange(name: &str, line: &str, server: Option<u32>) -> Result<String, ClientError> {
    let mut pipe = open(name)?;
    if let Some(expected) = server {
        if server_process(&pipe)? != expected {
            return Err(ClientError::Impostor);
        }
    }
    pipe.write_all(format!("{line}\n").as_bytes())
        .map_err(ClientError::Io)?;

    let mut answer = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let n = pipe.read(&mut chunk).map_err(ClientError::Io)?;
        if n == 0 {
            break;
        }
        answer.extend_from_slice(&chunk[..n]);
        if let Some(end) = answer.iter().position(|&b| b == b'\n') {
            answer.truncate(end);
            break;
        }
        if answer.len() > MAX_LINE {
            return Err(invalid("the answer is too long"));
        }
    }
    // Closing the pipe tells the server that the answer arrived.
    drop(pipe);
    String::from_utf8(answer).map_err(|_| invalid("the answer is not text"))
}

fn invalid(message: &str) -> ClientError {
    ClientError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn open(name: &str) -> Result<File, ClientError> {
    let deadline = Instant::now() + BUSY_TIMEOUT;
    loop {
        let opened = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | FILE_WRITE_DATA)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name);
        match opened {
            Ok(pipe) => return Ok(pipe),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                if Instant::now() >= deadline {
                    return Err(ClientError::Busy);
                }
                thread::sleep(BUSY_RETRY);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ClientError::NoPipe),
            Err(e) => return Err(ClientError::Io(e)),
        }
    }
}

fn server_process(pipe: &File) -> Result<u32, ClientError> {
    let mut pid = 0;
    // SAFETY: `pipe` is an open pipe handle, `pid` a valid out pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(ClientError::Io(io::Error::last_os_error()));
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn unique_name() -> String {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\stopinet-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn echo(name: &str) -> PipeServer {
        PipeServer::start(name, |line, _caller| format!("echo {line}")).unwrap()
    }

    #[test]
    fn answers_one_line_per_connection() {
        let name = unique_name();
        let _server = echo(&name);
        let me = Some(std::process::id());
        assert_eq!(exchange(&name, "status", me).unwrap(), "echo status");
        assert_eq!(
            exchange(&name, "mode tunnel", me).unwrap(),
            "echo mode tunnel"
        );
    }

    #[test]
    fn talks_only_to_the_expected_process() {
        let name = unique_name();
        let _server = echo(&name);
        let other = Some(std::process::id() + 1);
        assert!(matches!(
            exchange(&name, "status", other),
            Err(ClientError::Impostor)
        ));
        // The server goes on with the next client.
        assert_eq!(exchange(&name, "status", None).unwrap(), "echo status");
    }

    #[test]
    fn a_second_server_cannot_take_the_name() {
        let name = unique_name();
        let _server = echo(&name);
        assert!(PipeServer::start(&name, |_, _| String::new()).is_err());
    }

    #[test]
    fn a_missing_pipe_is_reported() {
        assert!(matches!(
            exchange(&unique_name(), "status", None),
            Err(ClientError::NoPipe)
        ));
    }

    #[test]
    fn a_too_long_request_gets_no_answer() {
        let name = unique_name();
        let _server = echo(&name);
        let long = "x".repeat(MAX_LINE + 10);
        // The server hangs up: the client sees a closed pipe or nothing.
        let answer = exchange(&name, &long, None);
        assert!(answer.as_ref().map_or(true, String::is_empty), "{answer:?}");
        assert_eq!(exchange(&name, "status", None).unwrap(), "echo status");
    }

    #[test]
    fn stops_at_once_while_waiting() {
        let server = echo(&unique_name());
        let started = Instant::now();
        drop(server);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_silent_client_is_dropped_after_the_time_limit() {
        let name = unique_name();
        let _server = echo(&name);
        let silent = open(&name).unwrap();
        // The only instance is busy until the server gives up on `silent`.
        let answer = exchange(&name, "status", None).unwrap();
        assert_eq!(answer, "echo status");
        drop(silent);
    }
}
