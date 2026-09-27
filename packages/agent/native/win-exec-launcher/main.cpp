#define WIN32_LEAN_AND_MEAN
// Before windows.h: it otherwise defines `min` and `max` as function-like MACROS,
// which then eat any `std::min(...)`, `std::max(...)` or
// `std::numeric_limits<T>::max()` in this file. That is not theoretical — it broke
// the MSVC build of this very file (C4003 + C2589 on `::max()`), and it slipped
// through review because the mingw-w64 cross-compile used to sanity-check this
// translation unit does NOT define those macros by default. Nothing here wants the
// macros, so switch them off once rather than working around them per use site.
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::array<char, 8> kRequestMagic{'A', 'I', 'C', 'E', 'X', 'E', '0', '1'};
constexpr std::array<char, 8> kResponseMagic{'A', 'I', 'C', 'E', 'X', 'R', '0', '1'};
constexpr std::uint32_t kProtocolVersion = 1;
constexpr std::uint32_t kMaxCommandBytes = 64 * 1024;

#pragma pack(push, 1)
struct RequestHeader {
  char magic[8];
  std::uint32_t version;
  std::uint32_t command_bytes;
};

struct ResponseHeader {
  char magic[8];
  std::uint32_t version;
  std::uint32_t status;
  std::uint32_t message_bytes;
};
#pragma pack(pop)

static_assert(sizeof(RequestHeader) == 16);
static_assert(sizeof(ResponseHeader) == 20);

class ScopedHandle {
 public:
  ScopedHandle() = default;
  explicit ScopedHandle(HANDLE value) : value_(value) {}
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
  ~ScopedHandle() {
    const DWORD error = GetLastError();
    Reset();
    SetLastError(error);
  }

  HANDLE Get() const { return value_; }
  HANDLE Release() {
    const HANDLE value = value_;
    value_ = INVALID_HANDLE_VALUE;
    return value;
  }
  void Reset(HANDLE value = INVALID_HANDLE_VALUE) {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    value_ = value;
  }

 private:
  HANDLE value_ = INVALID_HANDLE_VALUE;
};

bool ReadExact(HANDLE handle, void* destination, DWORD bytes) {
  auto* cursor = static_cast<unsigned char*>(destination);
  while (bytes != 0) {
    DWORD received = 0;
    if (!ReadFile(handle, cursor, bytes, &received, nullptr) || received == 0) return false;
    cursor += received;
    bytes -= received;
  }
  return true;
}

bool WriteExact(HANDLE handle, const void* source, DWORD bytes) {
  const auto* cursor = static_cast<const unsigned char*>(source);
  while (bytes != 0) {
    DWORD written = 0;
    if (!WriteFile(handle, cursor, bytes, &written, nullptr) || written == 0) return false;
    cursor += written;
    bytes -= written;
  }
  return true;
}

bool WriteResponse(HANDLE output, std::uint32_t status, const std::string& message = {}) {
  ResponseHeader header{};
  CopyMemory(header.magic, kResponseMagic.data(), kResponseMagic.size());
  header.version = kProtocolVersion;
  header.status = status;
  header.message_bytes = static_cast<std::uint32_t>(message.size());
  return WriteExact(output, &header, sizeof(header)) &&
         (message.empty() || WriteExact(output, message.data(), header.message_bytes));
}

std::string Win32Failure(const char* operation, DWORD error) {
  return std::string(operation) + " failed (Win32 " + std::to_string(error) + ")";
}

class AttributeList {
 public:
  AttributeList() = default;
  AttributeList(const AttributeList&) = delete;
  AttributeList& operator=(const AttributeList&) = delete;
  ~AttributeList() {
    const DWORD error = GetLastError();
    if (value_) {
      DeleteProcThreadAttributeList(value_);
      HeapFree(GetProcessHeap(), 0, value_);
    }
    SetLastError(error);
  }

  bool Initialize(const std::vector<HANDLE>& handles) {
    SIZE_T bytes = 0;
    if (InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0) {
      return false;
    }
    auto* allocation = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, bytes));
    if (!allocation) {
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      return false;
    }
    if (!InitializeProcThreadAttributeList(allocation, 1, 0, &bytes)) {
      const DWORD error = GetLastError();
      HeapFree(GetProcessHeap(), 0, allocation);
      SetLastError(error);
      return false;
    }

    // Publish the allocation only after the Win32 list has been initialized;
    // the destructor must never delete uninitialized heap bytes.
    value_ = allocation;
    return UpdateProcThreadAttribute(
               value_, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
               const_cast<HANDLE*>(handles.data()), handles.size() * sizeof(HANDLE),
               nullptr, nullptr) != FALSE;
  }

  LPPROC_THREAD_ATTRIBUTE_LIST Get() const { return value_; }

 private:
  LPPROC_THREAD_ATTRIBUTE_LIST value_ = nullptr;
};

bool MakeInheritable(HANDLE handle) {
  return handle != nullptr && handle != INVALID_HANDLE_VALUE &&
         SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) != FALSE;
}

bool CreateRestrictedProcess(
    const std::wstring& application,
    std::wstring command_line,
    DWORD flags,
    WORD show_window,
    HANDLE input,
    HANDLE output,
    HANDLE error,
    PROCESS_INFORMATION* process,
    HANDLE extra = INVALID_HANDLE_VALUE) {
  if (!MakeInheritable(input) || !MakeInheritable(output) || !MakeInheritable(error)) return false;
  std::vector<HANDLE> handles{input, output, error};
  // The attribute list is an ALLOW-list: only handles named here are inherited,
  // whatever else happens to be inheritable in this process. That is what keeps
  // the result channel below out of the command's own process tree.
  if (extra != nullptr && extra != INVALID_HANDLE_VALUE) {
    if (!MakeInheritable(extra)) return false;
    handles.push_back(extra);
  }
  AttributeList attributes;
  if (!attributes.Initialize(handles)) return false;

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.StartupInfo.wShowWindow = show_window;
  startup.StartupInfo.hStdInput = input;
  startup.StartupInfo.hStdOutput = output;
  startup.StartupInfo.hStdError = error;
  startup.lpAttributeList = attributes.Get();

  return CreateProcessW(
             application.c_str(), command_line.data(), nullptr, nullptr, TRUE,
             flags | EXTENDED_STARTUPINFO_PRESENT | CREATE_DEFAULT_ERROR_MODE,
             nullptr, nullptr, &startup.StartupInfo, process) != FALSE;
}

std::wstring CurrentExecutable() {
  std::wstring path(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0 || length >= path.size()) return {};
  path.resize(length);
  return path;
}

std::wstring SystemCmdPath() {
  std::wstring directory(MAX_PATH + 1, L'\0');
  const UINT length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
  if (length == 0 || length >= directory.size()) return {};
  directory.resize(length);
  directory.append(L"\\cmd.exe");
  return directory;
}

bool ValidateNativeArchitecture(std::string* error_message) {
  using IsWow64Process2Function = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
  const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  const auto is_wow64_process_2 = kernel32
      ? reinterpret_cast<IsWow64Process2Function>(
            GetProcAddress(kernel32, "IsWow64Process2"))
      : nullptr;

  if (is_wow64_process_2) {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!is_wow64_process_2(GetCurrentProcess(), &process_machine, &native_machine)) {
      *error_message = Win32Failure("detect native Windows architecture", GetLastError());
      return false;
    }
    if (native_machine != IMAGE_FILE_MACHINE_AMD64) {
      *error_message = "native Windows architecture is unsupported";
      return false;
    }
    return true;
  }

  // IsWow64Process2 is resolved dynamically so older supported Windows builds
  // cannot fail at image load. GetNativeSystemInfo remains emulation-aware.
  SYSTEM_INFO system_info{};
  GetNativeSystemInfo(&system_info);
  if (system_info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
    *error_message = "native Windows architecture is unsupported";
    return false;
  }
  return true;
}

class RelayGate {
 public:
  RelayGate() = default;
  RelayGate(const RelayGate&) = delete;
  RelayGate& operator=(const RelayGate&) = delete;
  ~RelayGate() {
    if (initialized_) DeleteCriticalSection(&lock_);
  }

  bool Initialize() {
    initialized_ = InitializeCriticalSectionEx(&lock_, 4000, 0) != FALSE;
    if (initialized_) InitializeConditionVariable(&condition_);
    return initialized_;
  }

  bool WaitUntilOpen() {
    EnterCriticalSection(&lock_);
    while (!open_ && !cancelled_) {
      if (!SleepConditionVariableCS(&condition_, &lock_, INFINITE)) {
        LeaveCriticalSection(&lock_);
        return false;
      }
    }
    const bool should_relay = open_ && !cancelled_;
    LeaveCriticalSection(&lock_);
    return should_relay;
  }

  void Open() {
    EnterCriticalSection(&lock_);
    open_ = true;
    WakeAllConditionVariable(&condition_);
    LeaveCriticalSection(&lock_);
  }

  void Cancel() {
    EnterCriticalSection(&lock_);
    cancelled_ = true;
    WakeAllConditionVariable(&condition_);
    LeaveCriticalSection(&lock_);
  }

 private:
  CRITICAL_SECTION lock_{};
  CONDITION_VARIABLE condition_{};
  bool initialized_ = false;
  bool open_ = false;
  bool cancelled_ = false;
};

/**
 * Post-exit drain window. MUST stay in sync with EXIT_DRAIN_QUIET_MS and
 * EXIT_DRAIN_MAX_MS in packages/agent/src/executor.ts — this launcher is the
 * Windows half of the SAME settle rule, one process layer lower, and the two
 * halves compose: Node settles when the launcher exits, so a launcher that
 * drains for longer than Node's own window would silently defeat it.
 *
 * WHY the window exists at all. `cmd.exe` hands the command's stdout/stderr
 * write handles to everything it starts, including anything backgrounded with
 * `start /b`. A pipe reports end-of-file only when the LAST write handle in the
 * system closes, so a relay that reads until EOF is really waiting for the whole
 * process tree, not for the command. Measured in production on 1.0.50:
 * `start /b cmd /c "ping -n 20 127.0.0.1" & echo x` burned the caller's entire
 * 8000 ms timeout although `echo` had finished in milliseconds. Redirecting the
 * inner command (`>nul`) does not help — the redirect applies to the inner
 * command while the outer `cmd` still holds the pipe, which is why that test
 * looked like it disproved handle inheritance and did not.
 *
 * So the shell's own exit is the event that settles the call, and reading past
 * it is bounded: keep relaying while bytes keep arriving, stop after
 * kExitDrainQuietMs of silence, and stop unconditionally at kExitDrainMaxMs.
 * The quiet rule is what keeps a normal command intact — a large burst written
 * immediately before exit is still sitting in the pipe buffer at exit and keeps
 * re-arming the window until it has all been relayed, at pipe speed, which for
 * the 64 KiB a pipe can hold is far inside the absolute cap.
 */
constexpr ULONGLONG kExitDrainQuietMs = 25;
constexpr ULONGLONG kExitDrainMaxMs = 250;

/**
 * How the relay observes those deadlines: PeekNamedPipe polling, NOT a blocking
 * ReadFile.
 *
 * A thread parked in a blocking ReadFile cannot notice that the shell exited —
 * that is exactly the bug above. The two alternatives were rejected on purpose:
 *  - overlapped ReadFile needs FILE_FLAG_OVERLAPPED, which CreatePipe cannot
 *    give; it would mean replacing the anonymous pipes with named pipes in the
 *    \\.\pipe\ namespace, i.e. a new externally reachable object in the one
 *    component whose isolation is load-bearing. Not worth it for a timer.
 *  - CancelSynchronousIo() from the main thread can abort a pending ReadFile,
 *    but it cannot tell a pending ReadFile from a pending WriteFile. A relay
 *    blocked writing to a back-pressured parent looks exactly like a quiet pipe
 *    (no new bytes read), so the cancel would land mid-write and TEAR a chunk.
 * Polling keeps every stop decision inside the relay thread, between whole
 * operations, so a chunk is never truncated in flight; the cost is one syscall
 * per idle poll interval, and only while the command runs.
 *
 * WHY THE TWO INTERVALS DIFFER SO MUCH. The idle interval is paid for the whole
 * lifetime of every command, by both relays, so it is the one number that has to
 * be cheap: at 10 ms a silent one-hour exec burned ~720k wakeups for nothing.
 * It can be raised almost freely because pre-exit read latency is INVISIBLE to
 * the caller — remote_exec buffers a command's output and returns it only when
 * the call completes, so a chunk that waits 150 ms in the pipe buffer arrives in
 * exactly the same reply. It costs nothing at the end of the command either:
 * the idle wait is on the DrainClock's event, so the shell's exit wakes both
 * relays immediately instead of after the remaining interval, and everything
 * still in the pipe is then drained at kDrainPollMs. Nor does it throttle
 * throughput — a poll that finds bytes reads and re-peeks without sleeping, so
 * a chatty command still runs at pipe speed and only an IDLE pipe sleeps.
 *
 * The drain interval is the opposite trade: it runs only inside the ≤250 ms
 * post-exit window, where latency IS on the caller's critical path (the call
 * settles when this window closes), so it stays tight.
 */
constexpr DWORD kRelayPollMs = 150;
constexpr DWORD kDrainPollMs = 2;

// Slack over the drain window before the main thread stops waiting for the
// relays to settle. Only a relay blocked in a write to a parent that stopped
// reading can reach it; see the wait in ConsoleStage.
constexpr DWORD kRelayStopWaitMs = static_cast<DWORD>(kExitDrainMaxMs) + 250;

// Published by the main thread the moment the shell exits; read by both relays.
// The event is what lets kRelayPollMs be long: an idle relay parks on it instead
// of on Sleep(), so the shell's exit still reaches both relays at once.
class DrainClock {
 public:
  bool Initialize() {
    exited_event_.Reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    return exited_event_.Get() != nullptr && exited_event_.Get() != INVALID_HANDLE_VALUE;
  }

  void MarkShellExited() {
    exit_tick_.store(GetTickCount64(), std::memory_order_relaxed);
    exited_.store(true, std::memory_order_release);
    SetEvent(exited_event_.Get());
  }

  bool ShellExited(ULONGLONG* exit_tick) const {
    if (!exited_.load(std::memory_order_acquire)) return false;
    *exit_tick = exit_tick_.load(std::memory_order_relaxed);
    return true;
  }

  // Sleeps for at most `timeout_ms`, returning early once the shell has exited.
  void WaitForExitOrTimeout(DWORD timeout_ms) const {
    WaitForSingleObject(exited_event_.Get(), timeout_ms);
  }

 private:
  std::atomic<ULONGLONG> exit_tick_{0};
  std::atomic<bool> exited_{false};
  ScopedHandle exited_event_{};
};

struct RelayContext {
  HANDLE source = INVALID_HANDLE_VALUE;
  HANDLE destination = INVALID_HANDLE_VALUE;
  RelayGate* gate = nullptr;
  const DrainClock* drain = nullptr;
  HANDLE stopped_relaying = INVALID_HANDLE_VALUE;
};

DWORD WINAPI RelayPipe(void* parameter) {
  auto* context = static_cast<RelayContext*>(parameter);
  if (!context->gate->WaitUntilOpen()) {
    SetEvent(context->stopped_relaying);
    CloseHandle(context->source);
    context->source = INVALID_HANDLE_VALUE;
    return 0;
  }

  std::array<unsigned char, 16 * 1024> buffer{};
  bool relaying = true;
  ULONGLONG last_activity = GetTickCount64();
  while (true) {
    ULONGLONG exit_tick = 0;
    const bool exited = context->drain->ShellExited(&exit_tick);
    if (relaying && exited) {
      // The absolute cap is the only rule that fires with bytes still readable;
      // the quiet rule below deliberately waits for an EMPTY pipe first, so
      // output already written at exit time is never dropped by a stale clock.
      if (GetTickCount64() - exit_tick >= kExitDrainMaxMs) {
        // Stop DELIVERING, not reading. Everything below keeps consuming this
        // pipe until its last writer closes, which is the whole point: closing
        // our read end here would break the pipe under a background process
        // that is legitimately still running (ERROR_BROKEN_PIPE on its next
        // write), and terminating it is not ours to do either. This mirrors
        // detachPipe() in executor.ts, which resumes-and-discards instead of
        // destroying the stream for exactly the same reason. Discarding also
        // keeps a survivor that fills the 64 KiB pipe buffer from blocking in
        // write() forever.
        relaying = false;
        SetEvent(context->stopped_relaying);
      }
    }

    if (!relaying) {
      // No deadline left to observe, so go back to a blocking read: the reaper
      // phase must cost nothing while it lasts. Its END is enforced one level
      // up, by the main thread's capped wait (kReaperMaxLifetimeMs) and the
      // ExitProcess that follows it — a blocked ReadFile cannot be woken safely,
      // and here it does not have to be.
      DWORD received = 0;
      if (!ReadFile(context->source, buffer.data(), static_cast<DWORD>(buffer.size()),
                    &received, nullptr) || received == 0) {
        break;
      }
      continue;
    }

    DWORD available = 0;
    // A failed peek is treated as "try to read": the read then either returns
    // the bytes still buffered in a pipe whose writers have gone (which must
    // not be dropped) or reports the closed pipe. It cannot block, because a
    // pipe with no live writer never withholds a reader.
    if (!PeekNamedPipe(context->source, nullptr, 0, nullptr, &available, nullptr)) {
      available = static_cast<DWORD>(buffer.size());
    }
    if (available == 0) {
      if (exited && GetTickCount64() - last_activity >= kExitDrainQuietMs) {
        // Quiet: the shell is gone and this pipe has produced nothing for a
        // while. Same stop as the cap above — deliver nothing more, keep
        // reading. Loops back into the blocking reaper read on the next turn.
        relaying = false;
        SetEvent(context->stopped_relaying);
        continue;
      }
      if (exited) {
        Sleep(kDrainPollMs);
      } else {
        // Park on the exit event rather than on the clock: a long idle interval
        // must not become a long "the command finished" latency.
        context->drain->WaitForExitOrTimeout(kRelayPollMs);
      }
      continue;
    }

    DWORD received = 0;
    // A plain comparison rather than std::min. NOMINMAX at the top of this file
    // now means the macro could no longer swallow a qualified call, so this is
    // no longer a workaround — it is just two DWORDs, and reading it needs no
    // header.
    const auto capacity = static_cast<DWORD>(buffer.size());
    const DWORD wanted = available < capacity ? available : capacity;
    if (!ReadFile(context->source, buffer.data(), wanted, &received, nullptr) || received == 0) {
      break;
    }
    last_activity = GetTickCount64();
    if (!WriteExact(context->destination, buffer.data(), received)) {
      relaying = false;
      SetEvent(context->stopped_relaying);
    }
  }
  if (relaying) SetEvent(context->stopped_relaying);
  CloseHandle(context->source);
  context->source = INVALID_HANDLE_VALUE;
  return 0;
}

class RelayWorker {
 public:
  RelayWorker() = default;
  RelayWorker(const RelayWorker&) = delete;
  RelayWorker& operator=(const RelayWorker&) = delete;

  bool Start(ScopedHandle* source, HANDLE destination, RelayGate* gate, const DrainClock* drain) {
    const HANDLE stopped = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopped) return false;
    stopped_relaying_.Reset(stopped);
    context_.source = source->Get();
    context_.destination = destination;
    context_.gate = gate;
    context_.drain = drain;
    context_.stopped_relaying = stopped;
    const HANDLE thread = CreateThread(nullptr, 0, RelayPipe, &context_, 0, nullptr);
    if (!thread) return false;
    source->Release();
    thread_.Reset(thread);
    return true;
  }

  // Signalled once this relay has written its last byte to the parent. After
  // that the thread only drains and discards, so the parent's handles are free.
  HANDLE StoppedRelaying() const { return stopped_relaying_.Get(); }

  HANDLE Thread() const { return thread_.Get(); }

  // Bounded on purpose; see kReaperMaxLifetimeMs for why nothing here may wait
  // INFINITE. Used by the startup failure paths, where the gate is already
  // cancelled and the threads return at once.
  void Join(DWORD timeout_ms) {
    if (thread_.Get() != INVALID_HANDLE_VALUE) WaitForSingleObject(thread_.Get(), timeout_ms);
    thread_.Reset();
  }

 private:
  RelayContext context_{};
  ScopedHandle thread_{};
  ScopedHandle stopped_relaying_{};
};

// Startup failure paths only: the gate is cancelled and the shell is dead or was
// never created, so both relays return immediately. Generous, and bounded.
constexpr DWORD kRelayShutdownWaitMs = 5000;

bool WaitForRelays(const RelayWorker& first, const RelayWorker& second, DWORD timeout_ms) {
  HANDLE live[2];
  DWORD count = 0;
  for (const HANDLE thread : {first.Thread(), second.Thread()}) {
    if (thread != nullptr && thread != INVALID_HANDLE_VALUE) live[count++] = thread;
  }
  if (count == 0) return true;
  return WaitForMultipleObjects(count, live, TRUE, timeout_ms) == WAIT_OBJECT_0;
}

/**
 * HARD LIFETIME CAP on the reaper phase.
 *
 * Once the relays stop delivering, this process keeps reading and discarding
 * only so a survivor that inherited the command's stdout/stderr cannot wedge in
 * write() against a full 64 KiB pipe buffer. That job has no natural end: a
 * `start /b` daemon holds those write handles for as long as it lives, and
 * waiting INFINITE for it meant one launcher process plus its console host
 * leaked per backgrounded service, forever, with nothing left for the caller to
 * notice — stage 1 has already returned by then.
 *
 * Two bounds are decisive for the number below:
 *  - UPGRADES. This binary runs from $INSTDIR\resources, so a live reaper locks
 *    a file the Windows installer must replace. An abandoned reaper may delay an
 *    in-place upgrade by at most this long — never indefinitely.
 *  - The command itself cannot outlive one hour (remote_exec's own ceiling), so
 *    two hours is already twice the longest thing that could have started the
 *    survivor. "Start a dev server and come back in a while" is untouched: its
 *    output keeps being swallowed for the whole window.
 * When the cap fires we simply exit. The survivor's next write then returns
 * ERROR_BROKEN_PIPE, which on Windows is an ordinary returned error — there is
 * no SIGPIPE — so a well-behaved daemon keeps running. Nothing is killed here,
 * and nothing ever kills the survivor.
 *
 * Nothing can consume a reaper's bytes in the first place — the caller's handles
 * are released the moment the relays settle, which is before this phase starts —
 * so there is no cheaper "output is unreachable" signal left to detect: the pipe
 * going quiet does not mean the survivor is finished with it, and only EOF (the
 * last writer closing) or this cap can end the wait.
 */
constexpr DWORD kReaperMaxLifetimeMs = 2 * 60 * 60 * 1000;

/**
 * BOUND ON HOW MANY REAPERS CAN EXIST AT ONCE.
 *
 * The cap above bounds each reaper's lifetime; this bounds the total, so a
 * machine that starts background services in a loop cannot accumulate an
 * unbounded pile of launcher+conhost pairs inside one cap window. A process-wide
 * counter cannot see other launchers, so the slots are named kernel objects in
 * the per-session Local\ namespace. They are counters, not channels: they carry
 * no data, no part of any payload passes through them, and nothing read from one
 * is ever trusted — the only two outcomes are "reap" and "don't".
 *
 * WHY N NAMED MUTEXES AND NOT ONE NAMED SEMAPHORE. A semaphore's count is
 * restored only by ReleaseSemaphore: closing the handle does not restore it, and
 * neither does the holder dying. A reaper is exactly the process most likely to
 * die without running user-mode cleanup — the installer taskkills it to unlock
 * $INSTDIR\resources, and a caller's timeout sends `taskkill /T` through stage 1
 * — so a semaphore would ratchet permanently downwards for as long as any other
 * reaper keeps the named object alive. After kMaxConcurrentReapers such deaths
 * inside one busy window nothing would be reaped again, i.e. the cap would
 * silently disable the mechanism it exists to protect.
 *
 * A MUTEX is the one Win32 object with the ownership semantics this actually
 * needs: when its owner dies the next waiter gets WAIT_ABANDONED and takes it.
 * So the "count" is expressed as kMaxConcurrentReapers separately named mutexes
 * and a slot is the first one we can take without waiting. That degrades safely
 * under a kill — the slot is released by the kernel — and it is still a pure
 * counter: WAIT_ABANDONED is treated as an ordinary free slot precisely because
 * the object protects nothing and holds no state to be left inconsistent.
 *
 * Failing to create or acquire a slot means we do not reap, which is the same
 * outcome as the cap expiring (the survivor gets ERROR_BROKEN_PIPE on its next
 * write and lives on), so a squatter on the names can cost a daemon its output,
 * never this process's correctness.
 */
constexpr LONG kMaxConcurrentReapers = 16;
constexpr wchar_t kReaperSlotPrefix[] = L"Local\\aicommander-win-exec-reaper-";

// Acquire/Release must run on the SAME thread — mutex ownership is thread
// affine — which they do: the whole reaper phase lives on ConsoleStage's thread.
class ReaperSlot {
 public:
  ReaperSlot() = default;
  ReaperSlot(const ReaperSlot&) = delete;
  ReaperSlot& operator=(const ReaperSlot&) = delete;
  ~ReaperSlot() { Release(); }

  bool Acquire() {
    for (LONG index = 0; index < kMaxConcurrentReapers; ++index) {
      const std::wstring name = kReaperSlotPrefix + std::to_wstring(index);
      const HANDLE mutex = CreateMutexW(nullptr, FALSE, name.c_str());
      // A slot we cannot even open counts as taken: every failure here fails
      // CLOSED, towards not reaping.
      if (mutex == nullptr) continue;
      ScopedHandle candidate(mutex);
      const DWORD state = WaitForSingleObject(mutex, 0);
      if (state != WAIT_OBJECT_0 && state != WAIT_ABANDONED) continue;
      held_.Reset(candidate.Release());
      return true;
    }
    return false;
  }

  // Returns the slot on EVERY exit path out of the reaper phase — the cap
  // expiring, end-of-file arriving first, or anything in between — because the
  // destructor runs before ConsoleStage's ExitProcess.
  void Release() {
    const HANDLE mutex = held_.Get();
    if (mutex == nullptr || mutex == INVALID_HANDLE_VALUE) return;
    ReleaseMutex(mutex);
    held_.Reset();
  }

 private:
  ScopedHandle held_{};
};

bool CreatePrivatePipe(ScopedHandle* read_end, ScopedHandle* write_end) {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE read = INVALID_HANDLE_VALUE;
  HANDLE write = INVALID_HANDLE_VALUE;
  if (!CreatePipe(&read, &write, &security, 0)) return false;
  read_end->Reset(read);
  write_end->Reset(write);
  if (!SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0)) return false;
  return true;
}

/**
 * The stage-2 -> stage-1 result channel.
 *
 * Stage 2 owns the shell's pipes, so it is stage 2 that must outlive the call
 * when a background process is still writing (see RelayPipe). Stage 1 is the
 * process the agent spawned and waits on, so it is stage 1 that must exit the
 * instant the shell's exit code is known. Those are two different lifetimes,
 * hence one extra private pipe carrying a couple of fixed-size records.
 *
 * The records are what let stage 1 tell "stage 2 REPORTED the shell's exit code"
 * apart from "stage 2 VANISHED without reporting". A bare exit code could not:
 * end-of-file on this pipe used to fall back to stage 2's own process exit code,
 * so a stage 2 that crashed mid-command handed the caller an ordinary completed
 * command — a success-shaped answer for an outcome nobody knows. Only kResultExit
 * is an exit status now; anything else is a failure, and kResultStarted tells
 * stage 1 which of the two failure reports the caller can still receive (see
 * StageOne).
 *
 * It is an anonymous pipe, not a name in any namespace, and it is inherited
 * only by stage 2 (the handle ALLOW-list in CreateRestrictedProcess keeps it
 * out of the shell and everything the command starts). The handle value travels
 * on stage 2's command line, which carries no part of the payload — the command
 * itself still reaches stage 2 only over the bounded stdin protocol.
 */
constexpr std::uint32_t kResultStarted = 1;  // the shell is running; READY is next
constexpr std::uint32_t kResultExit = 2;     // value = the shell's exit code

// End-of-file on the result channel already proves stage 2 is gone; this only
// gives the kernel a moment to publish its exit code for the diagnostics below.
constexpr DWORD kStageTwoReapWaitMs = 2000;

/**
 * Reported when stage 2 vanished after the shell was running, i.e. when the
 * command's true status is unknown.
 *
 * This number ALONE cannot carry that meaning: it is a legal 32-bit Windows
 * status and a command is free to return it, so a reader that keys off the value
 * would call such a command's ordinary result an unknown outcome. It is one half
 * of a two-part signal; the other half is kUnknownOutcomeMarker below, which
 * stage 1 emits on this path and only on this path. executor.ts requires BOTH,
 * so a real `exit /b` of this value stays a result (the marker is absent) and a
 * genuine vanish stays an error.
 */
constexpr std::uint32_t kUnknownOutcomeExitCode = 0xA1C0FFFF;

/**
 * The other half: a fixed leader on the stderr notice stage 1 writes when — and
 * only when — stage 2 died after the handshake.
 *
 * Past the handshake stage 1 has no private channel to the agent left (the
 * handshake frame is consumed, and everything after it is the command's own
 * output), so this rides the command's stderr. That makes it corroboration
 * rather than proof: a command that prints this exact leader AND exits with
 * exactly kUnknownOutcomeExitCode would still be misread. Two independent
 * coincidences, one of which no ordinary program produces, is as structural as
 * this stage of the protocol allows — and the mistake it now rules out (a real
 * exit status silently reclassified as "unknown") was reachable by one.
 * MUST stay byte-identical to WINDOWS_LAUNCHER_UNKNOWN_OUTCOME_MARKER in
 * packages/agent/src/executor.ts; windows-exec-launcher.test.ts pins the pair.
 */
constexpr char kUnknownOutcomeMarker[] = "aicommander-launcher-unknown-outcome:";

#pragma pack(push, 1)
struct ResultRecord {
  std::uint32_t tag;
  std::uint32_t value;
};
#pragma pack(pop)

static_assert(sizeof(ResultRecord) == 8);

bool ReportResult(HANDLE result, std::uint32_t tag, std::uint32_t value) {
  if (result == nullptr || result == INVALID_HANDLE_VALUE) return false;
  const ResultRecord record{tag, value};
  return WriteExact(result, &record, sizeof(record));
}

std::wstring EncodeHandleToken(HANDLE value) {
  auto number = static_cast<std::uintptr_t>(reinterpret_cast<ULONG_PTR>(value));
  constexpr wchar_t kDigits[] = L"0123456789abcdef";
  std::wstring text;
  do {
    text.insert(text.begin(), kDigits[number & 0xF]);
    number >>= 4;
  } while (number != 0);
  return L"0x" + text;
}

bool DecodeHandleToken(const wchar_t* text, HANDLE* value) {
  if (!text || text[0] != L'0' || text[1] != L'x' || text[2] == L'\0') return false;
  std::uintptr_t number = 0;
  for (const wchar_t* cursor = text + 2; *cursor != L'\0'; ++cursor) {
    std::uintptr_t digit = 0;
    if (*cursor >= L'0' && *cursor <= L'9') digit = static_cast<std::uintptr_t>(*cursor - L'0');
    else if (*cursor >= L'a' && *cursor <= L'f') digit = static_cast<std::uintptr_t>(*cursor - L'a') + 10;
    else return false;
    // Parenthesised on purpose, belt-and-braces with the NOMINMAX at the top: the
    // extra parens stop a `max` macro expanding here even if that define is ever
    // lost to an include-order change, which is how this line broke once already.
    if (number > ((std::numeric_limits<std::uintptr_t>::max)() >> 4)) return false;
    number = (number << 4) | digit;
  }
  *value = reinterpret_cast<HANDLE>(number);
  return true;
}

int StageOne() {
  // Production must not depend on Electron/service/terminal parent state. Pipe
  // standard handles remain valid, while the launcher deliberately drops any
  // inherited console before stage 2 creates its own hidden one.
  FreeConsole();
  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  const HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
  const std::wstring executable = CurrentExecutable();
  if (executable.empty()) {
    WriteResponse(output, 1, Win32Failure("resolve launcher", GetLastError()));
    return 1;
  }

  ScopedHandle result_read;
  ScopedHandle result_write;
  if (!CreatePrivatePipe(&result_read, &result_write)) {
    WriteResponse(output, 1, Win32Failure("create result channel", GetLastError()));
    return 1;
  }

  std::wstring command_line =
      L"\"" + executable + L"\" --console-stage " + EncodeHandleToken(result_write.Get());
  PROCESS_INFORMATION child{};
  if (!CreateRestrictedProcess(
          executable, std::move(command_line), CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
          SW_HIDE, input, output, error, &child, result_write.Get())) {
    WriteResponse(output, 1, Win32Failure("create console stage", GetLastError()));
    return 1;
  }
  if (ResumeThread(child.hThread) == static_cast<DWORD>(-1)) {
    const DWORD last_error = GetLastError();
    TerminateProcess(child.hProcess, 1);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    WriteResponse(output, 1, Win32Failure("resume console stage", last_error));
    return 1;
  }
  CloseHandle(child.hThread);
  // Drop our own write end: stage 2 is now the only writer, so the read below
  // ends either with the reported exit code or with EOF when stage 2 dies.
  result_write.Reset();

  bool started = false;
  ResultRecord record{};
  while (ReadExact(result_read.Get(), &record, sizeof(record))) {
    if (record.tag == kResultStarted) {
      started = true;
      continue;
    }
    if (record.tag != kResultExit) break;  // corrupt channel: treat as no report
    // Stage 2 has the shell's exit code. It may still be draining a background
    // process that outlived the command; waiting for that is precisely the bug
    // this whole path exists to avoid, so do not wait for stage 2 to exit.
    CloseHandle(child.hProcess);
    ExitProcess(record.value);
  }

  // No exit record: stage 2 vanished without reporting. Its own exit code is NOT
  // an answer — reporting it would tell the caller the command completed with a
  // status it never produced, while the shell may well still be running. Only
  // stage 2 can hold this handle (the inherit ALLOW-list keeps it out of the
  // shell), so end-of-file here means stage 2 itself is gone.
  WaitForSingleObject(child.hProcess, kStageTwoReapWaitMs);
  DWORD stage_two_code = 1;
  GetExitCodeProcess(child.hProcess, &stage_two_code);
  CloseHandle(child.hProcess);

  if (!started) {
    // The caller has not seen the ready handshake yet, so the handshake channel
    // is still open and this becomes a launcher error the agent turns into
    // onError (executor.ts). Stage 2 may have written its own error frame before
    // dying; a second frame is harmless there — the agent stops reading stdout
    // once the first one made the command fail.
    WriteResponse(
        output, 1,
        "Windows command launcher console stage exited before starting the command (exit " +
            std::to_string(stage_two_code) + ")");
    return 1;
  }

  // Stage 2 got as far as running the shell, so the caller has the ready
  // handshake (or stage 2 died in the instant before writing it, and the agent
  // settles that as a launcher that never became ready — see executor.ts). Past
  // the handshake the launcher has no error frame left to send: the agent has
  // consumed the one handshake and reads everything after it as the command's
  // own output. So say it in the command's stderr, where the caller
  // does see it, led by the marker the agent keys off, and exit with the sentinel
  // status. Neither half means "unknown outcome" on its own (see the constants);
  // together they do. This is the one outcome this launcher cannot report
  // cleanly; it requires stage 2 to die mid-command (a crash — a kill takes
  // stage 1 with it), and the message is what a human has to act on.
  const std::string notice =
      std::string(kUnknownOutcomeMarker) +
      " the Windows command launcher's console stage exited unexpectedly (exit " +
      std::to_string(stage_two_code) +
      "). The command's outcome is unknown and it may still be running.\r\n";
  WriteExact(error, notice.data(), static_cast<DWORD>(notice.size()));
  return static_cast<int>(kUnknownOutcomeExitCode);
}

int ConsoleStage(HANDLE result) {
  if (HWND window = GetConsoleWindow()) ShowWindow(window, SW_HIDE);
  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  const HANDLE error = GetStdHandle(STD_ERROR_HANDLE);

  RequestHeader header{};
  if (!ReadExact(input, &header, sizeof(header)) ||
      !std::equal(kRequestMagic.begin(), kRequestMagic.end(), header.magic) ||
      header.version != kProtocolVersion || header.command_bytes > kMaxCommandBytes ||
      (header.command_bytes % sizeof(wchar_t)) != 0) {
    WriteResponse(output, 1, "invalid launcher request");
    return 1;
  }

  std::wstring command(header.command_bytes / sizeof(wchar_t), L'\0');
  if (header.command_bytes != 0 && !ReadExact(input, command.data(), header.command_bytes)) {
    WriteResponse(output, 1, "incomplete launcher request");
    return 1;
  }
  if (command.find(L'\0') != std::wstring::npos) {
    WriteResponse(output, 1, "launcher request contains NUL");
    return 1;
  }

  std::string architecture_error;
  if (!ValidateNativeArchitecture(&architecture_error)) {
    WriteResponse(output, 1, architecture_error);
    return 1;
  }
  if (!SetConsoleCP(CP_UTF8) || !SetConsoleOutputCP(CP_UTF8) ||
      GetConsoleCP() != CP_UTF8 || GetConsoleOutputCP() != CP_UTF8) {
    WriteResponse(output, 1, Win32Failure("configure UTF-8 console", GetLastError()));
    return 1;
  }

  const std::wstring cmd_path = SystemCmdPath();
  if (cmd_path.empty()) {
    WriteResponse(output, 1, Win32Failure("resolve system shell", GetLastError()));
    return 1;
  }
  std::wstring cmd_line = L"cmd.exe /d /s /c \"" + command + L"\"";
  if (cmd_line.size() + 1 > 32767) {
    WriteResponse(output, 1, "Windows command line is too long");
    return 1;
  }

  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  ScopedHandle null_input(CreateFileW(
      L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (null_input.Get() == INVALID_HANDLE_VALUE) {
    WriteResponse(output, 1, Win32Failure("open command input", GetLastError()));
    return 1;
  }

  RelayGate relay_gate;
  if (!relay_gate.Initialize()) {
    WriteResponse(output, 1, Win32Failure("initialize output relay", GetLastError()));
    return 1;
  }
  ScopedHandle stdout_read;
  ScopedHandle stdout_write;
  ScopedHandle stderr_read;
  ScopedHandle stderr_write;
  if (!CreatePrivatePipe(&stdout_read, &stdout_write) ||
      !CreatePrivatePipe(&stderr_read, &stderr_write)) {
    WriteResponse(output, 1, Win32Failure("create output relay", GetLastError()));
    return 1;
  }

  DrainClock drain;
  if (!drain.Initialize()) {
    WriteResponse(output, 1, Win32Failure("initialize drain clock", GetLastError()));
    return 1;
  }
  RelayWorker stdout_relay;
  RelayWorker stderr_relay;
  if (!stdout_relay.Start(&stdout_read, output, &relay_gate, &drain)) {
    WriteResponse(output, 1, Win32Failure("start output relay", GetLastError()));
    return 1;
  }
  if (!stderr_relay.Start(&stderr_read, error, &relay_gate, &drain)) {
    const DWORD last_error = GetLastError();
    relay_gate.Cancel();
    stdout_write.Reset();
    stdout_relay.Join(kRelayShutdownWaitMs);
    WriteResponse(output, 1, Win32Failure("start error relay", last_error));
    return 1;
  }

  PROCESS_INFORMATION shell{};
  if (!CreateRestrictedProcess(
          cmd_path, std::move(cmd_line), CREATE_SUSPENDED, SW_HIDE,
          null_input.Get(), stdout_write.Get(), stderr_write.Get(), &shell)) {
    const DWORD last_error = GetLastError();
    relay_gate.Cancel();
    stdout_write.Reset();
    stderr_write.Reset();
    stdout_relay.Join(kRelayShutdownWaitMs);
    stderr_relay.Join(kRelayShutdownWaitMs);
    WriteResponse(output, 1, Win32Failure("create system shell", last_error));
    return 1;
  }
  null_input.Reset();
  stdout_write.Reset();
  stderr_write.Reset();

  // cmd.exe writes only to private pipes. Both relay threads already exist and
  // remain behind the in-process gate, so ResumeThread is the last fallible
  // startup step and command bytes cannot race ahead of this handshake.
  if (ResumeThread(shell.hThread) == static_cast<DWORD>(-1)) {
    const DWORD last_error = GetLastError();
    TerminateProcess(shell.hProcess, 1);
    WaitForSingleObject(shell.hProcess, INFINITE);
    CloseHandle(shell.hThread);
    CloseHandle(shell.hProcess);
    relay_gate.Cancel();
    stdout_relay.Join(kRelayShutdownWaitMs);
    stderr_relay.Join(kRelayShutdownWaitMs);
    WriteResponse(output, 1, Win32Failure("resume system shell", last_error));
    return 1;
  }
  CloseHandle(shell.hThread);

  // Tell stage 1 the command is running BEFORE the caller is told, never after.
  // The handshake is the caller's point of no return for error reporting —
  // everything it reads past it is the command's own output — so a stage 2 that
  // died between the two writes in the other order left the caller believing the
  // command had started while stage 1 still believed nothing had, and stage 1
  // then reported the vanish as an ordinary exit code (see StageOne). This
  // ordering has no such instant. Its own failure window is harmless in the other
  // direction: a stage 2 that dies after this record but before the handshake
  // makes stage 1 emit the unknown-outcome signal to a caller that never saw
  // READY, and executor.ts settles that as "exited before it was ready" — an
  // error either way, never a result.
  ReportResult(result, kResultStarted, 0);

  if (!WriteResponse(output, 0)) {
    TerminateProcess(shell.hProcess, 1);
    WaitForSingleObject(shell.hProcess, INFINITE);
    CloseHandle(shell.hProcess);
    relay_gate.Cancel();
    stdout_relay.Join(kRelayShutdownWaitMs);
    stderr_relay.Join(kRelayShutdownWaitMs);
    return 1;
  }

  // Opening the already-initialized in-process gate has no failure path. Relay
  // workers now stream the two byte pipes independently.
  relay_gate.Open();

  // The COMMAND's exit is what settles the call — not end-of-file on its pipes,
  // which arrives only once every process holding an inherited write handle is
  // gone (see kExitDrainQuietMs).
  WaitForSingleObject(shell.hProcess, INFINITE);
  DWORD code = 1;
  GetExitCodeProcess(shell.hProcess, &code);
  CloseHandle(shell.hProcess);
  drain.MarkShellExited();

  // Bounded by the drain window itself; the timeout is a backstop for the one
  // case a relay cannot stop on time — blocked in a write to a parent that has
  // stopped reading. Missing it costs nothing but the handle close below.
  const HANDLE stopped[] = {stdout_relay.StoppedRelaying(), stderr_relay.StoppedRelaying()};
  const bool relays_settled =
      WaitForMultipleObjects(2, stopped, TRUE, kRelayStopWaitMs) == WAIT_OBJECT_0;

  // Hand the exit code to stage 1, which exits with it immediately. This process
  // stays behind for a BOUNDED while (kReaperMaxLifetimeMs) if anything the
  // command left running still keeps its stdout/stderr open — reading and
  // discarding, never writing, never killing.
  ReportResult(result, kResultExit, static_cast<std::uint32_t>(code));

  if (relays_settled) {
    // Nothing will write to the agent's pipes again, so release them: the agent
    // sees end-of-file on stdout/stderr at the same moment it reaps stage 1,
    // exactly as it would for a command with nothing left running. Skipped when
    // the wait above timed out — a relay may still be inside a write, and
    // closing a handle under it could land a later write on a recycled one.
    CloseHandle(output);
    CloseHandle(error);
  }

  // Reaper phase. The common case has no survivor at all: both relays have
  // already reached end-of-file, the poll below returns at once and this process
  // never counts against the concurrency bound. Only a real survivor gets here,
  // and then only with a slot and only for as long as the cap allows.
  if (!WaitForRelays(stdout_relay, stderr_relay, 0)) {
    ReaperSlot reaper_slot;
    if (reaper_slot.Acquire()) {
      WaitForRelays(stdout_relay, stderr_relay, kReaperMaxLifetimeMs);
      // Explicit, though the destructor below would do it too: the slot must be
      // free again the moment this process stops reaping, not merely "eventually".
      reaper_slot.Release();
    }
  }
  // ExitProcess closes the read ends whether the relays finished or the cap ran
  // out. A survivor still holding the write end sees ERROR_BROKEN_PIPE on its
  // next write and carries on; nothing here terminates it.
  ExitProcess(code);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  if (argc >= 2 && argc <= 3 && wcscmp(argv[1], L"--console-stage") == 0) {
    // The optional second argument is the inherited result-channel handle stage 1
    // created for us. It carries no part of the payload, and without it stage 2
    // simply reports its exit code the old way — by exiting with it.
    HANDLE result = INVALID_HANDLE_VALUE;
    if (argc == 3 && !DecodeHandleToken(argv[2], &result)) {
      WriteResponse(GetStdHandle(STD_OUTPUT_HANDLE), 1, "invalid launcher invocation");
      return 1;
    }
    return ConsoleStage(result);
  }
  if (argc != 1) {
    WriteResponse(GetStdHandle(STD_OUTPUT_HANDLE), 1, "invalid launcher invocation");
    return 1;
  }
  return StageOne();
}
