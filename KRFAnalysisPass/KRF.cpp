#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/StringRef.h"
#include <unordered_set>
#include <string>
#include <fstream>
#include <iostream>

using namespace llvm;

namespace {

using JObject = json::Object;
using JArray = json::Array;
using JValue = json::Value;

cl::opt<bool> Json("krf-json", cl::desc("Print output in json format"));
cl::opt<std::string> Filename("krf-output", cl::desc("Output file"), cl::init("krfpass.out"));

struct KRF : public ModulePass {
  static char ID;
  std::error_code FD_EC;
  raw_fd_ostream output;
  KRF() : ModulePass(ID), output(Filename, FD_EC) {
    if (FD_EC) {
      errs() << "Failed to open file " << Filename << "\n";
    }
  }
  const std::unordered_set<std::string> blacklisted_functions = {"accept",
                                                                 "access",
                                                                 "bind",
                                                                 "brk",
                                                                 "chdir",
                                                                 "chmod",
                                                                 "chown",
                                                                 "chroot",
                                                                 "clock_getres",
                                                                 "clock_gettime",
                                                                 "clock_nanosleep",
                                                                 "clock_settime",
                                                                 "clone",
                                                                 "close",
                                                                 "connect",
                                                                 "creat",
                                                                 "dup",
                                                                 "dup2",
                                                                 "faccessat",
                                                                 "fchdir",
                                                                 "fchmod",
                                                                 "fchmodat",
                                                                 "fchown",
                                                                 "fchownat",
                                                                 "fcntl",
                                                                 "fdatasync",
                                                                 "flock",
                                                                 "fork",
                                                                 "fstat",
                                                                 "fstatfs",
                                                                 "fsync",
                                                                 "ftruncate",
                                                                 "getcpu",
                                                                 "getcwd",
                                                                 "getpeername",
                                                                 "getpgid",
                                                                 "getpriority",
                                                                 "getresgid",
                                                                 "getresuid",
                                                                 "getsid",
                                                                 "getsockname",
                                                                 "getsockopt",
                                                                 "gettimeofday",
                                                                 "ioctl",
                                                                 "kill",
                                                                 "lchown",
                                                                 "link",
                                                                 "linkat",
                                                                 "listen",
                                                                 "lstat",
                                                                 "madvise",
                                                                 "mincore",
                                                                 "mkdir",
                                                                 "mknod",
                                                                 "mknodat",
                                                                 "mlock",
                                                                 "mlock2",
                                                                 "mlockall",
                                                                 "mmap_pgoff",
                                                                 "mount",
                                                                 "mprotect",
                                                                 "mq_getsetattr",
                                                                 "mq_notify",
                                                                 "mq_open",
                                                                 "mq_timedreceive",
                                                                 "mq_timedsend",
                                                                 "mq_unlink",
                                                                 "mremap",
                                                                 "msgctl",
                                                                 "msgget",
                                                                 "msgrcv",
                                                                 "msgsnd",
                                                                 "msync",
                                                                 "munlock",
                                                                 "munlockall",
                                                                 "munmap",
                                                                 "newfstatat",
                                                                 "open",
                                                                 "openat",
                                                                 "pipe",
                                                                 "read",
                                                                 "readlink",
                                                                 "readlinkat",
                                                                 "reboot",
                                                                 "recvfrom",
                                                                 "recvmsg",
                                                                 "rename",
                                                                 "renameat",
                                                                 "renameat2",
                                                                 "rmdir",
                                                                 "rt_sigaction",
                                                                 "rt_sigpending",
                                                                 "rt_sigprocmask",
                                                                 "rt_sigqueueinfo",
                                                                 "rt_sigsuspend",
                                                                 "rt_sigtimedwait",
                                                                 "sigaction",
                                                                 "sigpending",
                                                                 "sigprocmask",
                                                                 "sigsuspend",
                                                                 "sigtimedwait",
                                                                 "sched_get_priority_max",
                                                                 "sched_get_priority_min",
                                                                 "sched_getaffinity",
                                                                 "sched_getattr",
                                                                 "sched_getparam",
                                                                 "sched_getscheduler",
                                                                 "sched_rr_get_interval",
                                                                 "sched_setaffinity",
                                                                 "sched_setattr",
                                                                 "sched_setparam",
                                                                 "sched_setscheduler",
                                                                 "select",
                                                                 "semctl",
                                                                 "semget",
                                                                 "semop",
                                                                 "sendmsg",
                                                                 "sendto",
                                                                 "setdomainname",
                                                                 "setgid",
                                                                 "sethostname",
                                                                 "setpgid",
                                                                 "setpriority",
                                                                 "setregid",
                                                                 "setresgid",
                                                                 "setresuid",
                                                                 "setreuid",
                                                                 "setsid",
                                                                 "setsockopt",
                                                                 "settimeofday",
                                                                 "setuid",
                                                                 "shmat",
                                                                 "shmctl",
                                                                 "shmdt",
                                                                 "shmget",
                                                                 "shutdown",
                                                                 "sigaltstack",
                                                                 "socket",
                                                                 "socketpair",
                                                                 "stat",
                                                                 "statfs",
                                                                 "swapoff",
                                                                 "swapon",
                                                                 "symlink",
                                                                 "symlinkat",
                                                                 "syncfs",
                                                                 "sysfs",
                                                                 "syslog",
                                                                 "tgkill",
                                                                 "time",
                                                                 "timer_create",
                                                                 "timer_delete",
                                                                 "timer_getoverrun",
                                                                 "timer_gettime",
                                                                 "timer_settime",
                                                                 "timerfd_create",
                                                                 "timerfd_gettime",
                                                                 "timerfd_settime",
                                                                 "tkill",
                                                                 "truncate",
                                                                 "umount",
                                                                 "unlink",
                                                                 "unlinkat",
                                                                 "uselib",
                                                                 "ustat",
                                                                 "utime",
                                                                 "wait4",
                                                                 "waitid",
                                                                 "write",
                                                                 "syscall"};

  bool runOnModule(Module &M) override {
    if (FD_EC) {
      return false;
    }
    JArray JRoot{};
    if (!Json) {
      output << "KRF: entered module ";
      output.write_escaped(M.getName()) << '\n';
    }
    for (const auto &F : M) {
      if (F.isIntrinsic()) {
        continue;
      }
      if (!Json) {
        output << "  entered function ";
        output.write_escaped((F.hasName()) ? F.getName() : "unname_function") << '\n';
      }
      for (const auto &B : F) {
        int lookingForErrno = 0;
        for (const auto &I : B) {
          if (const CallInst *call_inst = dyn_cast<CallInst>(&I)) {
            const Function *callee = call_inst->getCalledFunction();
            if (lookingForErrno && callee && callee->hasName() &&
                callee->getName().equals("__errno_location")) { // If call to errno
              for (const auto U :
                   call_inst->users()) { // For every instruction that uses that result
                if (const LoadInst *load_inst = dyn_cast<LoadInst>(U)) { // Check if its a load
                  for (const auto V :
                       load_inst->users()) {     // Then for every inst that uses *that* result
                    if (dyn_cast<ICmpInst>(V)) { // Check if its a comparison
                      if (Json) {
                        (*JRoot.back().getAsObject()->get("errno_checked")) = true;
                      } else {
                        output << "      errno checked: yes\n";
                      }
                      lookingForErrno = 0;
                      break;
                    }
                  }
                }
              }
              continue;
            }
            if (lookingForErrno) {
              lookingForErrno = 0;
            }
            if (!callee || !callee->hasName() ||
                !blacklisted_functions.count(callee->getName().str())) {
              continue;
            }
            if (callee->getReturnType()->isVoidTy()) {
              continue;
            }
            int isChecked = 0;
            if (!call_inst->hasNUses(0)) {
              for (const auto U : call_inst->users()) {
                if (dyn_cast<ICmpInst>(U)) {
                  isChecked = 1; // Could add check on operands to see if its < 0 or == -1
                  break;
                }
              }
            }

            if (!isChecked) { // If function's result is never used
              lookingForErrno = 1;
              if (!Json) {
                output << "    warning: return value of " << callee->getName() << " is unused\n";
              }
              if (DILocation *Loc = I.getDebugLoc()) { // Gets source info if exists
                if (!Loc->isImplicitCode()) {
                  unsigned Line = Loc->getLine();
                  StringRef File = Loc->getFilename();
                  StringRef Dir = Loc->getDirectory();
                  if (Json) {
                    JRoot.push_back(JObject{
                        {"function", (F.hasName() ? F.getName() : "unname_function")},
                        {"module", M.getName()},
                        {"errno_checked", false},
                        {"call", callee->getName()},
                        {"line", Line},
                        {"file", File},
                        {"dir", Dir},
                    });
                  } else {
                    output << "      at " << Dir << '/' << File << ':' << Line << '\n';
                  }
                }
              } else {
                if (Json) {
                  JRoot.push_back(JObject{
                      {"function", F.getName()},
                      {"module", M.getName()},
                      {"call", callee->getName()},
                      {"errno_checked", false},

                  });
                }
              }
            }
          }
        } // Inst iterator
      }   // BB iterator
    }     // Function iterator
    if (Json) {
      JValue Jout(std::move(JRoot));
      output << Jout << '\n';
    }
    return false;
  } // End of runOnModule()
};  // end of struct KRF
} // end of anonymous namespace

char KRF::ID = 0;
static RegisterPass<KRF> X("KRF", "KRF Pass", false /* Only looks at CFG */,
                           false /* Analysis Pass */);