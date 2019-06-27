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

using namespace llvm;

cl::opt<bool> Json ("json", cl::desc("Print output in json format"));

namespace {
struct KRF : public ModulePass {
  static char ID;
  KRF() : ModulePass(ID) {}
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
"syscall"
  };
					
  bool runOnModule(Module &M) override {
    json::OStream* J = (Json) ? new json::OStream(errs()) : NULL;
    if (Json) {
      J->objectBegin();
      J->attributeBegin(M.getName());
      J->objectBegin();
    } else {
      errs() << "KRF: entered module ";
      errs().write_escaped(M.getName()) << '\n';
    }
    for (auto &F : M) {
      if (Json) {
	J->attributeBegin((F.hasName()) ? F.getName() : "unname_function");
	J->arrayBegin();
      } else {
	errs() << "  entered function ";
	errs().write_escaped((F.hasName()) ? F.getName() : "unname_function") << '\n';
      }
      for (auto &B : F) {
	int lookingForErrno = 0;
	for (auto &I : B) {
	  if (CallInst* call_inst = dyn_cast<CallInst>(&I)) {
	    Function * callee = call_inst->getCalledFunction();
	    if (lookingForErrno && callee && callee->hasName() && callee->getName().equals("__errno_location")) { // If call to errno
	      for (auto U : call_inst->users()) { // For every instruction that uses that result
	      	if (LoadInst* load_inst = dyn_cast<LoadInst>(U)) { // Check if its a load
	      	  for (auto V : load_inst->users()) { // Then for every inst that uses *that* result
	      	    if (dyn_cast<ICmpInst>(V)) { // Check if its a comparison
	      	      if (Json) {
	      		J->attribute("errno_checked", true);
	      		J->objectEnd();
	      	      } else {
	      		errs() << "      errno checked: yes\n";
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
	      if (Json) {
		J->attribute("errno_checked", false);
		J->objectEnd();
	      }
	      lookingForErrno = 0;
	    }			   
	    if (callee && callee->hasName() && blacklisted_functions.count(callee->getName().str())) {
	      if (!callee->getReturnType()->isVoidTy()) { // If function does not return void
		if (call_inst->hasNUses(0)) { // If function's result is never used
		  lookingForErrno = 1;
		  if (Json) {
		    J->objectBegin();
		    J->attribute("call", callee->getName());
		  } else {
		    errs() << "    warning: return value of " << callee->getName() << " is unused\n";
		  }
		  if (DILocation *Loc = I.getDebugLoc()) { // Gets source info if exists
		    if (!Loc->isImplicitCode()) {
		      unsigned Line = Loc->getLine();
		      StringRef File = Loc->getFilename();
		      StringRef Dir = Loc->getDirectory();
		      if (Json) {
			J->attribute("line", Line);
			J->attribute("file", File);
			J->attribute("dir", Dir);
		      } else {
			errs() << "      at " << Dir << '/' << File << ':' << Line << '\n';
		      }
		    }
		  }
		}
	      }
	    }
	  }
	}
	  if (Json && lookingForErrno) {
	  J->attribute("errno_checked", false);
	  J->objectEnd();
	  }
      }
      if (Json) {
	J->arrayEnd();
	J->attributeEnd();
      }
    }
    if (Json) {
      J->objectEnd();
      J->attributeEnd();
      J->objectEnd();
      J->flush();
      errs() << '\n';
    }
    return false;
  }
}; // end of struct KRF
}  // end of anonymous namespace

char KRF::ID = 0;
static RegisterPass<KRF> X("KRF", "KRF Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
