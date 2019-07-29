#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Operator.h"
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
#include <vector>

using namespace llvm;

namespace {
const Function *getFunctionFromModule(const Module &M, const std::string &str) {
  const GlobalValue *g = M.getNamedValue(str);
  if (!g) {
    errs() << "GlobalValue " << str << " could not be found in module " << M.getName() << '\n';
    return NULL;
  }
  const Function *func = dyn_cast<Function>(g);
  if (!func) {
    errs() << "GlobalValue " << str << " is not a Function in  module " << M.getName() << '\n';
    return NULL;
  }
  return func;
}

void tokenize(std::string const &str, const char delim, std::vector<std::string> &out) {
  size_t start;
  size_t end = 0;
  while ((start = str.find_first_not_of(delim, end)) != std::string::npos) {
    end = str.find(delim, start);
    out.push_back(str.substr(start, end - start));
  }
}

bool isConst(const Use &Use, const Function *const call) {
  auto Subprogram = call->getSubprogram();
  if (!Subprogram) {
    errs() << "Cannot find subprogram for " << call->getName() << '\n';
    return false;
  }
  auto TypeArr = Subprogram->getType()->getTypeArray();
  // index will be Use->getOperandNo() + 1 (since return type is first)
  auto Type = dyn_cast<DIType>(TypeArr[Use.getOperandNo() + 1]);
  while (Type != NULL) {
    if (Type->getName().contains(
            "const")) { // Only known is "DW_TAG_const_type" but others may exist
      errs() << "Found it\n";
      return true;
    }
    if (const auto DIDerived = dyn_cast<DIDerivedType>(Type))
      Type = dyn_cast<DIType>(DIDerived->getBaseType());
    else
      Type = NULL;
  }
  return false;
}

using JObject = json::Object;
using JArray = json::Array;
using JValue = json::Value;

cl::opt<bool> Json("reverse-taint-json", cl::desc("Print output in json format"));
cl::opt<bool>
    IgnoreLine("reverse-taint-ignore-line",
               cl::desc("Ignores line number and matches all calls to the targeted function"));
cl::opt<std::string> Filename("reverse-taint-output", cl::desc("Output file"),
                              cl::init("reverseTaint.out"));
cl::opt<std::string> StackTrace("s", cl::desc("<comma-seperated stack trace functions>"),
                                cl::Required);

struct ReverseTaint : public ModulePass {
  static char ID;
  std::error_code FD_EC;
  raw_fd_ostream output;
  JArray Jtainted;
  ReverseTaint() : ModulePass(ID), output(Filename, FD_EC) {
    if (FD_EC) {
      errs() << "Failed to open file " << Filename << "\n";
    }
  }

  bool iterateOverArgs(const Use &U, std::unordered_set<int> *arguments,
                       std::unordered_set<Value *> &seen) {
    const auto V = U.get();
    if (seen.count(V))
      return false;
    seen.insert(V);
    V->print(errs());
    errs() << '\n';
    if (const auto &A = dyn_cast<Argument>(V)) {
      errs() << "It is an argument to the function in position " << A->getArgNo() << '\n';
      // go up a level, then return
      arguments->insert(A->getArgNo());
      return true;
    }
    if (const auto &C = dyn_cast<Constant>(V)) {
      errs() << "It is a constant.\n";
      // return here
      return false;
    }
    // Handle a call differently
    if (const auto call = dyn_cast<CallBase>(V)) {
      errs() << "Tainted by call to " << call->getCalledFunction()->getName() << '\n';
      return false;
    }
    // Handle a load by looking for the previous store(s)
    if (const auto load = dyn_cast<LoadInst>(V)) {
      bool ret = false;
      for (const auto &U : load->getPointerOperand()->uses()) {
        const auto &User = U.getUser();
        errs() << "Uses: ";
        User->print(errs());
        errs() << '\n';
        if (const auto store = dyn_cast<StoreInst>(User)) {
          errs() << "Found store\n";
          store->print(errs());
          errs() << '\n';
          for (const auto &Use : store->operands()) {
            if (iterateOverArgs(Use, arguments, seen))
              ret = true;
          }
        }
        if (const auto call = dyn_cast<CallBase>(User)) {
          errs() << "Found call2\n";
          const auto F = call->getCalledFunction(); // check if F is null?
          // check if param num is const?
          if (isConst(U, F))
            continue;
          errs() << "Tainted by call to " << call->getCalledFunction()->getName() << '\n';
        }
      }
      return ret;
    }
    // Otherwise
    if (const auto &I = dyn_cast<Instruction>(V)) {
      bool ret = false;
      for (const auto &Use : I->operands()) {
        if (iterateOverArgs(Use, arguments, seen))
          ret = true;
      }
      return ret;
    }
    errs() << "Not an instruction! Can't go deeper.\n  Instead: ";
    V->print(errs());
    errs() << '\n';
    return false;
  }

  bool checkFunction(const Function *func, const Function *func2, unsigned line,
                     std::unordered_set<int> *taintedArgs) {
    std::unordered_set<int> lastArgs = *taintedArgs;
    taintedArgs->clear();
    bool ret = false;
    std::unordered_set<Value *> seen;
    for (const auto &B : func->getBasicBlockList()) {
      for (const auto &I : B) {
        if (const CallBase *call_inst = dyn_cast<CallBase>(&I)) {
          if (const auto &bitcast = dyn_cast<ConstantExpr>(call_inst->getCalledOperand())) {
            const auto f = bitcast->getOperand(0);
            if (f != func2)
              continue;
          } else if (call_inst->getCalledFunction() != func2)
            continue;
          if (!IgnoreLine) {
            const DILocation *Loc = call_inst->getDebugLoc();
            if (!Loc) {
              errs() << "No debug information! Aborting\n";
              return false;
            }
            if (Loc->getLine() != line) // Not the right call
              continue;
          }
          errs() << "Found call\n";
          call_inst->print(errs());
          errs() << '\n';
          for (const auto &i : lastArgs) {
            if (iterateOverArgs(call_inst->getArgOperandUse(i), taintedArgs, seen))
              ret = true;
          }
        }
      }
    }
    return ret;
  }

  bool runOnModule(Module &M) override {
    if (FD_EC) {
      return false;
    }
    JArray JRoot{};
    std::vector<std::string> functions;
    tokenize(StackTrace, ',', functions);
    bool analyze = true;
    int functionDepth = 0;
    std::unordered_set<int> taintedArgs;
    while (analyze && (functionDepth < functions.size() - 1)) {
      const Function *func =
          getFunctionFromModule(M, functions[functionDepth + 2]); // One we are searching in
      if (!func)
        return false;
      if (!func->isStrongDefinitionForLinker()) { // needs to be defined to search through
        errs() << "Strong definition of " << StackTrace << " is not in module " << M.getName()
               << '\n';
        return false;
      }
      const int line = IgnoreLine ? 0 : std::stoi(functions[functionDepth + 1]);
      const Function *func2 =
          getFunctionFromModule(M, functions[functionDepth]); // One we are searching for
      if (!func2)
        return false;
      errs() << "Searching calls to " << functions[functionDepth] << " in "
             << functions[functionDepth + 2] << '\n';
      // If its the first one
      if (functionDepth == 0) {
        for (int i = 0; i < func2->arg_size(); i++)
          taintedArgs.insert(i);
      }
      analyze = checkFunction(func, func2, line, &taintedArgs);
      // if (analyze) {
      //   errs() << "At this point, go up a level and debug calls to " << func->getName()
      //          << " by the one above it\n";
      //   for (const auto &i : taintedArgs) {
      //     errs() << "Faulted arg: " << i << " in function above\n";
      //   }
      // }
      ++functionDepth;
      ++functionDepth;
    }
    if (analyze) { // If they ran out of functions to analyze
      errs() << "Tainted arguments in the function above:";
      for (const auto &i : taintedArgs) {
        errs() << ' ' << i;
      }
      errs() << '\n';
    } else {
      errs() << "All paths explored\n";
    }
    if (!Json) {
      output << "REVERSETAINT: entered module ";
      output.write_escaped(M.getName()) << '\n';
    }
    return false;
  } // End of runOnModule()
};  // end of struct REVERSETAINT
} // end of anonymous namespace

char ReverseTaint::ID = 0;
static RegisterPass<ReverseTaint> X("reverse-taint", "Reverse Taint Pass",
                                    false /* Only looks at CFG */, false /* Analysis Pass */);
