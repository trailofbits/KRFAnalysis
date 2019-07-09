#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstrTypes.h"
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

cl::opt<bool> Json("toctou-json", cl::desc("Print output in json format"));
cl::opt<std::string> Filename("toctou-output", cl::desc("Output file"), cl::init("toctou.out"));

struct ToctouPass : public ModulePass {
  static char ID;
  std::error_code FD_EC;
  raw_fd_ostream output;
  ToctouPass() : ModulePass(ID), output(Filename, FD_EC) {
    if (FD_EC) {
      errs() << "Failed to open file " << Filename << "\n";
    }
  }

  bool runOnModule(Module &M) override {
    if (FD_EC) {
      return false;
    }
    JArray JRoot{};
    if (!Json) {
      output << "TOC/TOU: entered module ";
      output.write_escaped(M.getName()) << '\n';
    }

    for (const auto &F : M) {
      if (F.isIntrinsic() || !F.isStrongDefinitionForLinker()) {
        continue;
      }
      if (!Json) {
        output << "  entered function " << (F.hasName() ? F.getName() : "unnamed_function") << '\n';
      }
      for (const auto &B : F) {
        for (const auto &I : B) {
          if (const CallBase *call_inst = dyn_cast<CallBase>(&I)) {
            const Function *callee = call_inst->getCalledFunction();
            if (!callee || !callee->hasName())
              continue;
            const Value *tracked;
            if (callee->getName().equals("access")) {
              tracked = call_inst->getOperand(0); // see access(2)
            } else if (callee->getName().equals("mktemp") || callee->getName().equals("tmpnam") ||
                       callee->getName().equals("tempnam")) {
              tracked = call_inst;
            } else {
              continue;
            }
            for (const auto &V : tracked->uses()) {
              const auto U = V.getUser();
              if (const CallBase *second_call = dyn_cast<CallBase>(U)) {
                const Function *second_callee = second_call->getCalledFunction();
                if (!second_callee || !second_callee->hasName() ||
                    !(second_callee->getName().equals("open")))
                  continue;
                std::string toctouTypeBacker;
                raw_string_ostream toctouType(toctouTypeBacker);
                toctouType << callee->getName() << '/' << second_callee->getName();
                if (!Json)
                  output << "    " << toctouType.str() << " TOC/TOU found!\n";
                if (const DILocation *Loc = I.getDebugLoc()) { // Gets source info if exists
                  if (!Loc->isImplicitCode()) {
                    const unsigned Line = Loc->getLine();
                    const StringRef File = Loc->getFilename();
                    const StringRef Dir = Loc->getDirectory();
                    if (Json) {
                      JRoot.push_back(JObject{
                          {"function", (F.hasName() ? F.getName() : "unname_function")},
                          {"module", M.getName()},
                          {"type", toctouType.str()},
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
                        {"function", (F.hasName() ? F.getName() : "unname_function")},
                        {"module", M.getName()},
                        {"type", toctouType.str()},
                    });
                  }
                }
              }
            }
          }
        }
      }
    }
    if (Json) {
      JValue Jout = std::move(JRoot);
      output << Jout << '\n';
    }
    return false;
  }
}; // end of struct ToctouPass
} // end of anonymous namespace

char ToctouPass::ID = 1;
static RegisterPass<ToctouPass> X("toctou", "TOC/TOU Pass", false, false);
