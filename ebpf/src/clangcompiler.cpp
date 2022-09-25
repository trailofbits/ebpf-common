/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "clangcompiler.h"
#include "bpf_helpers.h"
#include "ebpf_common_helpers.h"

#include <llvm/ADT/ArrayRef.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/TargetSelect.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>

#include <clang/Basic/DiagnosticOptions.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Basic/TargetOptions.h>

#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/CompilerInvocation.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>

#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Lex/PreprocessorOptions.h>

#include <tob/ebpf/ebpf_utils.h>
#include <tob/error/stringerror.h>

#include <btfparse/ibtfheadergenerator.h>

namespace tob::ebpf {

namespace {

const std::string kMainFilePath{"/internal/main.c"};
const std::string kUserDefinitionsIncludePath{"/internal/user_definitions.h"};
const std::string kBtfparseIncludeHeaderPath{"/internal/btfparse.h"};
const std::string kBPFHelpersIncludePath{"/internal/bpf_helpers.h"};
const std::string kEbpfCommonHelpersIncludePath{
    "/internal/ebpf_common_helpers.h"};

// clang-format off
#if LLVM_VERSION_MAJOR < 11
  const std::vector<const char *>
#else
  llvm::ArrayRef<const char *>
#endif

kCommonFlagList{
  "-O2",
  "-triple",
  "bpf-pc-linux",
  "-Wall",
  "-Wconversion",
  "-Wunused",
  "-Wshadow",
  "-Werror",
  "-include",
  kUserDefinitionsIncludePath.c_str(),
  "-include",
  kBtfparseIncludeHeaderPath.c_str(),
  "-include",
  kBPFHelpersIncludePath.c_str(),
  "-include",
  kEbpfCommonHelpersIncludePath.c_str()
};
// clang-format on

} // namespace

struct ClangCompiler::PrivateData final {
  std::string btf_include_header;
};

StringErrorOr<BPFProgramMap>
ClangCompiler::build(const std::string &source_code,
                     const DefinitionList &definition_list) {
  auto llvm_module_exp =
      createModule(source_code, definition_list, d->btf_include_header);

  if (!llvm_module_exp.succeeded()) {
    return llvm_module_exp.error();
  }

  auto llvm_module = llvm_module_exp.takeValue();

  auto llvm_bpf_pseudo_function = llvm_module->getFunction("llvm_bpf_pseudo");
  if (llvm_bpf_pseudo_function != nullptr) {
    auto &context = llvm_module->getContext();

    llvm::IRBuilder<> builder(context);

    // clang-format off
    auto pseudo_intrinsic_type = llvm::FunctionType::get(
      builder.getInt64Ty(),

      {
        builder.getInt64Ty(),
        builder.getInt64Ty()
      },

      false
    );
    // clang-format on

    auto pseudo_intrinsic = llvm::Function::Create(
        pseudo_intrinsic_type, llvm::GlobalValue::ExternalLinkage,
        "llvm.bpf.pseudo", *llvm_module.get());

    llvm_bpf_pseudo_function->replaceAllUsesWith(pseudo_intrinsic);
  }

  return createProgramMap(std::move(llvm_module));
}

ClangCompiler::~ClangCompiler() {}

llvm::MemoryBuffer *
ClangCompiler::getStringAsMemoryBuffer(const std::string &source_code) {
  auto buffer =
      llvm::MemoryBuffer::getMemBufferCopy(llvm::StringRef(source_code));

  // Clang will take ownership of this pointer, so release it
  return buffer.release();
}

std::string ClangCompiler::generateDefinitionInclude(
    const IClangCompiler::DefinitionList &definition_list) {
  std::stringstream buffer;

  for (const auto &definition : definition_list) {
    buffer << "#define " << definition.name << " " << definition.value << "\n";
  }

  return buffer.str();
}

ClangCompiler::ClangCompiler(const std::filesystem::path &btf_file_path)
    : d(new PrivateData) {

  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllTargets();

  auto btf_res = btfparse::IBTF::createFromPathList({btf_file_path});
  if (btf_res.failed()) {
    auto error = btf_res.takeError();
    throw StringError::create(error.toString());
  }

  auto btf = btf_res.takeValue();
  if (btf->count() == 0) {
    throw StringError::create("No BTF type found");
  }

  auto header_generator = btfparse::IBTFHeaderGenerator::create();

  std::string header;
  if (!header_generator->generate(header, btf)) {
    throw StringError::create("Failed to generate the BTF header");
  }

  d->btf_include_header = std::move(header);
}

StringErrorOr<std::unique_ptr<llvm::Module>>
ClangCompiler::createModule(const std::string &source_code,
                            const DefinitionList &definition_list,
                            const std::string &btf_include_header) {

  llvm::IntrusiveRefCntPtr<clang::DiagnosticIDs> diagnostic_id_list;
  clang::DiagnosticOptions diagnostic_options;
  auto text_diagnostic_printer =
      new clang::TextDiagnosticPrinter(llvm::errs(), &diagnostic_options);

  auto diagnostic_engine = new clang::DiagnosticsEngine(
      diagnostic_id_list, &diagnostic_options, text_diagnostic_printer);

  auto compiler_invocation = std::make_shared<clang::CompilerInvocation>();

#if LLVM_VERSION_MAJOR < 11
  clang::CompilerInvocation::CreateFromArgs(
      *compiler_invocation.get(), &kCommonFlagList[0],
      &kCommonFlagList[0] + kCommonFlagList.size(), *diagnostic_engine);

#else
  clang::CompilerInvocation::CreateFromArgs(
      *compiler_invocation.get(), kCommonFlagList, *diagnostic_engine);
#endif

  auto &frontend_options = compiler_invocation->getFrontendOpts();
  frontend_options.Inputs.clear();

#if LLVM_VERSION_MAJOR < 11
  frontend_options.Inputs.push_back(
      clang::FrontendInputFile(kMainFilePath, clang::InputKind::C));

#else
  frontend_options.Inputs.push_back(clang::FrontendInputFile(
      kMainFilePath, clang::InputKind(clang::Language::C)));
#endif

  auto &codegen_options = compiler_invocation->getCodeGenOpts();
  codegen_options.setInlining(clang::CodeGenOptions::NormalInlining);

  auto &preprocessor_options = compiler_invocation->getPreprocessorOpts();

  preprocessor_options.addRemappedFile(kMainFilePath,
                                       getStringAsMemoryBuffer(source_code));

  auto definition_include = generateDefinitionInclude(definition_list);
  preprocessor_options.addRemappedFile(
      kUserDefinitionsIncludePath, getStringAsMemoryBuffer(definition_include));

  preprocessor_options.addRemappedFile(
      kBtfparseIncludeHeaderPath, getStringAsMemoryBuffer(btf_include_header));

  preprocessor_options.addRemappedFile(
      kBPFHelpersIncludePath, getStringAsMemoryBuffer(kBPFHelperDefinitions));

  preprocessor_options.addRemappedFile(
      kEbpfCommonHelpersIncludePath,
      getStringAsMemoryBuffer(kEbpfCommonHelpers));

  clang::CompilerInstance compiler_instance;
  compiler_instance.setInvocation(compiler_invocation);
  compiler_instance.createDiagnostics();

  auto *compiler_action = new clang::EmitLLVMOnlyAction();
  if (!compiler_instance.ExecuteAction(*compiler_action)) {
    return StringError::create("Failed to generate the LLVM IR");
  }

  return compiler_action->takeModule();
}

StringErrorOr<BPFProgramMap>
ClangCompiler::createProgramMap(std::unique_ptr<llvm::Module> llvm_module) {
  for (auto &function : llvm_module->getFunctionList()) {
    auto name = function.getName();
    function.setSection("section_" + name.str());
  }

  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  if (llvm::verifyModule(*llvm_module.get(), &error_stream) != 0) {
    error_stream.flush();

    std::string error_message = "Module verification failed";
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    return StringError::create(error_message);
  }

  auto program_map_res = ebpf::compileModule(*llvm_module.get());
  if (!program_map_res.succeeded()) {
    return program_map_res.error();
  }

  return program_map_res.takeValue();
}

} // namespace tob::ebpf
