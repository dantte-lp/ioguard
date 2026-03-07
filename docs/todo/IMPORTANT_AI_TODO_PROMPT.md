> **DEPRECATED**: This prompt was written for the original refactoring approach (October 2025).
> The project has been replanned from scratch in March 2026 with a clean implementation.
> See `docs/plans/2026-03-07-wolfguard-architecture-design.md` for current architecture.

---

# TODO Prompt: Modernize WolfGuard Repository

You are an experienced C systems architect and technical writer tasked with turning the current WolfGuard repository into a coherent, production-ready codebase. Follow the steps below meticulously, documenting outcomes and open questions as you go.

## Objectives
1. **Synchronize documentation with reality.**
   - Update README and supporting docs to reflect actual directories, modules, and build instructions.
   - Move aspirational "coming soon" sections into a dedicated roadmap or planning document.
   - Provide accurate, step-by-step setup guidance for the chosen build system (CMake or Meson) and remove contradictory tool versions.

2. **Align code with supported C standards.**
   - Replace non-standard C++ constructs (`constexpr`, digit separators, etc.) with valid C23 or C17 equivalents.
   - Decide whether C17 suffices; if so, adjust compiler flags, code, and docs accordingly.
   - Ensure the code compiles cleanly with GCC and Clang using the declared standard without relying on extensions.

3. **Strengthen the TLS backend abstraction.**
   - Implement an explicit Strategy pattern via a `tls_backend_vtable` with function pointers for init, session management, and IO.
   - Enable dependency injection to swap TLS providers (e.g., wolfSSL, GnuTLS) without pervasive `switch` statements.
   - Add unit tests or mocks to validate backend selection and behavior.

4. **Fix the priority parser error system.**
   - Replace negative enumeration indexing with a safe mapping strategy (e.g., offset arrays or lookup tables).
   - Add `static_assert` checks for error ranges and cover `priority_strerror` with table-driven tests.

5. **Rationalize build scripts and dependencies.**
   - Trim `pkg_check_modules` to libraries that are actually used today; mark future dependencies as optional.
   - Vendor or fetch Unity (and any other external test frameworks) to guarantee reproducible CI builds.
   - Ensure build files reflect the real dependency graph and succeed in a clean environment.

6. **Build a sustainable testing strategy.**
   - Establish a unit test layout (e.g., for the priority parser and TLS abstraction) with deterministic fixtures.
   - Integrate tests into CI with the selected compiler and language standard to catch regressions early.
   - Document how contributors should run tests locally.

## Deliverables
- Updated documentation, build scripts, and code reflecting the objectives above.
- Passing CI that compiles and runs tests under the documented configuration.
- A changelog entry summarizing the modernization work and highlighting new contributor guidance.

Treat each objective as a blocking TODO: completion requires code changes, documentation updates, and tests that prove the improvements.
