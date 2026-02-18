# Engineering Guidelines

## Standard Workflow
- **Start by clarifying the objective.** Before writing code, confirm you understand what the user wants and why. If the request is ambiguous, ask — don't guess.
- Default cycle: **plan → implement → run tests → code review → fix findings → run tests → commit**.
- Always run the full test suite after implementation. If there's a `check` script, use it. Don't wait to be asked.
- Run benchmarks (if available) after performance-related changes.
- After review findings, fix ALL issues and re-run tests before reporting back. Don't document bugs as limitations—fix them.
- When the user references a prior choice or decision, proceed immediately. Don't re-ask.

## Development Principles
- **Readability**: Use clear names and logical structure. Comment intent, not action.
- **Modularity**: Small, single-purpose functions. Avoid deep nesting, many branches, or interleaved concerns.
- **Pragmatism**: Solve the immediate problem. Avoid speculative abstractions.
- **Explicitness**: Validate at boundaries. Fail fast with useful error messages.
- **Consistency**: Follow existing codebase patterns and naming conventions.
- **Cleanliness**: Delete dead code (verify with grep—it may be called dynamically). Only refactor what you understand and can test.
- **Testability**: Favor pure functions, clear I/O, and limited side effects.

## Testing Standards
- **Behavior-Focused**: Verify *what* code does, not *how*. Refactoring shouldn't break tests.
- **Atomic**: One concept per test. Follow the "Arrange, Act, Assert" pattern.
- **Documentation**: Use tests to explain system behavior through clear naming.
- **Realistic Mocks**: Mock external boundaries only. Don't mock internal collaborators.
- **Comprehensive**: Always test edge cases, empty inputs, and error paths.
- **Reliable**: Tests must be fast, deterministic, and isolated.
- **Regression-Proof**: Bug found? Write a failing test first, then fix it.
- **Organized**: Distribute tests into existing test files by feature/module. Don't create catch-all test files.
- **Accurate Mocks**: Verify API signatures from source before constructing mocks.

## Commit Messages
- **Match the repo's style**: Follow existing subject line conventions (check `git log --oneline`).
- **Imperative mood**: "Add feature" not "Added feature" or "Adds feature".
- **Bullet the changes**: After the subject line, include a concise list of meaningful changes.
- **Explain what and why**: The diff shows *how*—the message should explain *what* changed and *why*.
- **Keep it scannable**: Future readers (and agents) use git history to understand recent changes.
