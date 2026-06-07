```markdown
# hexis-hermes-guardrails Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill introduces the core development patterns used in the `hexis-hermes-guardrails` repository. The codebase is written in Python, with a focus on clarity and maintainability. It follows conventional commit messages, uses consistent file naming and import/export styles, and includes a testing pattern (though the framework is not specified). This guide will help you quickly align with the repository's standards and workflows.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `my_module.py`, `data_processor.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .utils import helper_function
    ```

### Export Style
- Use **named exports** (explicitly listing what is available from a module).
  - Example:
    ```python
    __all__ = ['MyClass', 'my_function']
    ```

### Commit Messages
- Use **conventional commits** with the `feat` prefix for features.
  - Example:  
    ```
    feat: add user authentication middleware
    ```
- Keep commit messages concise (average 69 characters).

## Workflows

### Feature Development
**Trigger:** When adding a new feature  
**Command:** `/feature-dev`

1. Create a new branch for your feature.
2. Implement the feature using snake_case file naming and relative imports.
3. Export new classes/functions using named exports.
4. Write or update tests as needed.
5. Commit changes using a conventional commit message with the `feat` prefix.
6. Open a pull request for review.

### Code Review Preparation
**Trigger:** Before submitting code for review  
**Command:** `/prepare-review`

1. Ensure all file names use snake_case.
2. Check that all imports are relative within the package.
3. Verify that all exports are named.
4. Confirm that commit messages follow the conventional pattern.
5. Run all tests to ensure they pass.

## Testing Patterns

- Test files are expected to follow the `*.test.ts` pattern (TypeScript test files).
- The specific testing framework is unknown.
- Place test files alongside the code they test or in a dedicated `tests/` directory.
- Example test file name: `my_module.test.ts`

## Commands

| Command           | Purpose                                   |
|-------------------|-------------------------------------------|
| /feature-dev      | Start a new feature development workflow  |
| /prepare-review   | Prepare your code for review              |
```