```markdown
# network-monitor Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns and conventions used in the `network-monitor` Python codebase. You'll learn how to structure files, write imports and exports, follow commit message conventions, and understand the project's approach to testing. This guide is ideal for contributors aiming for consistency and maintainability in a Python project without a framework.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - **Example:**  
    `network_utils.py`  
    `connection_manager.py`

### Import Style
- Use **relative imports** within the package.
  - **Example:**
    ```python
    from .network_utils import ping_host
    from .connection_manager import ConnectionManager
    ```

### Export Style
- Use **named exports**; explicitly define what is exported from each module.
  - **Example:**
    ```python
    __all__ = ['ping_host', 'ConnectionManager']
    ```

### Commit Message Conventions
- Follow **conventional commit** style.
- Prefixes include: `fix`, `test`, `docs`.
- Average commit message length: ~57 characters.
  - **Example:**
    ```
    fix: handle timeout error in ping_host function
    test: add tests for connection_manager edge cases
    docs: update README with usage instructions
    ```

## Workflows

### Code Contribution
**Trigger:** When adding or updating code in the repository  
**Command:** `/contribute-code`

1. Create a new Python file using snake_case naming.
2. Use relative imports for referencing internal modules.
3. Define `__all__` in modules to specify exports.
4. Write clear, conventional commit messages with appropriate prefixes.

### Writing Tests
**Trigger:** When adding or updating tests  
**Command:** `/write-test`

1. Create a test file matching the pattern `*.test.ts` (note: TypeScript pattern detected; adapt for Python if needed).
2. Place test files alongside the code or in a dedicated test directory.
3. Follow the project's conventions for test structure and naming.

### Documentation Updates
**Trigger:** When updating or adding documentation  
**Command:** `/update-docs`

1. Use the `docs:` prefix in commit messages.
2. Update relevant markdown files or docstrings in code.
3. Ensure documentation reflects the latest code changes.

## Testing Patterns

- **Framework:** Not explicitly detected; testing framework is unknown.
- **File Pattern:** Test files follow the `*.test.ts` pattern (suggests possible cross-language or legacy patterns).
- **Best Practice:** For Python, use `test_*.py` and a framework like `pytest` or `unittest` for consistency.
- **Example Test File (Python):**
  ```python
  # test_network_utils.py
  import unittest
  from .network_utils import ping_host

  class TestNetworkUtils(unittest.TestCase):
      def test_ping_host_success(self):
          self.assertTrue(ping_host('127.0.0.1'))
  ```

## Commands
| Command           | Purpose                                      |
|-------------------|----------------------------------------------|
| /contribute-code  | Steps for contributing new or updated code   |
| /write-test       | Steps for adding or updating tests           |
| /update-docs      | Steps for updating documentation             |
```
