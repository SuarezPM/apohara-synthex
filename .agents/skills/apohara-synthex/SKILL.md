```markdown
# apohara-synthex Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns and conventions used in the `apohara-synthex` TypeScript codebase. You'll learn how to name files, structure imports and exports, write and locate tests, and follow the project's commit and workflow practices. This guide is ideal for new contributors or anyone looking to maintain consistency within the repository.

## Coding Conventions

### File Naming
- Use **camelCase** for all file names.
  - Example: `myUtility.ts`, `dataProcessor.test.ts`

### Import Style
- Use **relative imports** for referencing modules within the project.
  - Example:
    ```typescript
    import { processData } from './dataProcessor';
    ```

### Export Style
- Use **named exports** rather than default exports.
  - Example:
    ```typescript
    // In dataProcessor.ts
    export function processData(input: string): string {
      // implementation
    }
    ```

### Commit Messages
- Commit messages are **freeform** and do not follow a strict prefix or format.
- Average commit message length is around 43 characters.
  - Example: `Fix bug in data processing logic`

## Workflows

_No automated workflows detected in this repository._

## Testing Patterns

- **Testing Framework:** Not explicitly detected. Tests are written in files matching the `*.test.*` pattern.
- **Test File Naming:** Place tests alongside or near the code they test, using camelCase and the `.test.` infix.
  - Example: `dataProcessor.test.ts`
- **Test Example:**
  ```typescript
  import { processData } from './dataProcessor';

  test('processData returns expected output', () => {
    expect(processData('input')).toBe('expectedOutput');
  });
  ```

## Commands
| Command | Purpose |
|---------|---------|
| /test   | Run all test files matching `*.test.*` |
| /lint   | Lint the codebase according to project conventions |
| /build  | Build the TypeScript project |
```