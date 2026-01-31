# Coding Style

## Error Handling (CRITICAL)
ALWAYS wrap errors with context:
```go
// WRONG
if err != nil {
  return err
}

// CORRECT
if err != nil {
  return fmt.Errorf("fetch user %d: %w", userID, err)
}
```

## Early Return Pattern
NEVER nest deeply, use guard clauses:
```go
// WRONG
func Process(user *User) error {
  if user != nil {
    if user.IsActive {
      // logic
    }
  }
  return nil
}

// CORRECT
func Process(user *User) error {
  if user == nil {
    return errors.New("user is nil")
  }
  if !user.IsActive {
    return errors.New("user inactive")
  }
  // logic
  return nil
}
```

## Naming Conventions
Follow Go idioms:
- Package names: short, lowercase, no underscores
- Acronyms: `userID`, `httpClient`, `URL` (not `userId`, `HttpClient`)
- Interfaces: `-er` suffix (`Reader`, `Writer`, `UserRepository`)
- Constructors: `New` prefix (`NewUserService`)
- Unexported by default, export only what's needed

## File Organization
- One package = one responsibility
- 200-500 lines typical, 1000 max
- Split by domain: `user/`, `order/`, `payment/`

## Code Quality Checklist
Before marking work complete:
- [ ] All errors handled with context
- [ ] No deep nesting (use early return)
- [ ] No `fmt.Println` or `log.Println` (use structured logger)
- [ ] No hardcoded values (use config)
- [ ] `go vet` passes
- [ ] `golangci-lint` passes
