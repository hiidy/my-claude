# Security Guidelines

## Mandatory Security Checks

Before ANY commit:
- [ ] No hardcoded secrets (API keys, passwords, tokens)
- [ ] All user inputs validated
- [ ] SQL injection prevention (parameterized queries)
- [ ] No unsafe template rendering (XSS prevention)
- [ ] CSRF protection enabled (for web apps)
- [ ] Authentication/authorization verified
- [ ] Rate limiting on all endpoints
- [ ] Error messages don't leak sensitive data
- [ ] No use of unsafe package without justification
- [ ] Proper TLS configuration

## Secret Management
```go
// ❌ NEVER: Hardcoded secrets
const apiKey = "sk-proj-xxxxx"

// ✅ ALWAYS: Environment variables
func getAPIKey() (string, error) {
    apiKey := os.Getenv("OPENAI_API_KEY")
    if apiKey == "" {
        return "", errors.New("OPENAI_API_KEY not configured")
    }
    return apiKey, nil
}

// ✅ BETTER: Use a config struct with validation
type Config struct {
    OpenAIKey   string `env:"OPENAI_API_KEY,required"`
    DatabaseURL string `env:"DATABASE_URL,required"`
    Debug       bool   `env:"DEBUG" envDefault:"false"`
}

func LoadConfig() (*Config, error) {
    cfg := &Config{}
    if err := env.Parse(cfg); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    return cfg, nil
}
```

## SQL Injection Prevention
```go
// ❌ NEVER: String concatenation
query := "SELECT * FROM users WHERE id = " + userID
db.Raw(query).Scan(&user)

// ❌ NEVER: fmt.Sprintf for queries
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)

// ✅ ALWAYS: Parameterized queries
db.Where("id = ?", userID).First(&user)

// ✅ ALWAYS: Named parameters
db.Where("name = @name AND age > @age", sql.Named("name", name), sql.Named("age", age))

// ✅ ALWAYS: Using sqlx with named params
query := "SELECT * FROM users WHERE name = :name"
rows, err := db.NamedQuery(query, map[string]interface{}{"name": name})
```

## Input Validation
```go
// ✅ Validate and sanitize all inputs
type CreateUserRequest struct {
    Email    string `json:"email" validate:"required,email,max=255"`
    Name     string `json:"name" validate:"required,min=1,max=100"`
    Age      int    `json:"age" validate:"gte=0,lte=150"`
    Password string `json:"password" validate:"required,min=8,max=72"`
}

func (h *Handler) CreateUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }
    
    // Use validator
    validate := validator.New()
    if err := validate.Struct(req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "validation failed"})
        return
    }
    
    // Sanitize strings
    req.Name = strings.TrimSpace(req.Name)
    req.Email = strings.ToLower(strings.TrimSpace(req.Email))
    
    // Continue processing...
}
```

## XSS Prevention (Template Rendering)
```go
// ❌ NEVER: Render raw HTML from user input
template.HTML(userInput)

// ✅ ALWAYS: Use html/template (auto-escapes by default)
tmpl := template.Must(template.ParseFiles("page.html"))
tmpl.Execute(w, data) // Auto-escapes

// ✅ If you must render HTML, sanitize first
import "github.com/microcosm-cc/bluemonday"

p := bluemonday.UGCPolicy()
sanitized := p.Sanitize(userInput)
```

## Authentication & Authorization
```go
// ✅ Secure password hashing
import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}

func CheckPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// ✅ JWT validation middleware
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
            return
        }
        
        claims, err := ValidateJWT(strings.TrimPrefix(token, "Bearer "))
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
            return
        }
        
        c.Set("user_id", claims.UserID)
        c.Next()
    }
}

// ✅ Authorization check
func (h *Handler) DeletePost(c *gin.Context) {
    userID := c.GetString("user_id")
    postID := c.Param("id")
    
    post, err := h.repo.GetPost(c, postID)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
        return
    }
    
    // Check ownership
    if post.AuthorID != userID {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }
    
    // Delete...
}
```

## Rate Limiting
```go
// ✅ Using golang.org/x/time/rate
import "golang.org/x/time/rate"

func RateLimitMiddleware(rps float64, burst int) gin.HandlerFunc {
    limiter := rate.NewLimiter(rate.Limit(rps), burst)
    
    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
                "error": "rate limit exceeded",
            })
            return
        }
        c.Next()
    }
}

// ✅ Per-IP rate limiting
type IPRateLimiter struct {
    ips map[string]*rate.Limiter
    mu  sync.RWMutex
    r   rate.Limit
    b   int
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
    i.mu.Lock()
    defer i.mu.Unlock()
    
    limiter, exists := i.ips[ip]
    if !exists {
        limiter = rate.NewLimiter(i.r, i.b)
        i.ips[ip] = limiter
    }
    
    return limiter
}
```

## Secure Error Handling
```go
// ❌ NEVER: Expose internal errors
c.JSON(500, gin.H{"error": err.Error()}) // May leak DB schema, paths, etc.

// ✅ ALWAYS: Generic error messages to client, detailed logs internally
func (h *Handler) GetUser(c *gin.Context) {
    user, err := h.repo.GetUser(c, c.Param("id"))
    if err != nil {
        // Log detailed error internally
        h.logger.Error("failed to get user",
            zap.Error(err),
            zap.String("user_id", c.Param("id")),
            zap.String("request_id", c.GetString("request_id")),
        )
        
        // Return generic error to client
        if errors.Is(err, ErrNotFound) {
            c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
            return
        }
        c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
        return
    }
    
    c.JSON(http.StatusOK, user)
}
```

## TLS Configuration
```go
// ✅ Secure TLS configuration
func NewTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        },
        PreferServerCipherSuites: true,
    }
}

// ✅ HTTPS server
server := &http.Server{
    Addr:      ":443",
    Handler:   router,
    TLSConfig: NewTLSConfig(),
    ReadTimeout:  5 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
}
server.ListenAndServeTLS("cert.pem", "key.pem")
```

## Unsafe Package Warning
```go
// ❌ AVOID: unsafe package unless absolutely necessary
import "unsafe"

// If you must use unsafe, document WHY
// #nosec G103 -- Required for zero-copy string conversion in hot path
// Performance critical: benchmarked 10x improvement
func bytesToString(b []byte) string {
    return *(*string)(unsafe.Pointer(&b))
}
```

## Security Response Protocol

If security issue found:

1. **STOP** immediately
2. Use **security-reviewer** agent
3. Fix CRITICAL issues before continuing
4. Rotate any exposed secrets
5. Review entire codebase for similar issues
6. Check git history for accidentally committed secrets:
```bash
   # Search for potential secrets in git history
   git log -p | grep -E "(password|secret|apikey|api_key|token)" -i
   
   # Use tools like gitleaks
   gitleaks detect --source .
```
7. If secrets were exposed:
```bash
   # Rotate immediately
   # - Generate new API keys
   # - Change passwords
   # - Revoke old tokens
   
   # Consider using git-filter-repo to remove from history
   # (coordinate with team first)
```

## Security Linting
```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run security scan
gosec ./...

# Run with specific rules
gosec -include=G101,G102,G103 ./...

# Exclude test files
gosec -exclude-dir=*_test.go ./...
```

## Common gosec Rules to Watch

| Rule | Description |
|------|-------------|
| G101 | Hardcoded credentials |
| G102 | Bind to all interfaces |
| G103 | Unsafe package usage |
| G104 | Unhandled errors |
| G107 | URL provided to HTTP request as taint input |
| G108 | Profiling endpoint exposed |
| G109 | Integer overflow |
| G110 | Decompression bomb |
| G201 | SQL query construction using format string |
| G202 | SQL query construction using string concatenation |
| G203 | Unescaped data in HTML templates |
| G204 | Subprocess launched with variable |
| G301 | Poor file permissions |
| G304 | File path provided as taint input |
| G401 | Use of weak cryptographic primitive |
| G501 | Import blacklist: crypto/md5 |
| G502 | Import blacklist: crypto/des |