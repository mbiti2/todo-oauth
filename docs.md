# Todo App Documentation

## Overview

This is a secure, OAuth2-protected Todo application built with Rust using the Axum web framework. The application integrates with Keycloak for authentication and authorization, providing a modern, secure way to manage personal tasks.

## Architecture

The application follows a client-server architecture with the following key components:

- **Frontend**: HTML templates with HTMX for dynamic interactions
- **Backend**: Rust-based web server using Axum framework
- **Authentication**: Keycloak OAuth2/OpenID Connect integration
- **Storage**: JSON file-based storage for todos
- **Security**: JWT token validation with multiple fallback strategies

## Core Components

### 1. Authentication System

#### OAuth2 Client Configuration

- **Realm**: `todo-realm`
- **Client ID**: `todo-client`
- **Client Secret**: Configured for secure communication
- **Scopes**: `openid`, `profile`, `email`

#### Authentication Flow

1. **Login Initiation** (`/login`):
   - Generates PKCE challenge for enhanced security
   - Redirects user to Keycloak authorization endpoint
   - Stores PKCE verifier with CSRF token

2. **OAuth Callback** (`/callback`):
   - Receives authorization code from Keycloak
   - Exchanges code for access/ID tokens
   - Sets secure HTTP-only cookies
   - Redirects to main application

3. **Token Validation**:
   - Multiple validation strategies for robustness:
     - Server-side token introspection (preferred)
     - UserInfo endpoint with bearer token
     - Local JWT validation with JWKS

#### Security Features

- **PKCE**: Prevents authorization code interception attacks
- **CSRF Protection**: State parameter prevents cross-site request forgery
- **Secure Cookies**: HttpOnly, SameSite=Lax, proper expiration
- **JWT Validation**: RSA256 signature verification with JWKS

### 2. Web Framework (Axum)

#### Routing Structure

- `/` - Landing page (public)
- `/todos` - Main todo interface (protected)
- `/add` - Add new todo (protected)
- `/toggle/:id` - Toggle todo completion (protected)
- `/delete/:id` - Delete todo (protected)
- `/login` - Initiate OAuth flow (public)
- `/callback` - OAuth callback handler (public)
- `/logout` - Logout and clear session (public)

#### Middleware and Extractors

- **AuthUser Extractor**: Custom extractor for authenticated users
- **CookieJar**: Manages authentication cookies
- **State Management**: Shared todo storage across requests

### 3. Data Models

#### TodoItem Structure

```rust
struct TodoItem {
    id: Uuid,           // Unique identifier
    title: String,      // Todo description
    completed: bool,     // Completion status
    user_sub: String,   // User identifier from JWT
}
```

#### Claims Structure (JWT)

```rust
struct Claims {
    sub: String,                    // Subject (user ID)
    exp: usize,                     // Expiration time
    iat: usize,                     // Issued at time
    iss: String,                    // Issuer
    aud: String,                    // Audience
    name: Option<String>,           // User's display name
    preferred_username: Option<String>, // Username
    email: Option<String>,          // Email address
    nbf: Option<usize>,            // Not before time
}
```

### 4. Storage System

#### File-based Storage

- **Format**: JSON with pretty printing
- **Location**: `todos.json` in application root
- **Persistence**: In-memory with periodic file writes
- **Thread Safety**: Arc<Mutex<Vec<TodoItem>>> for concurrent access

#### Data Operations

- **Load**: Read from JSON file on startup
- **Save**: Write to JSON file after modifications
- **User Isolation**: Todos filtered by user's `sub` claim

### 5. Frontend Templates

#### Template Engine

- **Framework**: Askama (Rust-native template engine)
- **Features**: Type-safe template compilation
- **Styling**: Modern CSS with dark theme

#### Key Templates

1. **Landing Page** (`landing.html`):
   - Public welcome page
   - Login button to initiate OAuth flow

2. **Todo Interface** (`index.html`):
   - Protected main application
   - HTMX integration for dynamic interactions
   - Responsive design with modern UI

### 6. Security Implementation

#### JWT Validation Strategies

1. **Token Introspection** (Primary):
   - Server-side validation via Keycloak
   - Most secure, handles all token types

2. **UserInfo Endpoint** (Fallback):
   - Standard OAuth2 user info retrieval
   - Works with access tokens

3. **Local JWT Validation** (Last Resort):
   - JWKS-based signature verification
   - Issuer and expiration validation

#### Cookie Security

- **HttpOnly**: Prevents XSS attacks
- **SameSite=Lax**: CSRF protection
- **Secure Expiration**: Automatic cleanup
- **Path Restriction**: Limited to application scope

## Configuration

### Environment Variables

- `RUST_LOG`: Logging level (default: debug)
- Keycloak connection details (hardcoded for demo)

### Keycloak Setup

- **Admin**: `admin/admin`
- **Realm**: `todo-realm`
- **Client**: `todo-client` (confidential)
- **Redirect URI**: `http://localhost:3000/callback`

### Network Configuration

- **Application**: `localhost:3000`
- **Keycloak**: `localhost:8080`
- **Internal Communication**: `keycloak:8080` (Docker)

## Dependencies

### Core Web Framework

- **Axum**: Modern Rust web framework
- **Tokio**: Async runtime
- **Tower**: HTTP middleware stack

### Authentication & Security

- **OAuth2**: OAuth2 client implementation
- **jsonwebtoken**: JWT handling
- **reqwest**: HTTP client for external APIs

### Template & Serialization

- **Askama**: Template engine
- **Serde**: Serialization/deserialization
- **Serde JSON**: JSON handling

### Utilities

- **Anyhow**: Error handling
- **UUID**: Unique identifier generation
- **Chrono**: Date/time handling
- **Tracing**: Structured logging

## Deployment

### Docker Compose

- **Keycloak**: Development server with persistent data
- **Todo Service**: Rust application with hot reload
- **Networking**: Internal communication between services

### Production Considerations

- **HTTPS**: Enable TLS for production
- **Database**: Replace file storage with proper database
- **Load Balancing**: Multiple application instances
- **Monitoring**: Health checks and metrics
- **Secrets Management**: Environment-based configuration

## Error Handling

### Authentication Errors

- **Invalid Tokens**: Redirect to login
- **Expired Tokens**: Clear cookies and redirect
- **Network Issues**: Graceful fallback to local validation

### Application Errors

- **Template Errors**: Graceful degradation
- **Storage Errors**: Fallback to empty state
- **Validation Errors**: User-friendly error messages

## Performance Considerations

### Caching

- **JWKS**: Cached in memory for JWT validation
- **User Data**: Minimal caching, always fresh

### Concurrency

- **Async/Await**: Non-blocking I/O operations
- **Mutex Protection**: Thread-safe data access
- **Connection Pooling**: HTTP client reuse

## Monitoring and Logging

### Logging Strategy

- **Structured Logging**: Using tracing framework
- **Log Levels**: Configurable verbosity
- **Context Information**: Request correlation

### Health Indicators

- **Keycloak Connectivity**: OAuth endpoint health
- **Storage Health**: File system accessibility
- **Authentication Status**: Token validation success rate
