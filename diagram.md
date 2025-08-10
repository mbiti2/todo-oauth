# Todo App System Architecture Diagram

This document contains Mermaid diagrams that illustrate the system architecture, authentication flow, and component interactions of the Todo application.

## System Overview

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[Web Browser]
    end
    
    subgraph "Application Layer"
        TodoApp[Todo Application<br/>Port 3000]
        Templates[HTML Templates<br/>Askama Engine]
    end
    
    subgraph "Authentication Layer"
        Keycloak[Keycloak Server<br/>Port 8080]
        OAuth[OAuth2/OpenID Connect]
        JWT[JWT Token Management]
    end
    
    subgraph "Storage Layer"
        FileStorage[JSON File Storage<br/>todos.json]
        MemoryStorage[In-Memory Storage<br/>Arc<Mutex<Vec>>]
    end
    
    subgraph "External Services"
        JWKS[JWKS Endpoint]
        UserInfo[UserInfo Endpoint]
        Introspect[Token Introspection]
    end
    
    Browser <--> TodoApp
    TodoApp <--> Templates
    TodoApp <--> Keycloak
    TodoApp <--> FileStorage
    TodoApp <--> MemoryStorage
    Keycloak <--> OAuth
    Keycloak <--> JWT
    Keycloak <--> JWKS
    Keycloak <--> UserInfo
    Keycloak <--> Introspect
```

## Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant B as Browser
    participant T as Todo App
    participant K as Keycloak
    participant S as Storage
    
    Note over U,S: Initial Access
    U->>B: Navigate to /todos
    B->>T: GET /todos
    T->>T: Check auth_token cookie
    T->>B: Redirect to /login (401)
    B->>T: GET /login
    
    Note over U,S: OAuth Login Initiation
    T->>T: Generate PKCE challenge
    T->>T: Store PKCE verifier + CSRF state
    T->>B: Redirect to Keycloak auth URL
    B->>K: GET /auth (with PKCE challenge)
    
    Note over U,S: User Authentication
    K->>U: Display login form
    U->>K: Submit credentials
    K->>K: Validate credentials
    K->>B: Redirect with auth code + state
    
    Note over U,S: Token Exchange
    B->>T: GET /callback?code=...&state=...
    T->>T: Retrieve PKCE verifier using state
    T->>K: POST /token (code + PKCE verifier)
    K->>T: Return access_token + id_token
    
    Note over U,S: Session Establishment
    T->>T: Validate tokens
    T->>T: Set auth_token cookie
    T->>B: Redirect to /todos
    B->>T: GET /todos (with auth cookie)
    T->>T: Extract and validate JWT
    T->>S: Load user's todos
    T->>B: Return protected todo page
```

## Request Flow for Protected Endpoints

```mermaid
sequenceDiagram
    participant B as Browser
    participant T as Todo App
    participant A as AuthUser Extractor
    participant S as Storage
    participant K as Keycloak
    
    Note over B,K: Protected Request Flow
    B->>T: Request to protected endpoint
    T->>A: Extract AuthUser from request
    
    A->>A: Extract auth_token from cookies
    A->>A: Validate JWT token
    
    alt Token Valid
        A->>A: Return AuthUser with sub claim
        T->>S: Access user-specific data
        S->>T: Return filtered todos
        T->>B: Return protected content
    else Token Invalid/Expired
        A->>T: Return 401 Unauthorized
        T->>B: Redirect to /login
    end
    
    Note over B,K: Token Validation Process
    A->>K: Try token introspection
    alt Introspection Success
        K->>A: Return token claims
    else Introspection Failed
        A->>K: Try UserInfo endpoint
        alt UserInfo Success
            K->>A: Return user info
        else UserInfo Failed
            A->>A: Try local JWT validation
            alt Local JWT Success
                A->>A: Validate signature + claims
            else Local JWT Failed
                A->>A: Authentication failed
            end
        end
    end
```

## Security Architecture

```mermaid
graph TB
    subgraph "Security Layers"
        PKCE[PKCE Challenge]
        CSRF[CSRF Protection]
        JWT[JWT Validation]
        Cookies[Secure Cookies]
    end
    
    subgraph "Authentication Methods"
        Introspection[Token Introspection]
        UserInfo[UserInfo Endpoint]
        LocalJWT[Local JWT Validation]
    end
    
    subgraph "Protection Mechanisms"
        HttpOnly[HttpOnly Cookies]
        SameSite[SameSite=Lax]
        Expiration[Token Expiration]
        Validation[Input Validation]
    end
    
    PKCE --> OAuth2[OAuth2 Flow]
    CSRF --> State[State Parameter]
    JWT --> Introspection
    JWT --> UserInfo
    JWT --> LocalJWT
    
    Cookies --> HttpOnly
    Cookies --> SameSite
    Cookies --> Expiration
    
    Introspection --> Validation
    UserInfo --> Validation
    LocalJWT --> Validation
```

## Error Handling Flow

```mermaid
flowchart TD
    Start([Request Received]) --> AuthCheck{Authentication Check}
    
    AuthCheck -->|Valid Token| ProcessRequest[Process Request]
    AuthCheck -->|Invalid Token| TokenError{Token Error Type}
    
    TokenError -->|Expired| ClearCookies[Clear Auth Cookies]
    TokenError -->|Invalid| RedirectLogin[Redirect to Login]
    TokenError -->|Network Error| FallbackValidation[Fallback Validation]
    
    FallbackValidation -->|Success| ProcessRequest
    FallbackValidation -->|Failure| RedirectLogin
    
    ProcessRequest --> BusinessLogic[Business Logic]
    BusinessLogic --> Success{Success?}
    
    Success -->|Yes| ReturnResponse[Return Response]
    Success -->|No| HandleError[Handle Business Error]
    
    ClearCookies --> RedirectLogin
    RedirectLogin --> End([End Request])
    ReturnResponse --> End
    HandleError --> End
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Docker Environment"
        subgraph "Todo Service Container"
            RustApp[Rust Application<br/>Port 3000]
            Templates[HTML Templates]
            Storage[File Storage]
        end
        
        subgraph "Keycloak Container"
            Keycloak[Keycloak Server<br/>Port 8080]
            Database[Keycloak Data]
        end
    end
    
    subgraph "External Access"
        Browser[Web Browser]
        Admin[Admin Interface]
    end
    
    subgraph "Network Configuration"
        HostPorts[Host Port Mapping]
        InternalNet[Internal Docker Network]
    end
    
    Browser --> HostPorts
    Admin --> HostPorts
    
    HostPorts --> RustApp
    HostPorts --> Keycloak
    
    RustApp --> InternalNet
    Keycloak --> InternalNet
    
    InternalNet --> Database
    InternalNet --> Storage
    
    RustApp --> Templates
    RustApp --> Storage
    Keycloak --> Database
```

These diagrams provide a comprehensive view of the Todo application's architecture, showing how different components interact, the authentication flow, security measures, and deployment structure. Each diagram focuses on a specific aspect of the system to make it easier to understand the complete picture.
