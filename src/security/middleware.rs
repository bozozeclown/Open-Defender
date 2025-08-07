// src/security/middleware.rs
use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{info, warn, error};
use crate::security::{auth::AuthMiddleware, SecurityConfig};

pub async fn security_headers_middleware<B>(
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let mut response = next.run(req).await;
    
    // Add security headers
    response.headers_mut().insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap(),
    );
    
    response.headers_mut().insert(
        "X-Frame-Options",
        "DENY".parse().unwrap(),
    );
    
    response.headers_mut().insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap(),
    );
    
    response.headers_mut().insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    
    response.headers_mut().insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none';".parse().unwrap(),
    );
    
    response
}

pub async fn authentication_middleware<B>(
    State(auth_middleware): State<Arc<AuthMiddleware>>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, Response> {
    match auth_middleware.authenticate(req).await {
        Ok(req) => Ok(next.run(req).await),
        Err(response) => Err(response),
    }
}

pub async fn authorization_middleware<B>(
    State(auth_middleware): State<Arc<AuthMiddleware>>,
    resource: &str,
    action: &str,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, Response> {
    match auth_middleware.authorize(req, resource, action).await {
        Ok(req) => Ok(next.run(req).await),
        Err(response) => Err(response),
    }
}

pub async fn audit_logging_middleware<B>(
    State(config): State<Arc<SecurityConfig>>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    // Extract user info if available
    let user_id = req.extensions()
        .get::<crate::security::auth::Claims>()
        .map(|claims| claims.sub.clone());
    
    let response = next.run(req).await;
    let duration = start.elapsed();
    let status = response.status();
    
    if config.audit.enabled {
        let audit_event = crate::security::audit::AuditEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            user_id,
            action: format!("{} {}", method, uri),
            resource: uri.path().to_string(),
            result: if status.is_success() { "success" } else { "failure" }.to_string(),
            details: Some(format!("Status: {}, Duration: {:?}", status, duration)),
            ip_address: None, // Would need to extract from request
            user_agent: None, // Would need to extract from request
        };
        
        if let Err(e) = crate::security::audit::log_audit_event(audit_event) {
            error!("Failed to log audit event: {}", e);
        }
    }
    
    response
}