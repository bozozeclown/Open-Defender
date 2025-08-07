// src/collaboration/rbac.rs
use crate::error::AppResult;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct RbacManager {
    users: Arc<RwLock<HashMap<String, User>>>,
    roles: Arc<RwLock<HashMap<String, Role>>>,
    permissions: Arc<RwLock<HashMap<String, Permission>>>,
    sessions: Arc<RwLock<HashMap<String, AuthSession>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: String,
    pub role_ids: HashSet<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permission_ids: HashSet<String>,
    pub is_system_role: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub description: String,
    pub resource: String,
    pub action: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub ip_address: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub effect: PolicyEffect,
    pub principals: Vec<String>, // User IDs or role IDs
    pub resources: Vec<String>,
    pub actions: Vec<String>,
    pub conditions: Vec<PolicyCondition>,
    pub priority: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    GreaterThan,
    LessThan,
    In,
    NotIn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub name: String,
    pub resource_type: String,
    pub attributes: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl RbacManager {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            permissions: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn initialize(&self) -> AppResult<()> {
        // Create default roles and permissions
        self.create_default_roles_and_permissions().await?;
        
        // Create default admin user
        self.create_default_admin_user().await?;
        
        Ok(())
    }

    async fn create_default_roles_and_permissions(&self) -> AppResult<()> {
        let mut roles = self.roles.write().await;
        let mut permissions = self.permissions.write().await;
        
        // Create permissions
        let view_incidents_perm = Permission {
            id: "view_incidents".to_string(),
            name: "View Incidents".to_string(),
            description: "View security incidents".to_string(),
            resource: "incidents".to_string(),
            action: "read".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let create_incidents_perm = Permission {
            id: "create_incidents".to_string(),
            name: "Create Incidents".to_string(),
            description: "Create security incidents".to_string(),
            resource: "incidents".to_string(),
            action: "create".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let update_incidents_perm = Permission {
            id: "update_incidents".to_string(),
            name: "Update Incidents".to_string(),
            description: "Update security incidents".to_string(),
            resource: "incidents".to_string(),
            action: "update".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let delete_incidents_perm = Permission {
            id: "delete_incidents".to_string(),
            name: "Delete Incidents".to_string(),
            description: "Delete security incidents".to_string(),
            resource: "incidents".to_string(),
            action: "delete".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let assign_incidents_perm = Permission {
            id: "assign_incidents".to_string(),
            name: "Assign Incidents".to_string(),
            description: "Assign security incidents to users".to_string(),
            resource: "incidents".to_string(),
            action: "assign".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let execute_playbooks_perm = Permission {
            id: "execute_playbooks".to_string(),
            name: "Execute Playbooks".to_string(),
            description: "Execute response playbooks".to_string(),
            resource: "playbooks".to_string(),
            action: "execute".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let manage_users_perm = Permission {
            id: "manage_users".to_string(),
            name: "Manage Users".to_string(),
            description: "Manage system users".to_string(),
            resource: "users".to_string(),
            action: "manage".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let manage_roles_perm = Permission {
            id: "manage_roles".to_string(),
            name: "Manage Roles".to_string(),
            description: "Manage system roles".to_string(),
            resource: "roles".to_string(),
            action: "manage".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let create_workspaces_perm = Permission {
            id: "create_workspaces".to_string(),
            name: "Create Workspaces".to_string(),
            description: "Create collaboration workspaces".to_string(),
            resource: "workspaces".to_string(),
            action: "create".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let manage_workspaces_perm = Permission {
            id: "manage_workspaces".to_string(),
            name: "Manage Workspaces".to_string(),
            description: "Manage collaboration workspaces".to_string(),
            resource: "workspaces".to_string(),
            action: "manage".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        // Add permissions to the permissions map
        permissions.insert(view_incidents_perm.id.clone(), view_incidents_perm);
        permissions.insert(create_incidents_perm.id.clone(), create_incidents_perm);
        permissions.insert(update_incidents_perm.id.clone(), update_incidents_perm);
        permissions.insert(delete_incidents_perm.id.clone(), delete_incidents_perm);
        permissions.insert(assign_incidents_perm.id.clone(), assign_incidents_perm);
        permissions.insert(execute_playbooks_perm.id.clone(), execute_playbooks_perm);
        permissions.insert(manage_users_perm.id.clone(), manage_users_perm);
        permissions.insert(manage_roles_perm.id.clone(), manage_roles_perm);
        permissions.insert(create_workspaces_perm.id.clone(), create_workspaces_perm);
        permissions.insert(manage_workspaces_perm.id.clone(), manage_workspaces_perm);
        
        // Create roles
        let admin_role = Role {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            description: "System administrator with full access".to_string(),
            permission_ids: HashSet::from([
                "view_incidents".to_string(),
                "create_incidents".to_string(),
                "update_incidents".to_string(),
                "delete_incidents".to_string(),
                "assign_incidents".to_string(),
                "execute_playbooks".to_string(),
                "manage_users".to_string(),
                "manage_roles".to_string(),
                "create_workspaces".to_string(),
                "manage_workspaces".to_string(),
            ]),
            is_system_role: true,
            created_at: chrono::Utc::now(),
        };
        
        let analyst_role = Role {
            id: "analyst".to_string(),
            name: "Security Analyst".to_string(),
            description: "Security analyst with incident management capabilities".to_string(),
            permission_ids: HashSet::from([
                "view_incidents".to_string(),
                "create_incidents".to_string(),
                "update_incidents".to_string(),
                "assign_incidents".to_string(),
                "execute_playbooks".to_string(),
                "create_workspaces".to_string(),
            ]),
            is_system_role: true,
            created_at: chrono::Utc::now(),
        };
        
        let responder_role = Role {
            id: "responder".to_string(),
            name: "Incident Responder".to_string(),
            description: "Incident responder with limited capabilities".to_string(),
            permission_ids: HashSet::from([
                "view_incidents".to_string(),
                "update_incidents".to_string(),
                "execute_playbooks".to_string(),
            ]),
            is_system_role: true,
            created_at: chrono::Utc::now(),
        };
        
        let readonly_role = Role {
            id: "readonly".to_string(),
            name: "Read-only User".to_string(),
            description: "User with read-only access".to_string(),
            permission_ids: HashSet::from([
                "view_incidents".to_string(),
            ]),
            is_system_role: true,
            created_at: chrono::Utc::now(),
        };
        
        // Add roles to the roles map
        roles.insert(admin_role.id.clone(), admin_role);
        roles.insert(analyst_role.id.clone(), analyst_role);
        roles.insert(responder_role.id.clone(), responder_role);
        roles.insert(readonly_role.id.clone(), readonly_role);
        
        Ok(())
    }

    async fn create_default_admin_user(&self) -> AppResult<()> {
        let mut users = self.users.write().await;
        
        let admin_user = User {
            id: "admin".to_string(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            full_name: "System Administrator".to_string(),
            role_ids: HashSet::from(["admin".to_string()]),
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: None,
        };
        
        users.insert(admin_user.id.clone(), admin_user);
        
        Ok(())
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> AppResult<Option<String>> {
        let users = self.users.read().await;
        
        // Find user by username
        let user = users.values()
            .find(|u| u.username == username && u.is_active)
            .cloned();
        
        let user = match user {
            Some(user) => user,
            None => return Ok(None),
        };
        
        // Verify password (in a real implementation, use proper password hashing)
        if password != "admin123" { // Placeholder password check
            return Ok(None);
        }
        
        // Create session
        let session_id = Uuid::new_v4().to_string();
        let token = self.generate_jwt_token(&user)?;
        
        let session = AuthSession {
            id: session_id.clone(),
            user_id: user.id.clone(),
            token: token.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            ip_address: "127.0.0.1".to_string(), // Placeholder
            user_agent: "Security Monitoring System".to_string(), // Placeholder
        };
        
        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }
        
        // Update user's last login
        {
            let mut users = self.users.write().await;
            if let Some(user) = users.get_mut(&user.id) {
                user.last_login = Some(chrono::Utc::now());
                user.updated_at = chrono::Utc::now();
            }
        }
        
        Ok(Some(token))
    }

    fn generate_jwt_token(&self, user: &User) -> AppResult<String> {
        // In a real implementation, use a proper JWT library
        let header = b64_encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let payload = b64_encode(&serde_json::json!({
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.role_ids,
            "exp": chrono::Utc::now().timestamp() + 86400, // 24 hours
            "iat": chrono::Utc::now().timestamp(),
        }));
        
        let signature = "placeholder_signature"; // In a real implementation, sign with a secret key
        
        Ok(format!("{}.{}.{}", header, payload, signature))
    }

    pub async fn validate_token(&self, token: &str) -> AppResult<Option<User>> {
        let sessions = self.sessions.read().await;
        
        // Find session by token
        let session = sessions.values()
            .find(|s| s.token == token && s.expires_at > chrono::Utc::now())
            .cloned();
        
        let session = match session {
            Some(session) => session,
            None => return Ok(None),
        };
        
        // Get user
        let users = self.users.read().await;
        let user = users.get(&session.user_id).cloned();
        
        Ok(user)
    }

    pub async fn check_permission(&self, user_id: &str, resource: &str, action: &str) -> AppResult<bool> {
        let users = self.users.read().await;
        let roles = self.roles.read().await;
        let permissions = self.permissions.read().await;
        
        // Get user
        let user = match users.get(user_id) {
            Some(user) => user,
            None => return Ok(false),
        };
        
        // Get all permissions for the user
        let mut user_permissions = HashSet::new();
        
        for role_id in &user.role_ids {
            if let Some(role) = roles.get(role_id) {
                for permission_id in &role.permission_ids {
                    user_permissions.insert(permission_id.clone());
                }
            }
        }
        
        // Check if user has the required permission
        for permission_id in user_permissions {
            if let Some(permission) = permissions.get(permission_id) {
                if permission.resource == resource && permission.action == action {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }

    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        full_name: &str,
        password: &str,
        role_ids: &[String],
    ) -> AppResult<String> {
        let user_id = Uuid::new_v4().to_string();
        
        let user = User {
            id: user_id.clone(),
            username: username.to_string(),
            email: email.to_string(),
            full_name: full_name.to_string(),
            role_ids: role_ids.iter().cloned().collect(),
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: None,
        };
        
        // Store user (in a real implementation, hash the password)
        let mut users = self.users.write().await;
        users.insert(user_id.clone(), user);
        
        Ok(user_id)
    }

    pub async fn update_user(
        &self,
        user_id: &str,
        username: Option<&str>,
        email: Option<&str>,
        full_name: Option<&str>,
        role_ids: Option<&[String]>,
        is_active: Option<bool>,
    ) -> AppResult<()> {
        let mut users = self.users.write().await;
        
        if let Some(user) = users.get_mut(user_id) {
            if let Some(username) = username {
                user.username = username.to_string();
            }
            if let Some(email) = email {
                user.email = email.to_string();
            }
            if let Some(full_name) = full_name {
                user.full_name = full_name.to_string();
            }
            if let Some(role_ids) = role_ids {
                user.role_ids = role_ids.iter().cloned().collect();
            }
            if let Some(is_active) = is_active {
                user.is_active = is_active;
            }
            user.updated_at = chrono::Utc::now();
            
            Ok(())
        } else {
            Err(crate::error::AppError::NotFound(format!("User not found: {}", user_id)))
        }
    }

    pub async fn delete_user(&self, user_id: &str) -> AppResult<()> {
        let mut users = self.users.write().await;
        
        if users.remove(user_id).is_some() {
            // Also remove any active sessions for this user
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| session.user_id != user_id);
            
            Ok(())
        } else {
            Err(crate::error::AppError::NotFound(format!("User not found: {}", user_id)))
        }
    }

    pub async fn create_role(
        &self,
        name: &str,
        description: &str,
        permission_ids: &[String],
    ) -> AppResult<String> {
        let role_id = Uuid::new_v4().to_string();
        
        let role = Role {
            id: role_id.clone(),
            name: name.to_string(),
            description: description.to_string(),
            permission_ids: permission_ids.iter().cloned().collect(),
            is_system_role: false,
            created_at: chrono::Utc::now(),
        };
        
        let mut roles = self.roles.write().await;
        roles.insert(role_id.clone(), role);
        
        Ok(role_id)
    }

    pub async fn update_role(
        &self,
        role_id: &str,
        name: Option<&str>,
        description: Option<&str>,
        permission_ids: Option<&[String]>,
    ) -> AppResult<()> {
        let mut roles = self.roles.write().await;
        
        if let Some(role) = roles.get_mut(role_id) {
            if role.is_system_role {
                return Err(crate::error::AppError::Validation("Cannot modify system role".to_string()));
            }
            
            if let Some(name) = name {
                role.name = name.to_string();
            }
            if let Some(description) = description {
                role.description = description.to_string();
            }
            if let Some(permission_ids) = permission_ids {
                role.permission_ids = permission_ids.iter().cloned().collect();
            }
            
            Ok(())
        } else {
            Err(crate::error::AppError::NotFound(format!("Role not found: {}", role_id)))
        }
    }

    pub async fn delete_role(&self, role_id: &str) -> AppResult<()> {
        let mut roles = self.roles.write().await;
        
        if let Some(role) = roles.get(role_id) {
            if role.is_system_role {
                return Err(crate::error::AppError::Validation("Cannot delete system role".to_string()));
            }
            
            if roles.remove(role_id).is_some() {
                // Also remove this role from all users
                let mut users = self.users.write().await;
                for user in users.values_mut() {
                    user.role_ids.remove(role_id);
                }
                
                Ok(())
            } else {
                Err(crate::error::AppError::NotFound(format!("Role not found: {}", role_id)))
            }
        } else {
            Err(crate::error::AppError::NotFound(format!("Role not found: {}", role_id)))
        }
    }

    pub async fn create_permission(
        &self,
        name: &str,
        description: &str,
        resource: &str,
        action: &str,
    ) -> AppResult<String> {
        let permission_id = Uuid::new_v4().to_string();
        
        let permission = Permission {
            id: permission_id.clone(),
            name: name.to_string(),
            description: description.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let mut permissions = self.permissions.write().await;
        permissions.insert(permission_id.clone(), permission);
        
        Ok(permission_id)
    }

    pub async fn update_permission(
        &self,
        permission_id: &str,
        name: Option<&str>,
        description: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
    ) -> AppResult<()> {
        let mut permissions = self.permissions.write().await;
        
        if let Some(permission) = permissions.get_mut(permission_id) {
            if let Some(name) = name {
                permission.name = name.to_string();
            }
            if let Some(description) = description {
                permission.description = description.to_string();
            }
            if let Some(resource) = resource {
                permission.resource = resource.to_string();
            }
            if let Some(action) = action {
                permission.action = action.to_string();
            }
            
            Ok(())
        } else {
            Err(crate::error::AppError::NotFound(format!("Permission not found: {}", permission_id)))
        }
    }

    pub async fn delete_permission(&self, permission_id: &str) -> AppResult<()> {
        let mut permissions = self.permissions.write().await;
        
        if permissions.remove(permission_id).is_some() {
            // Also remove this permission from all roles
            let mut roles = self.roles.write().await;
            for role in roles.values_mut() {
                role.permission_ids.remove(permission_id);
            }
            
            Ok(())
        } else {
            Err(crate::error::AppError::NotFound(format!("Permission not found: {}", permission_id)))
        }
    }

    pub async fn logout(&self, token: &str) -> AppResult<()> {
        let mut sessions = self.sessions.write().await;
        
        // Find and remove session by token
        sessions.retain(|_, session| session.token != token);
        
        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> AppResult<()> {
        let mut sessions = self.sessions.write().await;
        
        // Remove expired sessions
        sessions.retain(|_, session| session.expires_at > chrono::Utc::now());
        
        Ok(())
    }

    pub async fn get_user(&self, user_id: &str) -> AppResult<Option<User>> {
        let users = self.users.read().await;
        Ok(users.get(user_id).cloned())
    }

    pub async fn get_users(&self) -> AppResult<Vec<User>> {
        let users = self.users.read().await;
        Ok(users.values().cloned().collect())
    }

    pub async fn get_role(&self, role_id: &str) -> AppResult<Option<Role>> {
        let roles = self.roles.read().await;
        Ok(roles.get(role_id).cloned())
    }

    pub async fn get_roles(&self) -> AppResult<Vec<Role>> {
        let roles = self.roles.read().await;
        Ok(roles.values().cloned().collect())
    }

    pub async fn get_permission(&self, permission_id: &str) -> AppResult<Option<Permission>> {
        let permissions = self.permissions.read().await;
        Ok(permissions.get(permission_id).cloned())
    }

    pub async fn get_permissions(&self) -> AppResult<Vec<Permission>> {
        let permissions = self.permissions.read().await;
        Ok(permissions.values().cloned().collect())
    }
}

fn b64_encode(data: &serde_json::Value) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(data.to_string().as_bytes())
}