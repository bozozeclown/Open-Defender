// src/collaboration/mod.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message,
    tungstenite::handshake::client::Request,
};
use tracing::{debug, error, info, warn, instrument};
use uuid::Uuid;

use crate::config::CollaborationConfig;
use crate::observability::{increment_counter, record_histogram, trace_function};

pub struct CollaborationManager {
    config: CollaborationConfig,
    workspaces: Arc<RwLock<HashMap<String, Workspace>>>,
    users: Arc<RwLock<HashMap<String, User>>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    message_bus: Arc<RwLock<MessageBus>>,
    websocket_server: Arc<WebSocketServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: String,
    pub members: HashSet<String>,
    pub incidents: HashSet<String>,
    pub chat_messages: Vec<ChatMessage>,
    pub shared_artifacts: Vec<SharedArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub permissions: HashSet<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_active: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub workspace_id: Option<String>,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_ping: chrono::DateTime<chrono::Utc>,
    pub socket_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub username: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Text,
    Incident,
    Alert,
    Artifact,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedArtifact {
    pub id: String,
    pub workspace_id: String,
    pub artifact_id: String,
    pub shared_by: String,
    pub shared_at: chrono::DateTime<chrono::Utc>,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageBus {
    pub subscribers: HashMap<String, mpsc::UnboundedSender<CollaborationMessage>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationMessage {
    pub id: String,
    pub message_type: CollaborationMessageType,
    pub workspace_id: Option<String>,
    pub user_id: String,
    pub payload: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationMessageType {
    ChatMessage,
    UserJoined,
    UserLeft,
    WorkspaceCreated,
    WorkspaceUpdated,
    IncidentShared,
    ArtifactShared,
    CursorPosition,
    TypingIndicator,
    SystemNotification,
}

impl CollaborationManager {
    pub fn new(config: CollaborationConfig) -> Self {
        let manager = Self {
            config,
            workspaces: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            message_bus: Arc::new(RwLock::new(MessageBus {
                subscribers: HashMap::new(),
            })),
            websocket_server: Arc::new(WebSocketServer::new()),
        };
        
        // Start session cleanup task
        let manager_clone = Arc::new(manager);
        tokio::spawn(async move {
            manager_clone.start_session_cleanup().await;
        });
        
        // Return a non-Arc version (this is a bit of a hack for the circular dependency)
        Self {
            config: manager_clone.config.clone(),
            workspaces: manager_clone.workspaces.clone(),
            users: manager_clone.users.clone(),
            sessions: manager_clone.sessions.clone(),
            message_bus: manager_clone.message_bus.clone(),
            websocket_server: manager_clone.websocket_server.clone(),
        }
    }

    #[instrument(skip(self))]
    pub async fn create_workspace(
        &self,
        name: String,
        description: String,
        created_by: String,
    ) -> Result<String> {
        trace_function!("create_workspace");
        
        let workspace_id = Uuid::new_v4().to_string();
        let workspace = Workspace {
            id: workspace_id.clone(),
            name,
            description,
            created_at: chrono::Utc::now(),
            created_by: created_by.clone(),
            members: {
                let mut members = HashSet::new();
                members.insert(created_by);
                members
            },
            incidents: HashSet::new(),
            chat_messages: Vec::new(),
            shared_artifacts: Vec::new(),
        };

        let mut workspaces = self.workspaces.write().await;
        workspaces.insert(workspace_id.clone(), workspace);

        // Broadcast workspace creation
        self.broadcast_message(CollaborationMessage {
            id: Uuid::new_v4().to_string(),
            message_type: CollaborationMessageType::WorkspaceCreated,
            workspace_id: Some(workspace_id.clone()),
            user_id: created_by,
            payload: serde_json::json!({
                "workspace_id": workspace_id,
                "name": workspaces.get(&workspace_id).unwrap().name,
                "created_by": created_by,
            }),
            timestamp: chrono::Utc::now(),
        }).await?;

        info!("Created workspace: {}", workspace_id);
        increment_counter!("workspaces_created");
        Ok(workspace_id)
    }

    #[instrument(skip(self))]
    pub async fn join_workspace(&self, workspace_id: &str, user_id: &str) -> Result<()> {
        trace_function!("join_workspace");
        
        let mut workspaces = self.workspaces.write().await;
        
        if let Some(workspace) = workspaces.get_mut(workspace_id) {
            workspace.members.insert(user_id.to_string());
            
            // Broadcast user joined
            self.broadcast_message(CollaborationMessage {
                id: Uuid::new_v4().to_string(),
                message_type: CollaborationMessageType::UserJoined,
                workspace_id: Some(workspace_id.to_string()),
                user_id: user_id.to_string(),
                payload: serde_json::json!({
                    "workspace_id": workspace_id,
                    "user_id": user_id,
                }),
                timestamp: chrono::Utc::now(),
            }).await?;
            
            info!("User {} joined workspace {}", user_id, workspace_id);
            increment_counter!("workspace_joins");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Workspace not found: {}", workspace_id))
        }
    }

    #[instrument(skip(self))]
    pub async fn leave_workspace(&self, workspace_id: &str, user_id: &str) -> Result<()> {
        trace_function!("leave_workspace");
        
        let mut workspaces = self.workspaces.write().await;
        
        if let Some(workspace) = workspaces.get_mut(workspace_id) {
            workspace.members.remove(user_id);
            
            // Broadcast user left
            self.broadcast_message(CollaborationMessage {
                id: Uuid::new_v4().to_string(),
                message_type: CollaborationMessageType::UserLeft,
                workspace_id: Some(workspace_id.to_string()),
                user_id: user_id.to_string(),
                payload: serde_json::json!({
                    "workspace_id": workspace_id,
                    "user_id": user_id,
                }),
                timestamp: chrono::Utc::now(),
            }).await?;
            
            info!("User {} left workspace {}", user_id, workspace_id);
            increment_counter!("workspace_leaves");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Workspace not found: {}", workspace_id))
        }
    }

    #[instrument(skip(self))]
    pub async fn send_chat_message(
        &self,
        workspace_id: &str,
        user_id: &str,
        username: &str,
        message: String,
        message_type: MessageType,
    ) -> Result<String> {
        trace_function!("send_chat_message");
        
        let chat_message = ChatMessage {
            id: Uuid::new_v4().to_string(),
            workspace_id: workspace_id.to_string(),
            user_id: user_id.to_string(),
            username: username.clone(),
            message,
            timestamp: chrono::Utc::now(),
            message_type,
        };

        let mut workspaces = self.workspaces.write().await;
        
        if let Some(workspace) = workspaces.get_mut(workspace_id) {
            workspace.chat_messages.push(chat_message.clone());
            
            // Broadcast chat message
            self.broadcast_message(CollaborationMessage {
                id: Uuid::new_v4().to_string(),
                message_type: CollaborationMessageType::ChatMessage,
                workspace_id: Some(workspace_id.to_string()),
                user_id: user_id.to_string(),
                payload: serde_json::json!(chat_message),
                timestamp: chrono::Utc::now(),
            }).await?;
            
            info!("Chat message sent in workspace {} by user {}", workspace_id, username);
            increment_counter!("chat_messages_sent");
            Ok(chat_message.id)
        } else {
            Err(anyhow::anyhow!("Workspace not found: {}", workspace_id))
        }
    }

    #[instrument(skip(self))]
    pub async fn share_incident(&self, workspace_id: &str, incident_id: &str, user_id: &str) -> Result<()> {
        trace_function!("share_incident");
        
        let mut workspaces = self.workspaces.write().await;
        
        if let Some(workspace) = workspaces.get_mut(workspace_id) {
            workspace.incidents.insert(incident_id.to_string());
            
            // Broadcast incident shared
            self.broadcast_message(CollaborationMessage {
                id: Uuid::new_v4().to_string(),
                message_type: CollaborationMessageType::IncidentShared,
                workspace_id: Some(workspace_id.to_string()),
                user_id: user_id.to_string(),
                payload: serde_json::json!({
                    "workspace_id": workspace_id,
                    "incident_id": incident_id,
                    "shared_by": user_id,
                }),
                timestamp: chrono::Utc::now(),
            }).await?;
            
            info!("Incident {} shared in workspace {} by user {}", incident_id, workspace_id, user_id);
            increment_counter!("incidents_shared");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Workspace not found: {}", workspace_id))
        }
    }

    #[instrument(skip(self))]
    pub async fn share_artifact(
        &self,
        workspace_id: &str,
        artifact_id: &str,
        user_id: &str,
        permissions: String,
    ) -> Result<()> {
        trace_function!("share_artifact");
        
        let shared_artifact = SharedArtifact {
            id: Uuid::new_v4().to_string(),
            workspace_id: workspace_id.to_string(),
            artifact_id: artifact_id.to_string(),
            shared_by: user_id.to_string(),
            shared_at: chrono::Utc::now(),
            permissions,
        };

        let mut workspaces = self.workspaces.write().await;
        
        if let Some(workspace) = workspaces.get_mut(workspace_id) {
            workspace.shared_artifacts.push(shared_artifact);
            
            // Broadcast artifact shared
            self.broadcast_message(CollaborationMessage {
                id: Uuid::new_v4().to_string(),
                message_type: CollaborationMessageType::ArtifactShared,
                workspace_id: Some(workspace_id.to_string()),
                user_id: user_id.to_string(),
                payload: serde_json::json!({
                    "workspace_id": workspace_id,
                    "artifact_id": artifact_id,
                    "shared_by": user_id,
                }),
                timestamp: chrono::Utc::now(),
            }).await?;
            
            info!("Artifact {} shared in workspace {} by user {}", artifact_id, workspace_id, user_id);
            increment_counter!("artifacts_shared");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Workspace not found: {}", workspace_id))
        }
    }

    #[instrument(skip(self))]
    pub async fn update_cursor_position(
        &self,
        workspace_id: &str,
        user_id: &str,
        cursor_data: serde_json::Value,
    ) -> Result<()> {
        trace_function!("update_cursor_position");
        
        // Broadcast cursor position
        self.broadcast_message(CollaborationMessage {
            id: Uuid::new_v4().to_string(),
            message_type: CollaborationMessageType::CursorPosition,
            workspace_id: Some(workspace_id.to_string()),
            user_id: user_id.to_string(),
            payload: cursor_data,
            timestamp: chrono::Utc::now(),
        }).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn send_typing_indicator(
        &self,
        workspace_id: &str,
        user_id: &str,
        username: &str,
        is_typing: bool,
    ) -> Result<()> {
        trace_function!("send_typing_indicator");
        
        // Broadcast typing indicator
        self.broadcast_message(CollaborationMessage {
            id: Uuid::new_v4().to_string(),
            message_type: CollaborationMessageType::TypingIndicator,
            workspace_id: Some(workspace_id.to_string()),
            user_id: user_id.to_string(),
            payload: serde_json::json!({
                "username": username,
                "is_typing": is_typing,
            }),
            timestamp: chrono::Utc::now(),
        }).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn broadcast_message(&self, message: CollaborationMessage) -> Result<()> {
        trace_function!("broadcast_message");
        let message_bus = self.message_bus.read().await;
        
        // Send to all subscribers
        for (session_id, sender) in &message_bus.subscribers {
            // Only send to users in the same workspace if workspace_id is specified
            if let Some(ref workspace_id) = message.workspace_id {
                let sessions = self.sessions.read().await;
                if let Some(session) = sessions.get(session_id) {
                    if session.workspace_id.as_ref() == Some(workspace_id) {
                        if let Err(e) = sender.send(message.clone()) {
                            error!("Failed to send message to session {}: {}", session_id, e);
                        }
                    }
                }
            } else {
                // Send to all subscribers if no workspace specified
                if let Err(e) = sender.send(message.clone()) {
                    error!("Failed to send message to session {}: {}", session_id, e);
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn register_session(
        &self,
        session_id: String,
        user_id: String,
        workspace_id: Option<String>,
        socket_addr: String,
    ) -> Result<mpsc::UnboundedReceiver<CollaborationMessage>> {
        trace_function!("register_session");
        
        let (sender, receiver) = mpsc::unbounded_channel();

        let session = Session {
            id: session_id.clone(),
            user_id,
            workspace_id,
            connected_at: chrono::Utc::now(),
            last_ping: chrono::Utc::now(),
            socket_addr,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }

        {
            let mut message_bus = self.message_bus.write().await;
            message_bus.subscribers.insert(session_id, sender);
        }

        info!("Session {} registered", session_id);
        increment_counter!("sessions_registered");
        Ok(receiver)
    }

    #[instrument(skip(self))]
    pub async fn update_session_ping(&self, session_id: &str) -> Result<()> {
        trace_function!("update_session_ping");
        
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_ping = chrono::Utc::now();
            Ok(())
        } else {
            Err(anyhow::anyhow!("Session not found: {}", session_id))
        }
    }

    #[instrument(skip(self))]
    pub async fn cleanup_session(&self, session_id: &str) -> Result<()> {
        trace_function!("cleanup_session");
        
        // Remove from message bus
        {
            let mut message_bus = self.message_bus.write().await;
            message_bus.subscribers.remove(session_id);
        }
        
        // Remove from sessions and leave workspace if needed
        {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.remove(session_id) {
                // Leave workspace if in one
                if let Some(workspace_id) = &session.workspace_id {
                    drop(sessions); // Release lock before calling leave_workspace
                    if let Err(e) = self.leave_workspace(workspace_id, &session.user_id).await {
                        error!("Failed to leave workspace during session cleanup: {}", e);
                    }
                }
            }
        }
        
        info!("Session {} cleaned up", session_id);
        increment_counter!("sessions_cleaned_up");
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn cleanup_stale_sessions(&self) -> Result<()> {
        trace_function!("cleanup_stale_sessions");
        
        let timeout = chrono::Duration::minutes(5); // 5 minute timeout
        let now = chrono::Utc::now();
        
        let stale_sessions: Vec<String> = {
            let sessions = self.sessions.read().await;
            sessions.iter()
                .filter(|(_, session)| now - session.last_ping > timeout)
                .map(|(id, _)| id.clone())
                .collect()
        };
        
        for session_id in stale_sessions {
            if let Err(e) = self.cleanup_session(&session_id).await {
                error!("Failed to cleanup stale session {}: {}", session_id, e);
            }
        }
        
        Ok(())
    }

    #[instrument(skip(self))]
    async fn start_session_cleanup(&self) {
        trace_function!("start_session_cleanup");
        
        let mut interval = tokio::time::interval(Duration::from_secs(60)); // Check every minute
        
        loop {
            interval.tick().await;
            if let Err(e) = self.cleanup_stale_sessions().await {
                error!("Failed to cleanup stale sessions: {}", e);
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn start_websocket_server(&self) -> Result<()> {
        trace_function!("start_websocket_server");
        
        let listener = tokio::net::TcpListener::bind(&self.config.websocket_endpoint)
            .await
            .context("Failed to bind to WebSocket address")?;
        
        info!("WebSocket server started on {}", self.config.websocket_endpoint);
        
        while let Ok((stream, addr)) = listener.accept().await {
            let ws_config = tungstenite::protocol::WebSocketConfig {
                max_send_queue: Some(1024),
                ..Default::default()
            };
            
            let websocket = tokio_tungstenite::accept_async_with_config(stream, Some(ws_config))
                .await
                .context("Failed to accept WebSocket connection")?;
            
            info!("WebSocket connection established from {}", addr);
            
            // Generate session ID
            let session_id = Uuid::new_v4().to_string();
            
            // For now, we'll use a placeholder user ID
            // In a real implementation, we would authenticate the connection first
            let user_id = "user123".to_string();
            
            // Handle connection
            self.websocket_server.handle_connection(
                websocket,
                session_id,
                user_id,
                None, // No workspace initially
                self,
            ).await;
        }
        
        Ok(())
    }
}

// WebSocket Server Implementation
pub struct WebSocketServer {
    connections: Arc<RwLock<HashMap<String, WebSocketConnection>>>,
}

pub struct WebSocketConnection {
    pub session_id: String,
    pub user_id: String,
    pub workspace_id: Option<String>,
    pub sender: mpsc::UnboundedSender<Message>,
}

impl WebSocketServer {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn handle_connection(
        &self,
        websocket: WebSocket,
        session_id: String,
        user_id: String,
        workspace_id: Option<String>,
        manager: &CollaborationManager,
    ) {
        let (mut sender, mut receiver) = websocket.split();
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Store connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(session_id.clone(), WebSocketConnection {
                session_id: session_id.clone(),
                user_id: user_id.clone(),
                workspace_id,
                sender: tx,
            });
        }
        
        // Register session with collaboration manager
        if let Err(e) = manager.register_session(
            session_id.clone(),
            user_id.clone(),
            workspace_id,
            "websocket".to_string(),
        ).await {
            error!("Failed to register session: {}", e);
            return;
        }
        
        // Spawn task to handle incoming messages
        let manager_arc = Arc::new(manager.clone());
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            while let Some(msg_result) = receiver.next().await {
                match msg_result {
                    Ok(msg) => {
                        if let Err(e) = Self::handle_message(&manager_arc, &session_id_clone, msg).await {
                            error!("Error handling message: {}", e);
                        }
                    },
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                }
            }
            
            // Connection closed, clean up
            if let Err(e) = Self::cleanup_connection(&manager_arc, &session_id_clone).await {
                error!("Error cleaning up connection: {}", e);
            }
        });
        
        // Spawn task to handle outgoing messages
        let connections = self.connections.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = sender.send(msg).await {
                    error!("Error sending message: {}", e);
                    break;
                }
            }
        });
    }

    async fn handle_message(
        manager: &Arc<CollaborationManager>,
        session_id: &str,
        msg: Message,
    ) -> Result<()> {
        match msg {
            Message::Text(text) => {
                let json_msg: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;
                
                let msg_type = json_msg.get("type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Message type missing"))?;
                
                match msg_type {
                    "chat" => {
                        let workspace_id = json_msg.get("workspace_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| anyhow::anyhow!("Workspace ID missing"))?;
                        
                        let message = json_msg.get("message")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| anyhow::anyhow!("Message missing"))?;
                        
                        let message_type = json_msg.get("message_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("text");
                        
                        let message_type = match message_type {
                            "text" => MessageType::Text,
                            "incident" => MessageType::Incident,
                            "alert" => MessageType::Alert,
                            "artifact" => MessageType::Artifact,
                            "system" => MessageType::System,
                            _ => return Err(anyhow::anyhow!("Invalid message type: {}", message_type)),
                        };
                        
                        // Get username from session
                        let sessions = manager.sessions.read().await;
                        let session = sessions.get(session_id)
                            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
                        
                        let users = manager.users.read().await;
                        let user = users.get(&session.user_id)
                            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
                        
                        manager.send_chat_message(
                            workspace_id,
                            &session.user_id,
                            &user.username,
                            message.to_string(),
                            message_type,
                        ).await?;
                    },
                    "cursor_position" => {
                        let workspace_id = json_msg.get("workspace_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| anyhow::anyhow!("Workspace ID missing"))?;
                        
                        let cursor_data = json_msg.get("cursor_data")
                            .ok_or_else(|| anyhow::anyhow!("Cursor data missing"))?;
                        
                        // Get user ID from session
                        let sessions = manager.sessions.read().await;
                        let session = sessions.get(session_id)
                            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
                        
                        manager.update_cursor_position(
                            workspace_id,
                            &session.user_id,
                            cursor_data.clone(),
                        ).await?;
                    },
                    "typing_indicator" => {
                        let workspace_id = json_msg.get("workspace_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| anyhow::anyhow!("Workspace ID missing"))?;
                        
                        let is_typing = json_msg.get("is_typing")
                            .and_then(|v| v.as_bool())
                            .ok_or_else(|| anyhow::anyhow!("Typing indicator missing"))?;
                        
                        // Get user ID and username from session
                        let sessions = manager.sessions.read().await;
                        let session = sessions.get(session_id)
                            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
                        
                        let users = manager.users.read().await;
                        let user = users.get(&session.user_id)
                            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
                        
                        manager.send_typing_indicator(
                            workspace_id,
                            &session.user_id,
                            &user.username,
                            is_typing,
                        ).await?;
                    },
                    "ping" => {
                        // Update session ping
                        manager.update_session_ping(session_id).await?;
                    },
                    _ => {
                        return Err(anyhow::anyhow!("Unknown message type: {}", msg_type));
                    }
                }
            },
            Message::Binary(_) => {
                return Err(anyhow::anyhow!("Binary messages not supported"));
            },
            Message::Ping(data) => {
                // Respond with pong
                let connections = manager.websocket_server.connections.read().await;
                if let Some(conn) = connections.get(session_id) {
                    if let Err(e) = conn.sender.send(Message::Pong(data)) {
                        error!("Error sending pong: {}", e);
                    }
                }
            },
            Message::Pong(_) => {
                // Pong received, update ping time
                manager.update_session_ping(session_id).await?;
            },
            Message::Close(_) => {
                // Connection closed, will be handled by the receiver loop
            },
        }
        
        Ok(())
    }

    async fn cleanup_connection(
        manager: &Arc<CollaborationManager>,
        session_id: &str,
    ) -> Result<()> {
        // Clean up the session
        manager.cleanup_session(session_id).await?;
        
        // Remove from WebSocket connections
        {
            let mut connections = manager.websocket_server.connections.write().await;
            connections.remove(session_id);
        }
        
        info!("WebSocket connection {} cleaned up", session_id);
        Ok(())
    }
}
