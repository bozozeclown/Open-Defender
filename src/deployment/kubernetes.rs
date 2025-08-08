// src/deployment/kubernetes.rs
use anyhow::{Context, Result};
use k8s_openapi::api::{
    apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy},
    core::v1::{
        Container, ContainerPort, EnvVar, EnvVarSource, EnvVarValueFrom, ObjectFieldSelector,
        PodSpec, PodTemplateSpec, ResourceRequirements, Service, ServicePort, ServiceSpec,
        ServiceType,
    },
};
use kube::{
    api::{Api, ListParams, PostParams},
    Client, Config,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

use crate::config::CloudConfig;

pub struct KubernetesManager {
    client: Client,
    namespace: String,
}

impl KubernetesManager {
    pub async fn new(config: &CloudConfig) -> Result<Self> {
        let kube_config = Config::infer().await?;
        let client = Client::try_from(kube_config)?;
        
        Ok(Self {
            client,
            namespace: "default".to_string(),
        })
    }

    pub async fn deploy_exploit_detector(&self, cloud_config: &CloudConfig) -> Result<()> {
        info!("Deploying Exploit Detector to Kubernetes");

        // Create ConfigMap for configuration
        self.create_configmap(cloud_config).await?;

        // Create Secret for sensitive data
        self.create_secret(cloud_config).await?;

        // Create Service
        self.create_service().await?;

        // Create Deployment
        self.create_deployment(cloud_config).await?;

        // Create Ingress if enabled
        if cloud_config.networking.ingress.enabled {
            self.create_ingress(cloud_config).await?;
        }

        // Create ServiceMonitor for Prometheus if enabled
        self.create_servicemonitor().await?;

        info!("Exploit Detector deployed successfully to Kubernetes");
        Ok(())
    }

    async fn create_configmap(&self, cloud_config: &CloudConfig) -> Result<()> {
        let configmaps: Api<k8s_openapi::core::v1::ConfigMap> = Api::namespaced(self.client.clone(), &self.namespace);

        let mut data = HashMap::new();
        data.insert("config.yaml".to_string(), include_str!("../../../config.example.yaml").to_string());

        let configmap = k8s_openapi::core::v1::ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("exploit-detector-config".to_string()),
                namespace: Some(self.namespace.clone()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        configmaps.create(&PostParams::default(), &configmap).await?;
        info!("Created ConfigMap: exploit-detector-config");
        Ok(())
    }

    async fn create_secret(&self, cloud_config: &CloudConfig) -> Result<()> {
        let secrets: Api<k8s_openapi::core::v1::Secret> = Api::namespaced(self.client.clone(), &self.namespace);

        let mut data = HashMap::new();
        data.insert("database-password".to_string(), base64::encode("secure_password"));
        data.insert("api-key".to_string(), base64::encode("secure_api_key"));

        let secret = k8s_openapi::core::v1::Secret {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("exploit-detector-secrets".to_string()),
                namespace: Some(self.namespace.clone()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        secrets.create(&PostParams::default(), &secret).await?;
        info!("Created Secret: exploit-detector-secrets");
        Ok(())
    }

    async fn create_service(&self) -> Result<()> {
        let services: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);

        let service = Service {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("exploit-detector-service".to_string()),
                namespace: Some(self.namespace.clone()),
                labels: Some({
                    let mut labels = HashMap::new();
                    labels.insert("app".to_string(), "exploit-detector".to_string());
                    labels
                }),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some(ServiceType::ClusterIP),
                selector: Some({
                    let mut selector = HashMap::new();
                    selector.insert("app".to_string(), "exploit-detector".to_string());
                    selector
                }),
                ports: Some(vec![ServicePort {
                    port: 8080,
                    target_port: Some(8080.into()),
                    name: Some("http".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        services.create(&PostParams::default(), &service).await?;
        info!("Created Service: exploit-detector-service");
        Ok(())
    }

    async fn create_deployment(&self, cloud_config: &CloudConfig) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);

        let deployment = Deployment {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("exploit-detector".to_string()),
                namespace: Some(self.namespace.clone()),
                labels: Some({
                    let mut labels = HashMap::new();
                    labels.insert("app".to_string(), "exploit-detector".to_string());
                    labels
                }),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(cloud_config.deployment.replicas as i32),
                selector: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_labels: Some({
                        let mut labels = HashMap::new();
                        labels.insert("app".to_string(), "exploit-detector".to_string());
                        labels
                    }),
                    ..Default::default()
                }),
                template: Some(PodTemplateSpec {
                    metadata: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                        labels: Some({
                            let mut labels = HashMap::new();
                            labels.insert("app".to_string(), "exploit-detector".to_string());
                            labels
                        }),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            name: "exploit-detector".to_string(),
                            image: "exploit-detector:latest".to_string(),
                            ports: Some(vec![ContainerPort {
                                container_port: 8080,
                                name: Some("http".to_string()),
                                ..Default::default()
                            }]),
                            env: Some(vec![
                                EnvVar {
                                    name: "RUST_LOG".to_string(),
                                    value: Some("info".to_string()),
                                    ..Default::default()
                                },
                                EnvVar {
                                    name: "DATABASE_URL".to_string(),
                                    value_from: Some(EnvVarSource {
                                        secret_key_ref: Some(k8s_openapi::core::v1::SecretKeySelector {
                                            name: Some("exploit-detector-secrets".to_string()),
                                            key: "database-password".to_string(),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                },
                            ]),
                            resources: Some(ResourceRequirements {
                                limits: Some({
                                    let mut limits = HashMap::new();
                                    limits.insert("cpu".to_string(), Quantity("2".to_string()));
                                    limits.insert("memory".to_string(), Quantity("4Gi".to_string()));
                                    limits
                                }),
                                requests: Some({
                                    let mut requests = HashMap::new();
                                    requests.insert("cpu".to_string(), Quantity("500m".to_string()));
                                    requests.insert("memory".to_string(), Quantity("1Gi".to_string()));
                                    requests
                                }),
                            }),
                            liveness_probe: Some(k8s_openapi::core::v1::Probe {
                                http_get: Some(k8s_openapi::core::v1::HTTPGetAction {
                                    path: Some("/health".to_string()),
                                    port: 8080.into(),
                                    ..Default::default()
                                }),
                                initial_delay_seconds: Some(30),
                                period_seconds: Some(10),
                                ..Default::default()
                            }),
                            readiness_probe: Some(k8s_openapi::core::v1::Probe {
                                http_get: Some(k8s_openapi::core::v1::HTTPGetAction {
                                    path: Some("/ready".to_string()),
                                    port: 8080.into(),
                                    ..Default::default()
                                }),
                                initial_delay_seconds: Some(5),
                                period_seconds: Some(5),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        volumes: Some(vec![
                            k8s_openapi::core::v1::Volume {
                                name: "config".to_string(),
                                config_map: Some(k8s_openapi::core::v1::ConfigMapVolumeSource {
                                    name: Some("exploit-detector-config".to_string()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }),
                }),
                strategy: Some(DeploymentStrategy {
                    type_: Some("RollingUpdate".to_string()),
                    rolling_update: Some(k8s_openapi::api::apps::v1::RollingUpdateDeployment {
                        max_unavailable: Some(IntOrString::String("25%".to_string())),
                        max_surge: Some(IntOrString::String("25%".to_string())),
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        deployments.create(&PostParams::default(), &deployment).await?;
        info!("Created Deployment: exploit-detector");
        Ok(())
    }

    async fn create_ingress(&self, cloud_config: &CloudConfig) -> Result<()> {
        let ingresses: Api<k8s_openapi::networking::v1::Ingress> = Api::namespaced(self.client.clone(), &self.namespace);

        let ingress = k8s_openapi::networking::v1::Ingress {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("exploit-detector-ingress".to_string()),
                namespace: Some(self.namespace.clone()),
                annotations: Some({
                    let mut annotations = HashMap::new();
                    annotations.insert("kubernetes.io/ingress.class".to_string(), "nginx".to_string());
                    if cloud_config.networking.ingress.tls.enabled {
                        annotations.insert("cert-manager.io/cluster-issuer".to_string(), "letsencrypt-prod".to_string());
                    }
                    annotations
                }),
                ..Default::default()
            },
            spec: Some(k8s_openapi::networking::v1::IngressSpec {
                rules: Some(cloud_config.networking.ingress.rules.iter().map(|rule| {
                    k8s_openapi::networking::v1::IngressRule {
                        host: Some(rule.host.clone()),
                        http: Some(k8s_openapi::networking::v1::HTTPIngressRuleValue {
                            paths: rule.paths.iter().map(|path| {
                                k8s_openapi::networking::v1::HTTPIngressPath {
                                    path: path.path.clone(),
                                    path_type: Some("Prefix".to_string()),
                                    backend: Some(k8s_openapi::networking::v1::IngressBackend {
                                        service: Some(k8s_openapi::networking::v1::IngressServiceBackend {
                                            name: path.service_name.clone(),
                                            port: Some(k8s_openapi::networking::v1::ServiceBackendPort {
                                                number: path.service_port.into(),
                                                ..Default::default()
                                            }),
                                        }),
                                        ..Default::default()
                                    }),
                                )
                            }).collect(),
                        }),
                        ..Default::default()
                    }
                }).collect()),
                tls: if cloud_config.networking.ingress.tls.enabled {
                    Some(vec![k8s_openapi::networking::v1::IngressTLS {
                        hosts: Some(cloud_config.networking.ingress.rules.iter().map(|r| r.host.clone()).collect()),
                        secret_name: Some(cloud_config.networking.ingress.tls.secret_name.clone()),
                        ..Default::default()
                    }])
                } else {
                    None
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        ingresses.create(&PostParams::default(), &ingress).await?;
        info!("Created Ingress: exploit-detector-ingress");
        Ok(())
    }

    async fn create_servicemonitor(&self) -> Result<()> {
        let servicemonitors: Api<crate::deployment::ServiceMonitor> = Api::namespaced(self.client.clone(), &self.namespace);

        let servicemonitor = crate::deployment::ServiceMonitor {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("exploit-detector".to_string()),
                namespace: Some(self.namespace.clone()),
                labels: Some({
                    let mut labels = HashMap::new();
                    labels.insert("app".to_string(), "exploit-detector".to_string());
                    labels
                }),
                ..Default::default()
            },
            spec: crate::deployment::ServiceMonitorSpec {
                selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_labels: Some({
                        let mut labels = HashMap::new();
                        labels.insert("app".to_string(), "exploit-detector".to_string());
                        labels
                    }),
                    ..Default::default()
                },
                endpoints: vec![crate::deployment::Endpoint {
                    port: "http".to_string(),
                    interval: Some("30s".to_string()),
                    path: Some("/metrics".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            },
        };

        servicemonitors.create(&PostParams::default(), &servicemonitor).await?;
        info!("Created ServiceMonitor: exploit-detector");
        Ok(())
    }

    pub async fn scale_deployment(&self, replicas: i32) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        
        let mut deployment = deployments.get("exploit-detector").await?;
        if let Some(spec) = &mut deployment.spec {
            spec.replicas = Some(replicas);
        }
        
        deployments.replace("exploit-detector", &PostParams::default(), &deployment).await?;
        info!("Scaled deployment to {} replicas", replicas);
        Ok(())
    }

    pub async fn get_deployment_status(&self) -> Result<DeploymentStatus> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        let deployment = deployments.get("exploit-detector").await?;
        
        let status = deployment.status.unwrap_or_default();
        let replicas = status.replicas.unwrap_or(0);
        let available_replicas = status.available_replicas.unwrap_or(0);
        let updated_replicas = status.updated_replicas.unwrap_or(0);
        
        Ok(DeploymentStatus {
            name: "exploit-detector".to_string(),
            replicas,
            available_replicas,
            updated_replicas,
            ready: available_replicas == replicas && updated_replicas == replicas,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeploymentStatus {
    pub name: String,
    pub replicas: i32,
    pub available_replicas: i32,
    pub updated_replicas: i32,
    pub ready: bool,
}

// Custom types for Kubernetes resources
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceMonitor {
    pub metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    pub spec: ServiceMonitorSpec,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceMonitorSpec {
    pub selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub port: String,
    pub interval: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntOrString {
    // This would be implemented properly in a real scenario
}

impl From<i32> for IntOrString {
    fn from(value: i32) -> Self {
        IntOrString
    }
}

impl From<&str> for IntOrString {
    fn from(value: &str) -> Self {
        IntOrString
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Quantity(pub String);
