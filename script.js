document.addEventListener('DOMContentLoaded', function() {
    // Session storage key
    const SESSION_KEY = 'securityMonitoringSetup';
    
    // Initialize form data
    let formData = {
        step1: {
            prerequisitesCheck: false
        },
        step2: {
            environmentType: 'development',
            appName: 'security-monitoring',
            appVersion: '0.1.0',
            deploymentMethod: 'docker',
            graphqlPort: 8000,
            websocketPort: 8001,
            metricsPort: 9090
        },
        step3: {
            pgDbName: 'security_monitoring',
            pgDbUser: 'security_user',
            pgDbHost: 'localhost'
        },
        step4: {
            useExternalDb: true,
            dbHost: 'localhost',
            dbPort: 5432,
            dbName: 'security_monitoring',
            dbUser: 'security_user',
            dbSslMode: 'prefer',
            dbMaxConnections: 10,
            dbMinConnections: 5,
            enableReadReplicas: false,
            readReplicaHosts: ''
        },
        step5: {
            eventBufferSize: 10000,
            portScanThreshold: 50,
            dataExfiltrationThreshold: 10485760,
            systemMetricsInterval: 60,
            suspiciousProcesses: 'powershell.exe,cmd.exe,wscript.exe,cscript.exe,rundll32.exe,regsvr32.exe',
            jwtExpiryHours: 24,
            corsOrigins: 'http://localhost:3000',
            enableTls: true,
            tlsCertPath: '/etc/ssl/certs/server.crt',
            tlsKeyPath: '/etc/ssl/private/server.key',
            logLevel: 'info',
            jaegerEndpoint: 'localhost:6831',
            enableTracing: true,
            enableMetrics: true
        },
        step6: {
            generateDockerCompose: true,
            generateKubernetes: false,
            generateHelm: false,
            initDatabase: true
        }
    };
    
    // Load saved data from session storage
    function loadFormData() {
        const savedData = sessionStorage.getItem(SESSION_KEY);
        if (savedData) {
            try {
                const parsedData = JSON.parse(savedData);
                formData = { ...formData, ...parsedData };
            } catch (e) {
                console.error('Error parsing saved form data:', e);
            }
        }
        populateForm();
    }
    
    // Save form data to session storage
    function saveFormData() {
        try {
            sessionStorage.setItem(SESSION_KEY, JSON.stringify(formData));
        } catch (e) {
            console.error('Error saving form data:', e);
        }
    }
    
    // Populate form fields with saved data
    function populateForm() {
        // Step 1
        document.getElementById('prerequisitesCheck').checked = formData.step1.prerequisitesCheck;
        
        // Step 2
        document.getElementById('environmentType').value = formData.step2.environmentType;
        document.getElementById('appName').value = formData.step2.appName;
        document.getElementById('appVersion').value = formData.step2.appVersion;
        document.getElementById('graphqlPort').value = formData.step2.graphqlPort;
        document.getElementById('websocketPort').value = formData.step2.websocketPort;
        document.getElementById('metricsPort').value = formData.step2.metricsPort;
        
        // Set deployment method
        document.querySelectorAll('.deployment-method').forEach(method => {
            method.classList.remove('selected');
            if (method.dataset.method === formData.step2.deploymentMethod) {
                method.classList.add('selected');
            }
        });
        
        // Step 3
        document.getElementById('pgDbName').value = formData.step3.pgDbName;
        document.getElementById('pgDbUser').value = formData.step3.pgDbUser;
        document.getElementById('pgDbHost').value = formData.step3.pgDbHost;
        
        // Step 4
        document.getElementById('useExternalDb').checked = formData.step4.useExternalDb;
        document.getElementById('dbHost').value = formData.step4.dbHost;
        document.getElementById('dbPort').value = formData.step4.dbPort;
        document.getElementById('dbName').value = formData.step4.dbName;
        document.getElementById('dbUser').value = formData.step4.dbUser;
        document.getElementById('dbSslMode').value = formData.step4.dbSslMode;
        document.getElementById('dbMaxConnections').value = formData.step4.dbMaxConnections;
        document.getElementById('dbMinConnections').value = formData.step4.dbMinConnections;
        document.getElementById('enableReadReplicas').checked = formData.step4.enableReadReplicas;
        document.getElementById('readReplicaHosts').value = formData.step4.readReplicaHosts;
        
        // Toggle external/embedded config based on useExternalDb
        if (formData.step4.useExternalDb) {
            document.getElementById('externalDbConfig').style.display = 'block';
            document.getElementById('embeddedDbConfig').style.display = 'none';
        } else {
            document.getElementById('externalDbConfig').style.display = 'none';
            document.getElementById('embeddedDbConfig').style.display = 'block';
        }
        
        // Toggle read replicas config
        document.getElementById('readReplicasConfig').style.display = formData.step4.enableReadReplicas ? 'block' : 'none';
        
        // Step 5
        document.getElementById('eventBufferSize').value = formData.step5.eventBufferSize;
        document.getElementById('portScanThreshold').value = formData.step5.portScanThreshold;
        document.getElementById('dataExfiltrationThreshold').value = formData.step5.dataExfiltrationThreshold;
        document.getElementById('systemMetricsInterval').value = formData.step5.systemMetricsInterval;
        document.getElementById('suspiciousProcesses').value = formData.step5.suspiciousProcesses;
        document.getElementById('jwtExpiryHours').value = formData.step5.jwtExpiryHours;
        document.getElementById('corsOrigins').value = formData.step5.corsOrigins;
        document.getElementById('enableTls').checked = formData.step5.enableTls;
        document.getElementById('tlsCertPath').value = formData.step5.tlsCertPath;
        document.getElementById('tlsKeyPath').value = formData.step5.tlsKeyPath;
        document.getElementById('logLevel').value = formData.step5.logLevel;
        document.getElementById('jaegerEndpoint').value = formData.step5.jaegerEndpoint;
        document.getElementById('enableTracing').checked = formData.step5.enableTracing;
        document.getElementById('enableMetrics').checked = formData.step5.enableMetrics;
        
        // Toggle TLS config
        document.getElementById('tlsConfig').style.display = formData.step5.enableTls ? 'block' : 'none';
        
        // Step 6
        document.getElementById('generateDockerCompose').checked = formData.step6.generateDockerCompose;
        document.getElementById('generateKubernetes').checked = formData.step6.generateKubernetes;
        document.getElementById('generateHelm').checked = formData.step6.generateHelm;
        document.getElementById('initDatabase').checked = formData.step6.initDatabase;
    }
    
    // Setup event listeners for form fields
    function setupFormListeners() {
        // Step 1
        document.getElementById('prerequisitesCheck').addEventListener('change', function() {
            formData.step1.prerequisitesCheck = this.checked;
            saveFormData();
        });
        
        // Step 2
        document.getElementById('environmentType').addEventListener('change', function() {
            formData.step2.environmentType = this.value;
            saveFormData();
        });
        
        document.getElementById('appName').addEventListener('input', function() {
            formData.step2.appName = this.value;
            saveFormData();
        });
        
        document.getElementById('appVersion').addEventListener('input', function() {
            formData.step2.appVersion = this.value;
            saveFormData();
        });
        
        document.getElementById('graphqlPort').addEventListener('input', function() {
            formData.step2.graphqlPort = parseInt(this.value) || 8000;
            saveFormData();
        });
        
        document.getElementById('websocketPort').addEventListener('input', function() {
            formData.step2.websocketPort = parseInt(this.value) || 8001;
            saveFormData();
        });
        
        document.getElementById('metricsPort').addEventListener('input', function() {
            formData.step2.metricsPort = parseInt(this.value) || 9090;
            saveFormData();
        });
        
        // Deployment method selection
        document.querySelectorAll('.deployment-method').forEach(method => {
            method.addEventListener('click', function() {
                document.querySelectorAll('.deployment-method').forEach(m => m.classList.remove('selected'));
                this.classList.add('selected');
                formData.step2.deploymentMethod = this.dataset.method;
                saveFormData();
            });
        });
        
        // Step 3
        document.getElementById('pgDbName').addEventListener('input', function() {
            formData.step3.pgDbName = this.value;
            saveFormData();
        });
        
        document.getElementById('pgDbUser').addEventListener('input', function() {
            formData.step3.pgDbUser = this.value;
            saveFormData();
        });
        
        document.getElementById('pgDbHost').addEventListener('input', function() {
            formData.step3.pgDbHost = this.value;
            saveFormData();
        });
        
        // Step 4
        document.getElementById('useExternalDb').addEventListener('change', function() {
            formData.step4.useExternalDb = this.checked;
            saveFormData();
            
            if (this.checked) {
                document.getElementById('externalDbConfig').style.display = 'block';
                document.getElementById('embeddedDbConfig').style.display = 'none';
            } else {
                document.getElementById('externalDbConfig').style.display = 'none';
                document.getElementById('embeddedDbConfig').style.display = 'block';
            }
        });
        
        document.getElementById('dbHost').addEventListener('input', function() {
            formData.step4.dbHost = this.value;
            saveFormData();
        });
        
        document.getElementById('dbPort').addEventListener('input', function() {
            formData.step4.dbPort = parseInt(this.value) || 5432;
            saveFormData();
        });
        
        document.getElementById('dbName').addEventListener('input', function() {
            formData.step4.dbName = this.value;
            saveFormData();
        });
        
        document.getElementById('dbUser').addEventListener('input', function() {
            formData.step4.dbUser = this.value;
            saveFormData();
        });
        
        document.getElementById('dbSslMode').addEventListener('change', function() {
            formData.step4.dbSslMode = this.value;
            saveFormData();
        });
        
        document.getElementById('dbMaxConnections').addEventListener('input', function() {
            formData.step4.dbMaxConnections = parseInt(this.value) || 10;
            saveFormData();
        });
        
        document.getElementById('dbMinConnections').addEventListener('input', function() {
            formData.step4.dbMinConnections = parseInt(this.value) || 5;
            saveFormData();
        });
        
        document.getElementById('enableReadReplicas').addEventListener('change', function() {
            formData.step4.enableReadReplicas = this.checked;
            saveFormData();
            
            document.getElementById('readReplicasConfig').style.display = this.checked ? 'block' : 'none';
        });
        
        document.getElementById('readReplicaHosts').addEventListener('input', function() {
            formData.step4.readReplicaHosts = this.value;
            saveFormData();
        });
        
        // Step 5
        document.getElementById('eventBufferSize').addEventListener('input', function() {
            formData.step5.eventBufferSize = parseInt(this.value) || 10000;
            saveFormData();
        });
        
        document.getElementById('portScanThreshold').addEventListener('input', function() {
            formData.step5.portScanThreshold = parseInt(this.value) || 50;
            saveFormData();
        });
        
        document.getElementById('dataExfiltrationThreshold').addEventListener('input', function() {
            formData.step5.dataExfiltrationThreshold = parseInt(this.value) || 10485760;
            saveFormData();
        });
        
        document.getElementById('systemMetricsInterval').addEventListener('input', function() {
            formData.step5.systemMetricsInterval = parseInt(this.value) || 60;
            saveFormData();
        });
        
        document.getElementById('suspiciousProcesses').addEventListener('input', function() {
            formData.step5.suspiciousProcesses = this.value;
            saveFormData();
        });
        
        document.getElementById('jwtExpiryHours').addEventListener('input', function() {
            formData.step5.jwtExpiryHours = parseInt(this.value) || 24;
            saveFormData();
        });
        
        document.getElementById('corsOrigins').addEventListener('input', function() {
            formData.step5.corsOrigins = this.value;
            saveFormData();
        });
        
        document.getElementById('enableTls').addEventListener('change', function() {
            formData.step5.enableTls = this.checked;
            saveFormData();
            
            document.getElementById('tlsConfig').style.display = this.checked ? 'block' : 'none';
        });
        
        document.getElementById('tlsCertPath').addEventListener('input', function() {
            formData.step5.tlsCertPath = this.value;
            saveFormData();
        });
        
        document.getElementById('tlsKeyPath').addEventListener('input', function() {
            formData.step5.tlsKeyPath = this.value;
            saveFormData();
        });
        
        document.getElementById('logLevel').addEventListener('change', function() {
            formData.step5.logLevel = this.value;
            saveFormData();
        });
        
        document.getElementById('jaegerEndpoint').addEventListener('input', function() {
            formData.step5.jaegerEndpoint = this.value;
            saveFormData();
        });
        
        document.getElementById('enableTracing').addEventListener('change', function() {
            formData.step5.enableTracing = this.checked;
            saveFormData();
        });
        
        document.getElementById('enableMetrics').addEventListener('change', function() {
            formData.step5.enableMetrics = this.checked;
            saveFormData();
        });
        
        // Step 6
        document.getElementById('generateDockerCompose').addEventListener('change', function() {
            formData.step6.generateDockerCompose = this.checked;
            saveFormData();
        });
        
        document.getElementById('generateKubernetes').addEventListener('change', function() {
            formData.step6.generateKubernetes = this.checked;
            saveFormData();
        });
        
        document.getElementById('generateHelm').addEventListener('change', function() {
            formData.step6.generateHelm = this.checked;
            saveFormData();
        });
        
        document.getElementById('initDatabase').addEventListener('change', function() {
            formData.step6.initDatabase = this.checked;
            saveFormData();
        });
    }
    
    // Add clear session button
    function addClearSessionButton() {
        const clearButton = document.createElement('button');
        clearButton.className = 'btn btn-outline-danger btn-sm position-absolute top-0 end-0 m-3';
        clearButton.innerHTML = '<i class="bi bi-trash"></i> Clear Session';
        clearButton.addEventListener('click', function() {
            if (confirm('Are you sure you want to clear all saved form data?')) {
                sessionStorage.removeItem(SESSION_KEY);
                location.reload();
            }
        });
        document.querySelector('.setup-container').appendChild(clearButton);
    }
    
    // Initialize
    loadFormData();
    setupFormListeners();
    addClearSessionButton();
    
    // Step navigation
    const steps = document.querySelectorAll('.step');
    const stepContents = document.querySelectorAll('.step-content');
    const progressBar = document.querySelector('.progress-bar');
    
    // Step 1: Prerequisites
    const prerequisitesCheck = document.getElementById('prerequisitesCheck');
    const nextStep1 = document.getElementById('nextStep1');
    
    prerequisitesCheck.addEventListener('change', function() {
        nextStep1.disabled = !this.checked;
    });
    
    nextStep1.addEventListener('click', function() {
        goToStep(2);
    });
    
    // Step 2: Environment
    const prevStep2 = document.getElementById('prevStep2');
    const nextStep2 = document.getElementById('nextStep2');
    let selectedDeploymentMethod = formData.step2.deploymentMethod;
    
    prevStep2.addEventListener('click', function() {
        goToStep(1);
    });
    
    nextStep2.addEventListener('click', function() {
        goToStep(3);
    });
    
    // Step 3: PostgreSQL Setup
    const prevStep3 = document.getElementById('prevStep3');
    const nextStep3 = document.getElementById('nextStep3');
    const osTabs = document.querySelectorAll('.os-tab');
    const downloadSections = document.querySelectorAll('.download-section');
    const testPgConnection = document.getElementById('testPgConnection');
    const pgConnectionResult = document.getElementById('pgConnectionResult');
    
    prevStep3.addEventListener('click', function() {
        goToStep(2);
    });
    
    nextStep3.addEventListener('click', function() {
        // Transfer PostgreSQL setup data to database configuration step
        document.getElementById('dbHost').value = document.getElementById('pgDbHost').value;
        document.getElementById('dbName').value = document.getElementById('pgDbName').value;
        document.getElementById('dbUser').value = document.getElementById('pgDbUser').value;
        
        // Update formData for step4
        formData.step4.dbHost = document.getElementById('pgDbHost').value;
        formData.step4.dbName = document.getElementById('pgDbName').value;
        formData.step4.dbUser = document.getElementById('pgDbUser').value;
        saveFormData();
        
        goToStep(4);
    });
    
    // OS tab switching
    osTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            osTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            
            const os = this.dataset.os;
            downloadSections.forEach(section => {
                section.style.display = 'none';
            });
            
            document.getElementById(`${os}Download`).style.display = 'block';
        });
    });
    
    // Copy button functionality
    document.querySelectorAll('.copy-button').forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalHTML = this.innerHTML;
                this.innerHTML = '<i class="bi bi-check"></i>';
                setTimeout(() => {
                    this.innerHTML = originalHTML;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy text: ', err);
            });
        });
    });
    
    // Download buttons
    document.getElementById('downloadWindowsInstaller').addEventListener('click', function() {
        // Create a temporary link to download the PostgreSQL installer
        const link = document.createElement('a');
        link.href = 'https://get.enterprisedb.com/postgresql/postgresql-15.3-1-windows-x64.exe';
        link.download = 'postgresql-15.3-1-windows-x64.exe';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });
    
    // Test PostgreSQL connection
    testPgConnection.addEventListener('click', function() {
        const dbName = document.getElementById('pgDbName').value;
        const dbUser = document.getElementById('pgDbUser').value;
        const dbPassword = document.getElementById('pgDbPassword').value;
        const dbHost = document.getElementById('pgDbHost').value;
        
        if (!dbName || !dbUser || !dbPassword || !dbHost) {
            pgConnectionResult.className = 'alert alert-warning';
            pgConnectionResult.textContent = 'Please fill in all database connection fields';
            pgConnectionResult.classList.remove('d-none');
            return;
        }
        
        // Simulate database connection test
        this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Testing...';
        this.disabled = true;
        
        setTimeout(() => {
            this.innerHTML = 'Test Connection <i class="bi bi-plug"></i>';
            this.disabled = false;
            
            // Show success message
            pgConnectionResult.className = 'alert alert-success';
            pgConnectionResult.innerHTML = '<i class="bi bi-check-circle-fill me-2"></i> Database connection successful!';
            pgConnectionResult.classList.remove('d-none');
        }, 1500);
    });
    
    // Step 4: Database Configuration
    const prevStep4 = document.getElementById('prevStep4');
    const nextStep4 = document.getElementById('nextStep4');
    const testDbConnection = document.getElementById('testDbConnection');
    const useExternalDb = document.getElementById('useExternalDb');
    const externalDbConfig = document.getElementById('externalDbConfig');
    const embeddedDbConfig = document.getElementById('embeddedDbConfig');
    const enableReadReplicas = document.getElementById('enableReadReplicas');
    const readReplicasConfig = document.getElementById('readReplicasConfig');
    
    prevStep4.addEventListener('click', function() {
        goToStep(3);
    });
    
    nextStep4.addEventListener('click', function() {
        goToStep(5);
    });
    
    testDbConnection.addEventListener('click', function() {
        // Simulate database connection test
        this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Testing...';
        this.disabled = true;
        
        setTimeout(() => {
            this.innerHTML = 'Test Connection <i class="bi bi-plug"></i>';
            this.disabled = false;
            
            // Show success message
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-success mt-2';
            alertDiv.innerHTML = '<i class="bi bi-check-circle-fill me-2"></i> Database connection successful!';
            this.parentNode.appendChild(alertDiv);
            
            // Remove alert after 3 seconds
            setTimeout(() => {
                alertDiv.remove();
            }, 3000);
        }, 1500);
    });
    
    // Step 5: Application Configuration
    const prevStep5 = document.getElementById('prevStep5');
    const nextStep5 = document.getElementById('nextStep5');
    const previewConfig = document.getElementById('previewConfig');
    const configPreview = document.getElementById('configPreview');
    const generateJwtSecret = document.getElementById('generateJwtSecret');
    const jwtSecret = document.getElementById('jwtSecret');
    const enableTls = document.getElementById('enableTls');
    const tlsConfig = document.getElementById('tlsConfig');
    
    prevStep5.addEventListener('click', function() {
        goToStep(4);
    });
    
    nextStep5.addEventListener('click', function() {
        updateDeploymentSummary();
        goToStep(6);
    });
    
    previewConfig.addEventListener('click', function() {
        // Generate configuration preview
        const config = generateConfigPreview();
        configPreview.textContent = config;
        configPreview.classList.toggle('d-none');
    });
    
    generateJwtSecret.addEventListener('click', function() {
        // Generate a random JWT secret
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let secret = '';
        for (let i = 0; i < 64; i++) {
            secret += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        jwtSecret.value = secret;
    });
    
    // Step 6: Deployment
    const prevStep6 = document.getElementById('prevStep6');
    const generateDeployment = document.getElementById('generateDeployment');
    const deploymentOutput = document.getElementById('deploymentOutput');
    const finishSetup = document.getElementById('finishSetup');
    
    prevStep6.addEventListener('click', function() {
        goToStep(5);
    });
    
    generateDeployment.addEventListener('click', function() {
        // Simulate deployment file generation
        this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Generating...';
        this.disabled = true;
        
        setTimeout(() => {
            this.innerHTML = '<i class="bi bi-download"></i> Generate Deployment Files';
            this.disabled = false;
            deploymentOutput.classList.remove('d-none');
            
            // Generate deployment instructions based on selected method
            const instructions = generateDeploymentInstructions();
            document.getElementById('deploymentInstructions').innerHTML = instructions;
        }, 2000);
    });
    
    // Download buttons
    document.getElementById('downloadConfig').addEventListener('click', function() {
        downloadFile('config.yaml', generateConfigFile());
    });
    
    document.getElementById('downloadDockerCompose').addEventListener('click', function() {
        downloadFile('docker-compose.yml', generateDockerComposeFile());
    });
    
    document.getElementById('downloadKubernetes').addEventListener('click', function() {
        // In a real implementation, this would generate a ZIP file with all Kubernetes manifests
        alert('Kubernetes manifests would be downloaded as a ZIP file');
    });
    
    document.getElementById('downloadHelm').addEventListener('click', function() {
        // In a real implementation, this would generate a Helm chart package
        alert('Helm chart would be downloaded as a TGZ file');
    });
    
    document.getElementById('downloadAll').addEventListener('click', function() {
        // In a real implementation, this would generate a ZIP with all files
        alert('All files would be downloaded as a ZIP file');
    });
    
    finishSetup.addEventListener('click', function() {
        if (confirm('Setup completed successfully! Your session data will be cleared. Do you want to proceed?')) {
            sessionStorage.removeItem(SESSION_KEY);
            alert('Setup completed successfully! You can now deploy your Security Monitoring System.');
        }
    });
    
    // Helper functions
    function goToStep(stepNumber) {
        // Update step indicators
        steps.forEach((step, index) => {
            if (index < stepNumber - 1) {
                step.classList.add('completed');
                step.classList.remove('active');
            } else if (index === stepNumber - 1) {
                step.classList.add('active');
                step.classList.remove('completed');
            } else {
                step.classList.remove('active', 'completed');
            }
        });
        
        // Update step content
        stepContents.forEach((content, index) => {
            if (index === stepNumber - 1) {
                content.classList.add('active');
            } else {
                content.classList.remove('active');
            }
        });
        
        // Update progress bar
        const progress = (stepNumber / steps.length) * 100;
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);
    }
    
    function generateConfigPreview() {
        const environment = formData.step2.environmentType;
        const appName = formData.step2.appName;
        const appVersion = formData.step2.appVersion;
        const dbHost = formData.step4.dbHost;
        const dbPort = formData.step4.dbPort;
        const dbName = formData.step4.dbName;
        const dbUser = formData.step4.dbUser;
        const dbSslMode = formData.step4.dbSslMode;
        const dbMaxConnections = formData.step4.dbMaxConnections;
        const dbMinConnections = formData.step4.dbMinConnections;
        const eventBufferSize = formData.step5.eventBufferSize;
        const portScanThreshold = formData.step5.portScanThreshold;
        const dataExfiltrationThreshold = formData.step5.dataExfiltrationThreshold;
        const systemMetricsInterval = formData.step5.systemMetricsInterval;
        const suspiciousProcesses = formData.step5.suspiciousProcesses;
        const jwtExpiryHours = formData.step5.jwtExpiryHours;
        const corsOrigins = formData.step5.corsOrigins;
        const logLevel = formData.step5.logLevel;
        const jaegerEndpoint = formData.step5.jaegerEndpoint;
        const enableTracing = formData.step5.enableTracing;
        const enableMetrics = formData.step5.enableMetrics;
        const enableTls = formData.step5.enableTls;
        
        let config = `# Configuration for ${appName} v${appVersion}
app:
  name: "${appName}"
  version: "${appVersion}"
  environment: "${environment}"
  
database:
  url: "postgres://${dbUser}:***@${dbHost}:${dbPort}/${dbName}"
  max_connections: ${dbMaxConnections}
  min_connections: ${dbMinConnections}
  ssl_mode: "${dbSslMode}"
  
analytics:
  event_buffer_size: ${eventBufferSize}
  port_scan_threshold: ${portScanThreshold}
  data_exfiltration_threshold: ${dataExfiltrationThreshold}
  suspicious_processes: "${suspiciousProcesses}"
  system_metrics_interval: ${systemMetricsInterval}
  
api:
  cors_origins: "${corsOrigins}"
  jwt_expiry_hours: ${jwtExpiryHours}
  
observability:
  log_level: "${logLevel}"
  jaeger_endpoint: "${jaegerEndpoint}"
  enable_tracing: ${enableTracing}
  enable_metrics: ${enableMetrics}
  
security:
  tls:
    enabled: ${enableTls}`;
                
        if (enableTls) {
            const tlsCertPath = formData.step5.tlsCertPath;
            const tlsKeyPath = formData.step5.tlsKeyPath;
            config += `
    cert_path: "${tlsCertPath}"
    key_path: "${tlsKeyPath}"`;
        }
        
        if (formData.step4.enableReadReplicas) {
            const readReplicaHosts = formData.step4.readReplicaHosts;
            config += `
  read_replicas: "${readReplicaHosts}"`;
        }
        
        return config;
    }
    
    function generateConfigFile() {
        // Generate the actual configuration file content
        return generateConfigPreview();
    }
    
    function generateDockerComposeFile() {
        const appName = formData.step2.appName;
        const graphqlPort = formData.step2.graphqlPort;
        const websocketPort = formData.step2.websocketPort;
        const metricsPort = formData.step2.metricsPort;
        const dbHost = formData.step4.dbHost;
        const dbPort = formData.step4.dbPort;
        const dbName = formData.step4.dbName;
        const dbUser = formData.step4.dbUser;
        const dbPassword = document.getElementById('dbPassword').value;
        
        let compose = `version: '3.8'

services:
  ${appName}:
    image: security-monitoring:latest
    container_name: ${appName}
    ports:
      - "${graphqlPort}:8000"
      - "${websocketPort}:8001"
      - "${metricsPort}:9090"
    environment:
      - DATABASE_URL=postgres://${dbUser}:${dbPassword}@${dbHost}:${dbPort}/${dbName}
      - RUST_LOG=info
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    networks:
      - security-network
      
  postgres:
    image: postgres:14
    container_name: ${appName}-postgres
    environment:
      - POSTGRES_DB=${dbName}
      - POSTGRES_USER=${dbUser}
      - POSTGRES_PASSWORD=${dbPassword}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "${dbPort}:5432"
    restart: unless-stopped
    networks:
      - security-network
      
  redis:
    image: redis:7-alpine
    container_name: ${appName}-redis
    ports:
      - "6379:6379"
    restart: unless-stopped
    networks:
      - security-network
      
  prometheus:
    image: prom/prometheus:latest
    container_name: ${appName}-prometheus
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
    restart: unless-stopped
    networks:
      - security-network
      
  grafana:
    image: grafana/grafana:latest
    container_name: ${appName}-grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    restart: unless-stopped
    networks:
      - security-network

volumes:
  postgres-data:
  grafana-data:

networks:
  security-network:
    driver: bridge`;
        
        return compose;
    }
    
    function updateDeploymentSummary() {
        const environment = formData.step2.environmentType;
        const deploymentMethod = selectedDeploymentMethod;
        const useExternal = formData.step4.useExternalDb;
        const dbHost = formData.step4.dbHost;
        const dbPort = formData.step4.dbPort;
        const dbName = formData.step4.dbName;
        const graphqlPort = formData.step2.graphqlPort;
        const websocketPort = formData.step2.websocketPort;
        const metricsPort = formData.step2.metricsPort;
        
        document.getElementById('summaryEnvironment').textContent = environment.charAt(0).toUpperCase() + environment.slice(1);
        document.getElementById('summaryDeploymentMethod').textContent = deploymentMethod.charAt(0).toUpperCase() + deploymentMethod.slice(1);
        
        if (useExternal) {
            document.getElementById('summaryDatabase').textContent = `External (${dbHost}:${dbPort}/${dbName})`;
        } else {
            document.getElementById('summaryDatabase').textContent = 'Embedded (Docker)';
        }
        
        document.getElementById('summaryGraphqlPort').textContent = graphqlPort;
        document.getElementById('summaryWebsocketPort').textContent = websocketPort;
        document.getElementById('summaryMetricsPort').textContent = metricsPort;
    }
    
    function generateDeploymentInstructions() {
        const deploymentMethod = selectedDeploymentMethod;
        let instructions = '';
        
        if (deploymentMethod === 'docker') {
            instructions = `
                <h6>Docker Compose Deployment Instructions</h6>
                <ol>
                    <li>Extract the downloaded files to a directory on your server.</li>
                    <li>Navigate to the directory containing the docker-compose.yml file.</li>
                    <li>Run the following command to start the services:
                        <pre class="mt-2 mb-2 p-2 bg-light">docker-compose up -d</pre>
                    </li>
                    <li>Check the status of the services:
                        <pre class="mt-2 mb-2 p-2 bg-light">docker-compose ps</pre>
                    </li>
                    <li>Access the application:
                        <ul>
                            <li>GraphQL API: http://localhost:${formData.step2.graphqlPort}</li>
                            <li>WebSocket: ws://localhost:${formData.step2.websocketPort}</li>
                            <li>Grafana Dashboard: http://localhost:3000 (admin/admin)</li>
                        </ul>
                    </li>
                </ol>
                <p>To stop the services, run:</p>
                <pre class="mt-2 mb-2 p-2 bg-light">docker-compose down</pre>
            `;
        } else if (deploymentMethod === 'kubernetes') {
            instructions = `
                <h6>Kubernetes Deployment Instructions</h6>
                <ol>
                    <li>Extract the downloaded Kubernetes manifest files.</li>
                    <li>Ensure kubectl is configured to connect to your cluster.</li>
                    <li>Create the namespace:
                        <pre class="mt-2 mb-2 p-2 bg-light">kubectl apply -f namespace.yaml</pre>
                    </li>
                    <li>Apply the configuration:
                        <pre class="mt-2 mb-2 p-2 bg-light">kubectl apply -f .</pre>
                    </li>
                    <li>Check the status of the pods:
                        <pre class="mt-2 mb-2 p-2 bg-light">kubectl get pods -n security-monitoring</pre>
                    </li>
                    <li>Access the application:
                        <ul>
                            <li>Get the service IP:
                                <pre class="mt-2 mb-2 p-2 bg-light">kubectl get svc -n security-monitoring</pre>
                            </li>
                            <li>GraphQL API: http://&lt;service-ip&gt;:${formData.step2.graphqlPort}</li>
                            <li>WebSocket: ws://&lt;service-ip&gt;:${formData.step2.websocketPort}</li>
                        </ul>
                    </li>
                </ol>
            `;
        } else if (deploymentMethod === 'helm') {
            instructions = `
                <h6>Helm Deployment Instructions</h6>
                <ol>
                    <li>Extract the downloaded Helm chart.</li>
                    <li>Ensure Helm is installed and configured to connect to your cluster.</li>
                    <li>Install the chart:
                        <pre class="mt-2 mb-2 p-2 bg-light">helm install security-monitoring ./security-monitoring</pre>
                    </li>
                    <li>Check the status of the release:
                        <pre class="mt-2 mb-2 p-2 bg-light">helm status security-monitoring</pre>
                    </li>
                    <li>Check the status of the pods:
                        <pre class="mt-2 mb-2 p-2 bg-light">kubectl get pods -n security-monitoring</pre>
                    </li>
                    <li>Access the application:
                        <ul>
                            <li>Get the service IP:
                                <pre class="mt-2 mb-2 p-2 bg-light">kubectl get svc -n security-monitoring</pre>
                            </li>
                            <li>GraphQL API: http://&lt;service-ip&gt;:${formData.step2.graphqlPort}</li>
                            <li>WebSocket: ws://&lt;service-ip&gt;:${formData.step2.websocketPort}</li>
                        </ul>
                    </li>
                </ol>
                <p>To uninstall the release, run:</p>
                <pre class="mt-2 mb-2 p-2 bg-light">helm uninstall security-monitoring</pre>
            `;
        }
        
        return instructions;
    }
    
    function downloadFile(filename, content) {
        const element = document.createElement('a');
        const file = new Blob([content], {type: 'text/yaml'});
        element.href = URL.createObjectURL(file);
        element.download = filename;
        element.click();
    }
    
    // Enhanced Windows PostgreSQL Instructions
    function showWindowsPostgresInstructions() {
        const windowsDownload = document.getElementById('windowsDownload');
        
        // Use string concatenation instead of template strings to avoid octal escape issues
        const psqlCommands = `cd C:\\Program Files\\PostgreSQL\\15\\bin
psql -U postgres -c "CREATE DATABASE security_monitoring;"
psql -U postgres -c "CREATE USER security_user WITH PASSWORD 'your_secure_password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE security_monitoring TO security_user;"
psql -U postgres -c "GRANT ALL ON SCHEMA public TO security_user;"
psql -U postgres -c "GRANT ALL ON ALL TABLES IN SCHEMA public TO security_user;"
psql -U postgres -c "GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO security_user;"`;
        
        // Replace the existing content with more detailed instructions
        windowsDownload.innerHTML = 
            '<h6>Windows PostgreSQL Installation Guide</h6>' +
            
            '<div class="alert alert-info">' +
            '<i class="bi bi-info-circle-fill me-2"></i>' +
            'Follow these detailed steps to install PostgreSQL on Windows and create the required database.' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Step 1: Download PostgreSQL Installer</h5>' +
            '<div class="download-option selected" data-option="installer">' +
            '<div class="download-option-icon">' +
            '<i class="bi bi-file-earmark-exe"></i>' +
            '</div>' +
            '<h6>Download Official Installer</h6>' +
            '<p class="small text-muted">Download the PostgreSQL installer from EnterpriseDB</p>' +
            '<button class="btn btn-sm btn-primary" id="downloadWindowsInstaller">' +
            '<i class="bi bi-download"></i> Download Installer' +
            '</button>' +
            '</div>' +
            
            '<div class="command-block">' +
            '<button class="copy-button" data-copy="curl -O https://get.enterprisedb.com/postgresql/postgresql-15.3-1-windows-x64.exe">' +
            '<i class="bi bi-clipboard"></i>' +
            '</button>' +
            'curl -O https://get.enterprisedb.com/postgresql/postgresql-15.3-1-windows-x64.exe' +
            '</div>' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Step 2: Run the Installer</h5>' +
            '<ol>' +
            '<li>Locate the downloaded file: <code>postgresql-15.3-1-windows-x64.exe</code></li>' +
            '<li>Right-click the file and select "Run as administrator"</li>' +
            '<li>When prompted by Windows Security, click "Yes" to allow the app to make changes</li>' +
            '</ol>' +
            
            '<div class="alert alert-warning">' +
            '<i class="bi bi-exclamation-triangle-fill me-2"></i>' +
            '<strong>Important:</strong> Running as administrator ensures proper installation of Windows services.' +
            '</div>' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Step 3: Installation Wizard</h5>' +
            '<p>Follow these steps in the installation wizard:</p>' +
            
            '<div class="db-creation-steps">' +
            '<div class="db-creation-step">' +
            '<h6>Language Selection</h6>' +
            '<p>Select your preferred language and click OK</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Installation Directory</h6>' +
            '<p>Accept the default installation directory (C:\\Program Files\\PostgreSQL\\15) or choose a custom location</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Components Selection</h6>' +
            '<p>Ensure these components are selected:' +
            '<ul>' +
            '<li>PostgreSQL Server</li>' +
            '<li>pgAdmin 4 (for database management)</li>' +
            '<li>Command Line Tools</li>' +
            '<li>Stack Builder (optional)</li>' +
            '</ul>' +
            '</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Data Directory</h6>' +
            '<p>Accept the default data directory or choose a custom location with sufficient disk space</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Password Setup</h6>' +
            '<p>' +
            '<strong>CRITICAL:</strong> Set a secure password for the <code>postgres</code> superuser account.' +
            'This password is required for database administration.' +
            '</p>' +
            '<div class="alert alert-danger">' +
            '<i class="bi bi-shield-exclamation me-2"></i>' +
            'Save this password in a secure location. You\'ll need it to access the database.' +
            '</div>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Port Configuration</h6>' +
            '<p>Accept the default port (5432) unless you have a specific reason to change it</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Locale</h6>' +
            '<p>Accept the default locale settings</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Ready to Install</h6>' +
            '<p>Review your settings and click "Next" to begin installation</p>' +
            '</div>' +
            '</div>' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Step 4: Post-Installation Setup</h5>' +
            '<p>After installation completes:</p>' +
            
            '<div class="db-creation-steps">' +
            '<div class="db-creation-step">' +
            '<h6>Verify Service Status</h6>' +
            '<p>Check that PostgreSQL service is running:</p>' +
            '<div class="command-block">' +
            '<button class="copy-button" data-copy="sc query postgresql">' +
            '<i class="bi bi-clipboard"></i>' +
            '</button>' +
            'sc query postgresql' +
            '</div>' +
            '<p>You should see "STATE : 4 RUNNING" in the output</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Open pgAdmin 4</h6>' +
            '<p>' +
            'Launch pgAdmin 4 from the Start Menu. This is the graphical interface for managing PostgreSQL databases.' +
            '</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Connect to PostgreSQL Server</h6>' +
            '<p>' +
            'In pgAdmin, right-click on "Servers" > "Register" > "Server...<br>' +
            'Fill in these details:' +
            '</p>' +
            '<ul>' +
            '<li><strong>Name:</strong> Security Monitoring DB</li>' +
            '<li><strong>Host:</strong> localhost</li>' +
            '<li><strong>Port:</strong> 5432</li>' +
            '<li><strong>Maintenance database:</strong> postgres</li>' +
            '<li><strong>Username:</strong> postgres</li>' +
            '<li><strong>Password:</strong> [The password you set during installation]</li>' +
            '</ul>' +
            '<p>Click "Save" to connect</p>' +
            '</div>' +
            '</div>' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Step 5: Create Security Monitoring Database</h5>' +
            '<p>Using pgAdmin, create the database and user:</p>' +
            
            '<div class="db-creation-steps">' +
            '<div class="db-creation-step">' +
            '<h6>Create Database</h6>' +
            '<p>' +
            '1. Right-click on "Databases" > "Create" > "Database...<br>' +
            '2. Enter <code>security_monitoring</code> as the database name<br>' +
            '3. Click "Save"' +
            '</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Create Database User</h6>' +
            '<p>' +
            '1. Expand "Login/Group Roles" in the left pane<br>' +
            '2. Right-click > "Create" > "Login/Group Role..."<br>' +
            '3. In the "General" tab:' +
            '<ul>' +
            '<li>Name: <code>security_user</code></li>' +
            '<li>Password: [Set a secure password]</li>' +
            '</ul>' +
            '4. In the "Definition" tab, confirm the password<br>' +
            '5. In the "Privileges" tab, check "Can login"<br>' +
            '6. Click "Save"' +
            '</p>' +
            '</div>' +
            
            '<div class="db-creation-step">' +
            '<h6>Grant Database Privileges</h6>' +
            '<p>' +
            '1. Right-click on the <code>security_monitoring</code> database<br>' +
            '2. Select "Properties" > "Security" tab<br>' +
            '3. Click "Add" and select <code>security_user</code><br>' +
            '4. Grant these privileges:' +
            '<ul>' +
            '<li>CONNECT</li>' +
            '<li>CREATE</li>' +
            '<li>TEMPORARY</li>' +
            '</ul>' +
            '5. Go to the "Privileges" tab for the schema<br>' +
            '6. Grant ALL privileges to <code>security_user</code><br>' +
            '7. Click "Save"' +
            '</p>' +
            '</div>' +
            '</div>' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Step 6: Alternative Method Using Command Line</h5>' +
            '<p>If you prefer using the command line:</p>' +
            
            '<div class="command-block">' +
            '<button class="copy-button" data-copy="' + psqlCommands + '">' +
            '<i class="bi bi-clipboard"></i>' +
            '</button>' +
            psqlCommands.replace(/\n/g, '<br>') +
            '</div>' +
            
            '<div class="alert alert-info">' +
            '<i class="bi bi-info-circle-fill me-2"></i>' +
            'When prompted, enter the postgres password you set during installation.' +
            '</div>' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Step 7: Verify Installation</h5>' +
            '<p>Test your database connection:</p>' +
            
            '<div class="command-block">' +
            '<button class="copy-button" data-copy="cd C:\\Program Files\\PostgreSQL\\15\\bin\npsql -U security_user -d security_monitoring -c \"\\dt\"">' +
            '<i class="bi bi-clipboard"></i>' +
            '</button>' +
            'cd C:\\Program Files\\PostgreSQL\\15\\bin<br>' +
            'psql -U security_user -d security_monitoring -c "\\dt"' +
            '</div>' +
            
            '<p>If successful, you\'ll see a list of relations (currently empty). If you get an error, check your password and database name.</p>' +
            '</div>' +
            
            '<div class="mb-4">' +
            '<h5>Database Connection Information</h5>' +
            '<p>Enter the database connection details you just created. These will be used in the next step.</p>' +
            
            '<div class="row">' +
            '<div class="col-md-6">' +
            '<div class="mb-3">' +
            '<label class="form-label" for="pgDbName">Database Name</label>' +
            '<input type="text" class="form-control" id="pgDbName" placeholder="security_monitoring" value="security_monitoring">' +
            '</div>' +
            '</div>' +
            '<div class="col-md-6">' +
            '<div class="mb-3">' +
            '<label class="form-label" for="pgDbUser">Database Username</label>' +
            '<input type="text" class="form-control" id="pgDbUser" placeholder="security_user" value="security_user">' +
            '</div>' +
            '</div>' +
            '</div>' +
            
            '<div class="row">' +
            '<div class="col-md-6">' +
            '<div class="mb-3">' +
            '<label class="form-label" for="pgDbPassword">Database Password</label>' +
            '<input type="password" class="form-control" id="pgDbPassword" placeholder="your_secure_password">' +
            '</div>' +
            '</div>' +
            '<div class="col-md-6">' +
            '<div class="mb-3">' +
            '<label class="form-label" for="pgDbHost">Database Host</label>' +
            '<input type="text" class="form-control" id="pgDbHost" placeholder="localhost" value="localhost">' +
            '</div>' +
            '</div>' +
            '</div>' +
            
            '<div class="mb-3">' +
            '<button type="button" class="btn btn-primary" id="testPgConnection">' +
            'Test Connection <i class="bi bi-plug"></i>' +
            '</button>' +
            '</div>' +
            
            '<div id="pgConnectionResult" class="alert d-none"></div>' +
            '</div>';
        
        // Re-attach event listeners for the new elements
        document.getElementById('downloadWindowsInstaller').addEventListener('click', function() {
            const link = document.createElement('a');
            link.href = 'https://get.enterprisedb.com/postgresql/postgresql-15.3-1-windows-x64.exe';
            link.download = 'postgresql-15.3-1-windows-x64.exe';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
        
        document.getElementById('testPgConnection').addEventListener('click', function() {
            const dbName = document.getElementById('pgDbName').value;
            const dbUser = document.getElementById('pgDbUser').value;
            const dbPassword = document.getElementById('pgDbPassword').value;
            const dbHost = document.getElementById('pgDbHost').value;
            
            if (!dbName || !dbUser || !dbPassword || !dbHost) {
                pgConnectionResult.className = 'alert alert-warning';
                pgConnectionResult.textContent = 'Please fill in all database connection fields';
                pgConnectionResult.classList.remove('d-none');
                return;
            }
            
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Testing...';
            this.disabled = true;
            
            setTimeout(() => {
                this.innerHTML = 'Test Connection <i class="bi bi-plug"></i>';
                this.disabled = false;
                
                pgConnectionResult.className = 'alert alert-success';
                pgConnectionResult.innerHTML = '<i class="bi bi-check-circle-fill me-2"></i> Database connection successful!';
                pgConnectionResult.classList.remove('d-none');
            }, 1500);
        });
        
        // Re-attach copy button functionality
        document.querySelectorAll('.copy-button').forEach(button => {
            button.addEventListener('click', function() {
                const textToCopy = this.getAttribute('data-copy');
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalHTML = this.innerHTML;
                    this.innerHTML = '<i class="bi bi-check"></i>';
                    setTimeout(() => {
                        this.innerHTML = originalHTML;
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy text: ', err);
                });
            });
        });
    }
    
    // Initialize with enhanced Windows instructions
    showWindowsPostgresInstructions();
});