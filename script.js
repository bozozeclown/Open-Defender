document.addEventListener('DOMContentLoaded', function() {
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
    const deploymentMethods = document.querySelectorAll('.deployment-method');
    let selectedDeploymentMethod = 'docker';
    
    prevStep2.addEventListener('click', function() {
        goToStep(1);
    });
    
    nextStep2.addEventListener('click', function() {
        goToStep(3);
    });
    
    deploymentMethods.forEach(method => {
        method.addEventListener('click', function() {
            deploymentMethods.forEach(m => m.classList.remove('selected'));
            this.classList.add('selected');
            selectedDeploymentMethod = this.dataset.method;
        });
    });
    
    // Set default selected deployment method
    document.querySelector('.deployment-method[data-method="docker"]').classList.add('selected');
    
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
        document.getElementById('dbPassword').value = document.getElementById('pgDbPassword').value;
        
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
    
    useExternalDb.addEventListener('change', function() {
        if (this.checked) {
            externalDbConfig.style.display = 'block';
            embeddedDbConfig.style.display = 'none';
        } else {
            externalDbConfig.style.display = 'none';
            embeddedDbConfig.style.display = 'block';
        }
    });
    
    enableReadReplicas.addEventListener('change', function() {
        readReplicasConfig.style.display = this.checked ? 'block' : 'none';
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
    
    enableTls.addEventListener('change', function() {
        tlsConfig.style.display = this.checked ? 'block' : 'none';
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
        alert('Setup completed successfully! You can now deploy your Security Monitoring System.');
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
        const environment = document.getElementById('environmentType').value;
        const appName = document.getElementById('appName').value;
        const appVersion = document.getElementById('appVersion').value;
        const dbHost = document.getElementById('dbHost').value;
        const dbPort = document.getElementById('dbPort').value;
        const dbName = document.getElementById('dbName').value;
        const dbUser = document.getElementById('dbUser').value;
        const dbSslMode = document.getElementById('dbSslMode').value;
        const dbMaxConnections = document.getElementById('dbMaxConnections').value;
        const dbMinConnections = document.getElementById('dbMinConnections').value;
        const eventBufferSize = document.getElementById('eventBufferSize').value;
        const portScanThreshold = document.getElementById('portScanThreshold').value;
        const dataExfiltrationThreshold = document.getElementById('dataExfiltrationThreshold').value;
        const systemMetricsInterval = document.getElementById('systemMetricsInterval').value;
        const suspiciousProcesses = document.getElementById('suspiciousProcesses').value;
        const jwtExpiryHours = document.getElementById('jwtExpiryHours').value;
        const corsOrigins = document.getElementById('corsOrigins').value;
        const logLevel = document.getElementById('logLevel').value;
        const jaegerEndpoint = document.getElementById('jaegerEndpoint').value;
        const enableTracing = document.getElementById('enableTracing').checked;
        const enableMetrics = document.getElementById('enableMetrics').checked;
        const enableTls = document.getElementById('enableTls').checked;
        
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
            const tlsCertPath = document.getElementById('tlsCertPath').value;
            const tlsKeyPath = document.getElementById('tlsKeyPath').value;
            config += `
    cert_path: "${tlsCertPath}"
    key_path: "${tlsKeyPath}"`;
        }
        
        if (enableReadReplicas.checked) {
            const readReplicaHosts = document.getElementById('readReplicaHosts').value;
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
        const appName = document.getElementById('appName').value;
        const graphqlPort = document.getElementById('graphqlPort').value;
        const websocketPort = document.getElementById('websocketPort').value;
        const metricsPort = document.getElementById('metricsPort').value;
        const dbHost = document.getElementById('dbHost').value;
        const dbPort = document.getElementById('dbPort').value;
        const dbName = document.getElementById('dbName').value;
        const dbUser = document.getElementById('dbUser').value;
        const dbPassword = document.getElementById('dbPassword').value;
        
        let compose = `version: '3.8'

services:
  ${appName}:
    image: Open-Defender:latest
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
        const environment = document.getElementById('environmentType').value;
        const deploymentMethod = selectedDeploymentMethod;
        const useExternal = document.getElementById('useExternalDb').checked;
        const dbHost = document.getElementById('dbHost').value;
        const dbPort = document.getElementById('dbPort').value;
        const dbName = document.getElementById('dbName').value;
        const graphqlPort = document.getElementById('graphqlPort').value;
        const websocketPort = document.getElementById('websocketPort').value;
        const metricsPort = document.getElementById('metricsPort').value;
        
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
                            <li>GraphQL API: http://localhost:${document.getElementById('graphqlPort').value}</li>
                            <li>WebSocket: ws://localhost:${document.getElementById('websocketPort').value}</li>
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
                        <pre class="mt-2 mb-2 p-2 bg-light">kubectl get pods -n Open-Defender</pre>
                    </li>
                    <li>Access the application:
                        <ul>
                            <li>Get the service IP:
                                <pre class="mt-2 mb-2 p-2 bg-light">kubectl get svc -n Open-Defender</pre>
                            </li>
                            <li>GraphQL API: http://&lt;service-ip&gt;:${document.getElementById('graphqlPort').value}</li>
                            <li>WebSocket: ws://&lt;service-ip&gt;:${document.getElementById('websocketPort').value}</li>
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
                        <pre class="mt-2 mb-2 p-2 bg-light">helm install Open-Defender ./Open-Defender</pre>
                    </li>
                    <li>Check the status of the release:
                        <pre class="mt-2 mb-2 p-2 bg-light">helm status Open-Defender</pre>
                    </li>
                    <li>Check the status of the pods:
                        <pre class="mt-2 mb-2 p-2 bg-light">kubectl get pods -n Open-Defender</pre>
                    </li>
                    <li>Access the application:
                        <ul>
                            <li>Get the service IP:
                                <pre class="mt-2 mb-2 p-2 bg-light">kubectl get svc -n Open-Defender</pre>
                            </li>
                            <li>GraphQL API: http://&lt;service-ip&gt;:${document.getElementById('graphqlPort').value}</li>
                            <li>WebSocket: ws://&lt;service-ip&gt;:${document.getElementById('websocketPort').value}</li>
                        </ul>
                    </li>
                </ol>
                <p>To uninstall the release, run:</p>
                <pre class="mt-2 mb-2 p-2 bg-light">helm uninstall Open-Defender</pre>
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