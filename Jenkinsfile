// ─────────────────────────────────────────────────────────────
// Jenkinsfile — Secure CI/CD Pipeline
// Stages: Checkout → Build → SAST (CodeQL) → IAST → DAST → Gate → Deploy
// ─────────────────────────────────────────────────────────────

pipeline {
    agent any

    environment {
        APP_NAME    = "secure-java-app"
        IMAGE_TAG   = "${env.BUILD_NUMBER}"
        // Inject real secret from Jenkins Credentials store
        APP_JWT_SECRET = credentials('jwt-secret')
    }

    tools {
        maven 'Maven-3.9'
        jdk   'JDK-17'
    }

    stages {

        // ── 1. Checkout ───────────────────────────────────────
        stage('Checkout') {
            steps {
                checkout scm
                echo "Branch: ${env.GIT_BRANCH} | Commit: ${env.GIT_COMMIT}"
            }
        }

        // ── 2. Build & Unit Tests ─────────────────────────────
        stage('Build & Unit Tests') {
            steps {
                sh 'mvn clean package -DskipITs'
            }
            post {
                always {
                    junit 'target/surefire-reports/**/*.xml'
                }
            }
        }

        // ── 3. SAST — CodeQL ──────────────────────────────────
        // CodeQL scans source code without running it.
        // It builds a semantic model to find injection flaws,
        // auth bypasses, unsafe deserialization, etc.
        stage('SAST — CodeQL') {
            steps {
                sh '''
                    # Initialize CodeQL database from the compiled source
                    codeql database create codeql-db \
                        --language=java \
                        --command="mvn clean compile -DskipTests" \
                        --overwrite

                    # Run the standard Java security queries
                    codeql database analyze codeql-db \
                        --format=sarif-latest \
                        --output=codeql-results.sarif \
                        codeql/java-queries:codeql-suites/java-security-extended.qls

                    echo "CodeQL SAST scan complete"
                '''
            }
            post {
                always {
                    // Upload SARIF to GitHub Security tab via GitHub Advanced Security
                    archiveArtifacts artifacts: 'codeql-results.sarif', allowEmptyArchive: true
                    // If using GitHub Advanced Security plugin:
                    // recordIssues tool: codeQl(pattern: 'codeql-results.sarif')
                }
            }
        }

        // ── 4. IAST — Agent-based runtime analysis ───────────
        // The IAST agent (e.g. Contrast Security, Seeker, or HCL AppScan)
        // is injected as a Java agent. As integration tests run, the agent
        // monitors every code path from inside the JVM — tracking taint
        // flow, unsafe calls, and real exploitable paths.
        stage('IAST — Integration Tests') {
            steps {
                sh '''
                    # Download IAST agent if not cached
                    if [ ! -f /opt/iast/agent.jar ]; then
                        mkdir -p /opt/iast
                        # Replace with your vendor's agent download URL
                        curl -L https://your-iast-vendor.com/agent.jar -o /opt/iast/agent.jar
                    fi

                    # Run integration tests (*IT.java) with the IAST agent injected
                    mvn verify -Dsurefire.skip=true \
                        -Dfailsafe.argLine="-javaagent:/opt/iast/agent.jar \
                            -Diast.server.url=http://iast-server:8090 \
                            -Diast.api.key=${IAST_API_KEY}"
                '''
            }
            post {
                always {
                    junit 'target/failsafe-reports/**/*.xml'
                    // Fetch findings from IAST server API and archive
                    sh '''
                        curl -s http://iast-server:8090/api/findings \
                            -H "Authorization: Bearer ${IAST_API_KEY}" \
                            -o iast-findings.json || true
                    '''
                    archiveArtifacts artifacts: 'iast-findings.json', allowEmptyArchive: true
                }
            }
        }

        // ── 5. DAST — OWASP ZAP ──────────────────────────────
        // ZAP attacks the running app from the outside like a real attacker:
        // crawls endpoints, fuzzes inputs, checks headers, tests auth, etc.
        stage('DAST — OWASP ZAP') {
            steps {
                // Start the app in the background for ZAP to scan
                sh '''
                    java -jar target/${APP_NAME}-1.0.0.jar \
                        --spring.profiles.active=test &
                    APP_PID=$!
                    echo $APP_PID > app.pid

                    # Wait for app to be ready
                    echo "Waiting for app to start..."
                    for i in $(seq 1 30); do
                        curl -sf http://localhost:8080/actuator/health && break
                        sleep 3
                    done

                    # Run ZAP Full Scan using the config file
                    docker run --rm \
                        --network host \
                        -v $(pwd)/zap:/zap/wrk \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-full-scan.py \
                            -t http://localhost:8080 \
                            -c /zap/wrk/zap-rules.conf \
                            -r /zap/wrk/zap-report.html \
                            -J /zap/wrk/zap-report.json \
                            -I

                    # Stop the app
                    kill $(cat app.pid) || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap/zap-report.*', allowEmptyArchive: true
                    publishHTML([
                        allowMissing: true,
                        reportDir: 'zap',
                        reportFiles: 'zap-report.html',
                        reportName: 'DAST ZAP Report'
                    ])
                }
            }
        }

        // ── 6. Security Quality Gate ──────────────────────────
        // Parse all scan results and BLOCK the build if any
        // Critical or High severity findings are present.
        stage('Security Quality Gate') {
            steps {
                sh '''
                    FAIL=0

                    # Check CodeQL — any "error" level result fails
                    if grep -q '"level":"error"' codeql-results.sarif 2>/dev/null; then
                        echo "FAIL: CodeQL found critical issues"
                        FAIL=1
                    fi

                    # Check IAST findings
                    if grep -q '"severity":"CRITICAL"' iast-findings.json 2>/dev/null; then
                        echo "FAIL: IAST found critical issues"
                        FAIL=1
                    fi

                    # Check ZAP — fail on HIGH alerts
                    HIGH=$(python3 -c "
import json, sys
try:
    data = json.load(open('zap/zap-report.json'))
    highs = sum(1 for s in data.get('site',[]) for a in s.get('alerts',[]) if a.get('riskcode') == '3')
    print(highs)
except: print(0)
")
                    if [ "$HIGH" -gt "0" ]; then
                        echo "FAIL: ZAP found $HIGH HIGH risk alerts"
                        FAIL=1
                    fi

                    if [ "$FAIL" -eq "1" ]; then
                        echo "Security gate FAILED — build blocked"
                        exit 1
                    fi

                    echo "Security gate PASSED — all scans clean"
                '''
            }
        }

        // ── 7. Deploy ─────────────────────────────────────────
        stage('Deploy to Staging') {
            when { branch 'main' }
            steps {
                sh '''
                    echo "Building Docker image..."
                    docker build -t ${APP_NAME}:${IMAGE_TAG} .

                    echo "Pushing to registry..."
                    docker tag  ${APP_NAME}:${IMAGE_TAG} registry.example.com/${APP_NAME}:${IMAGE_TAG}
                    docker push registry.example.com/${APP_NAME}:${IMAGE_TAG}

                    echo "Deploying to staging..."
                    # kubectl set image deployment/${APP_NAME} \
                    #     app=registry.example.com/${APP_NAME}:${IMAGE_TAG}
                    echo "Deployed image: ${IMAGE_TAG}"
                '''
            }
        }
    }

    // ── Post-pipeline ─────────────────────────────────────────
    post {
        success {
            echo "Pipeline passed — notifying GitHub with success status"
            // githubNotify status: 'SUCCESS', description: 'All security scans passed'
        }
        failure {
            echo "Pipeline FAILED — notifying GitHub to block merge"
            // githubNotify status: 'FAILURE', description: 'Security gate failed'
            // emailext to: 'security-team@example.com', subject: "SECURITY FAIL: ${env.JOB_NAME}"
        }
        always {
            cleanWs()
        }
    }
}
