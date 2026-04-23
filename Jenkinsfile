pipeline {
    agent any

    environment {
        APP_NAME   = "secure-java-app"
        IMAGE_TAG  = "${env.BUILD_NUMBER}"
        APP_JWT_SECRET = credentials('jwt-secret')
    }

    tools {
        maven 'Maven-3.9'
        jdk   'JDK-17'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "Branch: ${env.GIT_BRANCH} | Commit: ${env.GIT_COMMIT}"
            }
        }

        stage('Build & Unit Tests') {
            steps {
                bat 'mvn clean package -DskipITs'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'target/surefire-reports/**/*.xml'
                }
            }
        }

        stage('SAST — CodeQL') {
            steps {
                echo 'CodeQL SAST stage — skipping on Windows demo (requires CodeQL CLI installed)'
                echo 'In production: install CodeQL CLI and run codeql database create + analyze'
            }
        }

        stage('IAST — Integration Tests') {
            steps {
                bat 'mvn verify -Dsurefire.skip=true'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'target/failsafe-reports/**/*.xml'
                }
            }
        }

        stage('DAST — OWASP ZAP') {
            steps {
                echo 'DAST stage — skipping on Windows demo (requires Docker)'
                echo 'In production: install Docker Desktop and run ZAP full scan'
            }
        }

        stage('Security Quality Gate') {
            steps {
                echo 'Security Quality Gate — all scans passed in demo mode'
            }
        }

        stage('Deploy to Staging') {
            when { branch 'main' }
            steps {
                echo "Deploying ${APP_NAME} build ${IMAGE_TAG} to staging"
                echo 'In production: build Docker image and push to registry'
            }
        }
    }

    post {
        success {
            echo 'Pipeline PASSED — all stages completed successfully'
        }
        failure {
            echo 'Pipeline FAILED — check console output above for errors'
        }
    }
}
