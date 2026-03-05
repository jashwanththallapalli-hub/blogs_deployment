pipeline {
    agent any

    environment {
        IMAGE_NAME = "jashwanth239/blogs-app"
        EC2_IP = "44.221.50.70"
    }

    stages {

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t $IMAGE_NAME .'
            }
        }

        stage('Push Docker Image') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
                    sh 'docker login -u $USER -p $PASS'
                    sh 'docker push $IMAGE_NAME'
                }
            }
        }

        stage('Deploy to EC2') {
            steps {
                sh '''
                ssh -o StrictHostKeyChecking=no -i /var/lib/jenkins/samplekey.pem ubuntu@$EC2_IP << EOF

                docker pull $IMAGE_NAME
                docker stop blogs-container || true
                docker rm blogs-container || true
                docker run -d -p 5000:5000 --name blogs-container $IMAGE_NAME

                EOF
                '''
            }
        }
    }
}
