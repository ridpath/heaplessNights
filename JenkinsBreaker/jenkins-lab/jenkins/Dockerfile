FROM jenkins/jenkins:2.138.3-alpine

USER root

RUN apk add --no-cache \
    curl \
    wget \
    git \
    openssh-client \
    vim \
    bash \
    sudo \
    python3 \
    py3-pip \
    tar \
    gzip

RUN echo "jenkins ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/docker, /bin/systemctl, /usr/bin/tar, /usr/bin/find" >> /etc/sudoers || true

RUN echo "jenkins ALL=(root) NOPASSWD: /opt/scripts/backup.sh" >> /etc/sudoers.d/jenkins-backup || true

RUN mkdir -p /home/jenkins/.aws /home/jenkins/.ssh /home/jenkins/.docker /home/jenkins/.m2 /home/jenkins/.config && \
    chown -R jenkins:jenkins /home/jenkins

COPY --chown=jenkins:jenkins secrets/aws_credentials /home/jenkins/.aws/credentials
COPY --chown=jenkins:jenkins secrets/id_rsa /home/jenkins/.ssh/id_rsa
COPY --chown=jenkins:jenkins secrets/npmrc /home/jenkins/.npmrc
COPY --chown=jenkins:jenkins secrets/docker_config.json /home/jenkins/.docker/config.json
COPY --chown=jenkins:jenkins secrets/maven_settings.xml /home/jenkins/.m2/settings.xml
COPY --chown=jenkins:jenkins secrets/database_credentials.env /home/jenkins/.config/database.env
COPY --chown=jenkins:jenkins secrets/api_keys.env /home/jenkins/.config/api_keys.env
COPY --chown=jenkins:jenkins secrets/cloud_credentials.env /home/jenkins/.config/cloud.env

RUN chmod 600 /home/jenkins/.ssh/id_rsa /home/jenkins/.aws/credentials
RUN chmod 644 /home/jenkins/.config/*.env

RUN mkdir -p /opt/scripts /var/jenkins_home/backups && \
    chown -R jenkins:jenkins /var/jenkins_home/backups

COPY --chown=root:root secrets/backup_script.sh /opt/scripts/backup.sh
RUN chmod 755 /opt/scripts/backup.sh

RUN mkdir -p /etc/cron.d
RUN echo "0 2 * * * jenkins /opt/scripts/backup.sh >> /var/log/jenkins_backup.log 2>&1" > /etc/cron.d/jenkins-backup
RUN chmod 644 /etc/cron.d/jenkins-backup

RUN mkdir -p /tmp/scripts && \
    echo '#!/bin/bash' > /tmp/scripts/deploy.sh && \
    echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' >> /tmp/scripts/deploy.sh && \
    echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' >> /tmp/scripts/deploy.sh && \
    echo 'export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY' >> /tmp/scripts/deploy.sh && \
    echo 'echo "Deploying to production..."' >> /tmp/scripts/deploy.sh && \
    chmod 777 /tmp/scripts/deploy.sh

USER jenkins

# Credentials configured via init.groovy.d scripts (see init.groovy.d/ directory)
# Users should modify init.groovy.d/01-security.groovy to set custom credentials
# Default test environment uses: admin/admin (CHANGE IN PRODUCTION)
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt

RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt || true

COPY --chown=jenkins:jenkins init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/

COPY --chown=jenkins:jenkins jobs/ /usr/share/jenkins/ref/jobs/

COPY --chown=jenkins:jenkins secrets/ /var/jenkins_home/secrets/

EXPOSE 8080 50000
