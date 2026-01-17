#!groovy

import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*
import hudson.plugins.sshslaves.*
import jenkins.model.*
import org.jenkinsci.plugins.plaincredentials.impl.*

def domain = Domain.global()
def store = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()

def awsApiKey = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "aws-secret-key",
  "AWS Secret Access Key",
  hudson.util.Secret.fromString("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
)

def awsAccessKey = new UsernamePasswordCredentialsImpl(
  CredentialsScope.GLOBAL,
  "aws-credentials",
  "AWS Access Credentials",
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

def githubToken = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "github-token",
  "GitHub API Token",
  hudson.util.Secret.fromString("ghp_ExampleTokenString123456789ABC")
)

def dockerPassword = new UsernamePasswordCredentialsImpl(
  CredentialsScope.GLOBAL,
  "docker-registry",
  "Docker Registry Credentials",
  "dockeruser",
  "dockerpassword123"
)

def npmToken = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "npm-token",
  "NPM Registry Token",
  hudson.util.Secret.fromString("npm_ExampleTokenString123456789")
)

def databaseAdmin = new UsernamePasswordCredentialsImpl(
  CredentialsScope.GLOBAL,
  "database-admin",
  "Database Administrator Credentials",
  "dbadmin",
  "DB_@dm1n_P@ssw0rd_2024!"
)

def herokuApiKey = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "heroku-api-key",
  "Heroku API Key",
  hudson.util.Secret.fromString("abcdef12-3456-7890-abcd-ef1234567890")
)

def cloudflareToken = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "cloudflare-token",
  "Cloudflare API Token",
  hudson.util.Secret.fromString("CloudflareTokenExample123456789ABC")
)

def stripeSecretKey = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "stripe-secret-key",
  "Stripe Secret Key",
  hudson.util.Secret.fromString("sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm")
)

def sendgridApiKey = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "sendgrid-api-key",
  "SendGrid API Key",
  hudson.util.Secret.fromString("SG.AbCdEfGhIjKlMnOpQrStUv.WxYz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd")
)

def twilioAuthToken = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "twilio-auth-token",
  "Twilio Auth Token",
  hudson.util.Secret.fromString("abcdef1234567890abcdef1234567890")
)

def slackBotToken = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "slack-bot-token",
  "Slack Bot Token",
  hudson.util.Secret.fromString("xoxb-0123456789-0123456789012-AbCdEfGhIjKlMnOpQrStUv")
)

def datadogApiKey = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "datadog-api-key",
  "Datadog API Key",
  hudson.util.Secret.fromString("abcdef1234567890abcdef1234567890")
)

def jwtSecret = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "jwt-secret",
  "JWT Secret Key",
  hudson.util.Secret.fromString("jwt-secret-key-256-bits-change-in-production-environment")
)

def apiMasterKey = new StringCredentialsImpl(
  CredentialsScope.GLOBAL,
  "api-master-key",
  "API Master Key",
  hudson.util.Secret.fromString("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
)

def sshPrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/tYFBRuAzqO6pxzVhBiMwbEbHxEJi27vP
FcwmBFa4AqXLKVqPVMZSP2CQLvQFVr9Y8Ux5Td0cFjKqXQsW8jVPKF3xXjGYvhxu
RCOYdISlCCNmJ3ycWJxqGQPr4l5pMVL6kVPJVKZQUqPf3FZ9eV2kXt3Qe5ZjRpx/
8PtCRKHNvYLfVJ2XE9qQvGGYfDQnLJXS7EKpMX5YV4LbAZZXHTKVJaA7C0eQqnT3
yWKLLMZUJ7tGV3pL1bXCMZNdPJVL0qhLvHXjEfVNFqKVp0wDKtTGqN3fXbLr1F0s
rPp3xJqKqQj6KHJMGPvWJ3xvVrJd3yMcXQVJmQIDAQABAoIBAG8KJvJqv7KCQCFG
hQRyFfHFjLnJrHvKp3nLJr0dpJPYHD6xJL7HqEOYQVqJvGsP8eXEJPKaQxLJ0b1I
J9NJqxHEVvVPMqvJQN6L8R8pqKDKMQXgLfJ6PKJ1N8rGP5JLJnXJPqLvWrJKMpVp
0Q9KJL7VqJP8LfJvVLqPMqJLPvLqJL8L9JpVqLPJLvKqJL9JpLvJqL0JLvJqPL9J
qLvJPLqJL9PqJLvJPLqJL9qJLvJPLqKL9qJLvPqJLqKL9qPLvJqLKqL9qPLvJqLK
qL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJq
LKqL9qECgYEA7xZ3vJL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9
qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKq
L9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqL
KqL9qPECgYEA4J9KJL7VqJP8LfJvVLqPMqJLPvLqJL8L9JpVqLPJLvKqJL9JpLvJ
qL0JLvJqPL9JqLvJPLqJL9PqJLvJPLqJL9qJLvJPLqKL9qJLvPqJLqKL9qPLvJqL
KqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJ
qLKqL9qPLvJqLKqL9qECgYEA0fJVL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9q
PLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL
9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLK
qL9qPLvJqLKqL9qECgYBJL7VqJP8LfJvVLqPMqJLPvLqJL8L9JpVqLPJLvKqJL9J
pLvJqL0JLvJqPL9JqLvJPLqJL9PqJLvJPLqJL9qJLvJPLqKL9qJLvPqJLqKL9qPL
vJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9q
PLvJqLKqL9qPLvJqLKqL9qECgYBJL7VqJP8LfJvVLqPMqJLPvLqJL8L9JpVqLPJL
vKqJL9JpLvJqL0JLvJqPL9JqLvJPLqJL9PqJLvJPLqJL9qJLvJPLqKL9qJLvPqJL
qKL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJqLKqL9qPLvJ
qLKqL9qPLvJqLKqL9qPLvJqLKqL9qA==
-----END RSA PRIVATE KEY-----"""

def prodServerSsh = new BasicSSHUserPrivateKey(
  CredentialsScope.GLOBAL,
  "prod-server-ssh",
  "deploy",
  new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(sshPrivateKey),
  "",
  "Production Server SSH Key"
)

store.addCredentials(domain, awsApiKey)
store.addCredentials(domain, awsAccessKey)
store.addCredentials(domain, githubToken)
store.addCredentials(domain, dockerPassword)
store.addCredentials(domain, npmToken)
store.addCredentials(domain, databaseAdmin)
store.addCredentials(domain, herokuApiKey)
store.addCredentials(domain, cloudflareToken)
store.addCredentials(domain, stripeSecretKey)
store.addCredentials(domain, sendgridApiKey)
store.addCredentials(domain, twilioAuthToken)
store.addCredentials(domain, slackBotToken)
store.addCredentials(domain, datadogApiKey)
store.addCredentials(domain, jwtSecret)
store.addCredentials(domain, apiMasterKey)
store.addCredentials(domain, prodServerSsh)

println "All credentials added for testing (16 total)"
