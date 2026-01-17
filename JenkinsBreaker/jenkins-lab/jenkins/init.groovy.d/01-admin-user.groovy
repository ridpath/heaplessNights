#!groovy

import jenkins.model.*
import hudson.security.*
import jenkins.install.InstallState

def instance = Jenkins.getInstance()

// SECURITY WARNING: Default credentials for testing only
// For production/custom credentials, set environment variables:
//   JENKINS_ADMIN_USER - Admin username (default: admin)
//   JENKINS_ADMIN_PASS - Admin password (default: admin)
//
// Example:
//   docker run -e JENKINS_ADMIN_USER=myuser -e JENKINS_ADMIN_PASS=strongpass123 ...
//
// Or in docker-compose.yml:
//   environment:
//     - JENKINS_ADMIN_USER=myuser
//     - JENKINS_ADMIN_PASS=strongpass123

def adminUser = System.getenv("JENKINS_ADMIN_USER") ?: "admin"
def adminPass = System.getenv("JENKINS_ADMIN_PASS") ?: "admin"

def hudsonRealm = new HudsonPrivateSecurityRealm(false)
hudsonRealm.createAccount(adminUser, adminPass)
instance.setSecurityRealm(hudsonRealm)

def strategy = new FullControlOnceLoggedInStrategy()
strategy.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(strategy)

if (!instance.installState.isSetupComplete()) {
  InstallState.INITIAL_SETUP_COMPLETED.initializeState()
}

instance.save()

println "Jenkins configured with admin user: ${adminUser}"
if (adminUser == "admin" && adminPass == "admin") {
  println "WARNING: Using default admin/admin credentials - CHANGE IN PRODUCTION!"
}
