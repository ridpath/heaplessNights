#!groovy

import jenkins.model.*
import hudson.security.csrf.DefaultCrumbIssuer
import jenkins.CLI

def instance = Jenkins.getInstance()

def cli = CLI.get()
cli.setEnabled(true)

println "CLI enabled for vulnerability testing"

instance.save()
