#!groovy

import jenkins.model.*
import hudson.model.*
import org.jenkinsci.plugins.workflow.job.WorkflowJob
import javax.xml.transform.stream.StreamSource

def jenkins = Jenkins.instance

def jobsDir = new File('/usr/share/jenkins/ref/jobs')

if (!jobsDir.exists()) {
    println "Jobs directory not found, skipping job loading"
    return
}

jobsDir.eachDir { jobDir ->
    def jobName = jobDir.name
    def configFile = new File(jobDir, 'config.xml')
    
    if (configFile.exists()) {
        try {
            def existing = jenkins.getItem(jobName)
            if (existing != null) {
                println "Job ${jobName} already exists, skipping"
            } else {
                def configXml = configFile.text
                def xmlStream = new ByteArrayInputStream(configXml.getBytes("UTF-8"))
                def job = jenkins.createProjectFromXML(jobName, xmlStream)
                println "Created job: ${jobName}"
            }
        } catch (Exception e) {
            println "Error creating job ${jobName}: ${e.message}"
            e.printStackTrace()
        }
    }
}

jenkins.save()
println "Jobs loaded successfully"
