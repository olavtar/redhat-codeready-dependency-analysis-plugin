![openshift](https://user-images.githubusercontent.com/37098367/114392384-522d8480-9bb6-11eb-8cd8-cdc6191f6a79.png)
***

# Table of Contents
- [Introduction](#red-hat-codeready-dependency-analysis)
- [How To Use The Plugin](#how-to-use-the-plugin)
  - [Admin Steps](#admin-steps)
    - [Generate CRDA Key](#1-generate-crda-key)
    - [Install The Plugin](#2-install-the-redhat-codeready-dependency-analysis-jenkins-plugin)
    - [CRDA Credentials](#3-crda-credentials)
    - [Configuration](#4-configuration)
      - [1. Build Step](#option-i--as-a-build-step)
      - [2. Pipeline Task](#option-ii--as-a-pipeline-task)
- [Results](#results)
  - [1. Console Output](#1-console-output)
  - [2. CRDA Stack Report](#2-crda-stack-report)
  - [3. Detailed CRDA Stack Report](#3-detailed-crda-stack-report)
- [Snyk Registration](#snyk-registration)
  - [1. Via CLI](#1-via-cli)
  - [2. Via CRDA Stack Report UI](#2-via-crda-stack-report-ui)

# Red Hat Codeready Dependency Analysis
Red Hat codeready dependency analysis is a jenkins plugin developed by **Red Hat Inc**. CRDA (codeready dependency analytics) is powered by **Snyk Intel Vulnerability DB**, which is the most advanced and accurate open source vulnerability database in the industry. It adds value with the latest, fastest and more number of vulnerabilities derived from numerous sources.

'CRDA Report' with Insights about your application dependencies:
- Flags a security vulnerability(CVE) and suggests a remedial version
- Shows Github popularity metrics along with latest version
- Suggests a project level license, check for conflicts between dependency licences
- AI based guidance for additional, alternative dependencies

The plugin can be used in jenkins as a pipeline task or as a build step.

## How to use the plugin
### Admin Steps
### 1. Generate CRDA Key
- Download the CRDA CLI tool on your system. Click [here](https://github.com/fabric8-analytics/cli-tools/releases "here") to download.
- Follow the instructions for the installation and run `crda auth` command to generate the crda key. Copy this key.

### 2. Install the redhat-codeready-dependency-analysis jenkins plugin
- Goto the jenkins dashboard -> Manage Jenkins -> Manage Plugins.
- Seach for `redhat-codeready-dependency-analysis` and install.

### 3. CRDA credentials
- Goto jenkins dashboard -> Manage Jenkins -> Manage Credentials. Select the global domain -> Add Credentials.
- Select the option `CRDA Key` in the Kind option.
- Let the scope be global.
- Enter a valid CRDA Snyk Token which was generated via the crda auth command using the CRDA CLI.
- Let the ID field blank. Jenkins will generate the ID. You can also provide an id of your own if you wish to.
- Give some description for the identification of the credentials.
![](./images/credentialsScreen.png)

### 4. Configuration
Make sure that the Path is updated to point to the corresponding executables, like mvn, pip etc.
#### Option I- As a build step
- Click on Configure -> Build Trigger -> Add Build Step. Select `Invoke Red Hat Codeready Dependency Analysis (CRDA)`.
- Filepath (Mandatory): Provide the filepath for the manifest file. We currently support the following
	- Maven: pom.xml
	- Python: requirements.txt
	- Npm: package.json
	- Golang: go.mod
- CRDA Snyk token (Mandatory): The Id generated by jenkins from the step 3. You also have an option to create a new key/id if you have access to it.
- Usage Statistics (Optional): Consent given to red hat to collect some usage statistics to improve the plugin and report. Default consent is false.
![](./images/configOption1.png)
  
#### Option II- As a pipeline task
- Its just a single line that you need to add in your pipeline script.
`crdaAnalysis file:'manifest file path', crdaKeyId:'crda key id', consentTelemetry:true`
The value description remains the same as provided in the Option I.
User can also use the pipeline snippet generator to generate the command.
![Screenshot from 2021-05-06 15-11-38](https://user-images.githubusercontent.com/37098367/117278019-0355d080-ae7e-11eb-9eb1-92f7b6dd256e.png)
- It returns 3 different exit status code
	- 0: Analysis is successful and there were no vulnerabilities found in the dependency stack.
	- 1: Analysis encountered an error.
	- 2: Analysis is successful and it found 1 or more vulnerabilities in the dependency stack.

## Results
There are a total 3 ways to view the results of the analysis.
### 1. Console Output
This provides the count and types of vulnerabilities found in the dependency stack. This data is generated for every build and can be viewed in the corresponding console log. It also provides a link to the detailed report.
![](./images/consoleOutput.png)

### 2. CRDA Stack Report
After every successful analysis, you can find a new icon added in the left panel named
`CRDA Stack Report` . Click on this icon to view the report in graphical form. Here too, we provide a button to redirect to the detailed stack report UI.
![Screenshot from 2021-04-12 16-51-30](https://user-images.githubusercontent.com/37098367/114390156-83588580-9bb3-11eb-8b3c-7f82e48a5747.png)

### 3. Detailed CRDA Stack Report
The stack report can be accessed via 2 ways, as mentioned in point number 1 (via url) and 2 (via button click). The report provides comprehensive details about each vulnerability, each dependency in the stack along with the license analysis and the recommended companions.
![crda](https://user-images.githubusercontent.com/37098367/114390401-d6cad380-9bb3-11eb-823d-bd4111ed3fbe.gif)

## Snyk Registration
There are 2 ways to register with Snyk
### 1. Via CLI
If you have a Snyk token, then the same can be used at the time of `crda auth` cli command execution by providing the snyk token.

### 2. Via CRDA Stack Report UI
Follow the 2 steps shown below to generate a snyk token and provide it in the appropriate place in the stack report.

**Step1**
![snyk-sign-up](https://user-images.githubusercontent.com/37098367/114044101-86e2c880-98a4-11eb-83db-5e1e07bbae15.gif)

**Step2**
![snyk-token](https://user-images.githubusercontent.com/37098367/114044134-8f3b0380-98a4-11eb-84c0-70809a3cccc3.gif)
