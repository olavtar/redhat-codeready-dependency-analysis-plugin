/* Copyright © 2021 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Author: Yusuf Zainee <yzainee@redhat.com>
*/

package redhat.jenkins.plugins.crda.task;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.redhat.crda.backend.AnalysisReport;
import com.redhat.crda.backend.DependenciesSummary;
import com.redhat.crda.backend.VulnerabilitiesSummary;
import com.redhat.crda.impl.CrdaApi;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jakarta.ws.rs.client.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import redhat.jenkins.plugins.crda.action.CRDAAction;
import redhat.jenkins.plugins.crda.client.BackendOptions;
import redhat.jenkins.plugins.crda.client.DepAnalysisDTO;
import redhat.jenkins.plugins.crda.credentials.CRDAKey;
import redhat.jenkins.plugins.crda.service.PackageManagerService;
import redhat.jenkins.plugins.crda.utils.Config;
import redhat.jenkins.plugins.crda.utils.Utils;

import javax.servlet.ServletException;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;


public class CRDABuilder extends Builder implements SimpleBuildStep, Serializable {

    private String file;
    private String crdaKeyId;
    private String cliVersion;
    private boolean consentTelemetry = false;

    @DataBoundConstructor
    public CRDABuilder(String file, String crdaKeyId, String cliVersion, boolean consentTelemetry) {
        this.file = file;
        this.crdaKeyId = crdaKeyId;
        this.cliVersion = cliVersion;
        this.consentTelemetry = consentTelemetry;
    }

    public String getFile() {
        return file;
    }

    @DataBoundSetter
    public void setFile(String file) {
        this.file = file;
    }

    public String getCliVersion() {
        return cliVersion;
    }

    @DataBoundSetter
    public void setCliVersion(String cliVersion) {
        this.cliVersion = cliVersion;
    }

    public String getCrdaKeyId() {
        return crdaKeyId;
    }

    @DataBoundSetter
    public void setCrdaKeyId(String crdaKeyId) {
        this.crdaKeyId = crdaKeyId;
    }

    public boolean getConsentTelemetry() {
        return consentTelemetry;
    }

    @DataBoundSetter
    public void setConsentTelemetry(boolean consentTelemetry) {
        this.consentTelemetry = consentTelemetry;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        PrintStream logger = listener.getLogger();
        logger.println("----- CRDA Analysis Begins -----");
        String snykToken = Utils.getCRDACredential(this.getCrdaKeyId());

        logger.println("PATH: " + System.getenv("PATH"));
        logger.println("MVN: " + System.getenv("CRDA_MVN_PATH"));
        logger.println("SNYK: " + System.getenv("CRDA_SNYK_TOKEN"));
        logger.println("BACKEND: " + System.getenv("CRDA_BACKEND_URL"));

        Path manifestPath = Paths.get(getFile());
        if (manifestPath.getParent() == null) {
            manifestPath = Paths.get(workspace.child(getFile()).toURI());
        }

        // instantiate the Crda API implementation
        var crdaApi = new CrdaApi();
        // get a byte array future holding a html report
       // CompletableFuture<byte[]> htmlReport = crdaApi.stackAnalysisHtmlAsync(manifestPath.toString());
        // get a AnalysisReport future holding a deserialized report
        CompletableFuture<AnalysisReport> analysisReport = crdaApi.stackAnalysisAsync(manifestPath.toString());
        try {
            processReport(analysisReport, listener);
            logger.println("Click on the CRDA Stack Report icon to view the detailed report");
            logger.println("----- CRDA Analysis Ends -----");
           // run.addAction(new CRDAAction(snykToken, dto.getReport()));
        } catch (ExecutionException e) {
            e.printStackTrace();
        }


//        BackendOptions options = new BackendOptions();
//        options.setVerbose(true);
//        options.setSnykToken(snykToken);
//        Path manifestPath = Paths.get(getFile());
//        if (manifestPath.getParent() == null) {
//            manifestPath = Paths.get(workspace.child(getFile()).toURI());
//        }
//        PackageManagerService svc = redhat.jenkins.plugins.crda.service.PackageManagerServiceProvider.get(manifestPath.toFile());
//        logger.println("----- CRDA path: " + manifestPath);
//
//        try (Client client = ClientBuilder.newClient()) {
//            WebTarget target = client.target("http://localhost:8082/api/v3/dependency-analysis/" + svc.getName());
//            target = target.queryParam("verbose", options.isVerbose());
//            Invocation.Builder builder = target.request(MediaType.APPLICATION_JSON_TYPE);
//            builder = builder.header("crda-snyk-token", options.getSnykToken());
//            try (Response response = builder.post(Entity.entity(svc.generateSbom(manifestPath), MediaType.APPLICATION_JSON_TYPE))) {
//                DepAnalysisDTO dto = processResponse(response, listener);
//                processReport(dto.getReport(), listener);
//                saveHtmlReport(dto.getHtml(), listener, workspace);
//                logger.println("Click on the CRDA Stack Report icon to view the detailed report");
//                logger.println("----- CRDA Analysis Ends -----");
//                run.addAction(new CRDAAction(snykToken, dto.getReport()));
//            }
//        }

        //----------OLD JENKINS
//        try {
//            Response response = dependencyAnalysisService.createReport(svc.getName(), true,snykToken, svc.generateSbom(new File(this.getFile()).toPath()));
//            logger.println("----- CRDA response ");
//            logger.println(response.getStatus());
//            logger.println(response.getStringHeaders());
//            DepAnalysisDTO dto = processResponse(response);
//            processReport(dto.getReport(), listener);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }


//        try (Client client = ClientBuilder.newClient()) {
//            logger.println("----- CRDA client ");
//            WebTarget target = client.target("https://jsonplaceholder.typicode.com/todos/1");
//            Invocation.Builder builder = target.request(MediaType.APPLICATION_JSON_TYPE);
//            try (Response response = builder.get()) {
//                logger.println("----- CRDA response ");
//                logger.println(response.getStatus());
//                logger.println(response.readEntity(String.class));
//            }
//        }
        //   saveHtmlReport(dto.getHtml());

//    	String jenkinsPath = env.get("PATH");
//    	String crdaUuid = Utils.getCRDACredential(this.getCrdaKeyId());
//        String cliVersion = this.getCliVersion();
//        if (cliVersion == null) {
//        	cliVersion = Config.DEFAULT_CLI_VERSION;
//        	logger.println("No CRDA Cli version provided. Taking the default version " + cliVersion);
//        }
//        if (cliVersion.startsWith("v")) {
//        	cliVersion = cliVersion.replace("v", "");
//        	DefaultArtifactVersion cli = new DefaultArtifactVersion(cliVersion);
//    		DefaultArtifactVersion cliDef = new DefaultArtifactVersion(Config.DEFAULT_CLI_VERSION);
//
//    		if (cli.compareTo(cliDef) <0 ) {
//    			logger.println("Please consider upgrading the cli version to " + Config.DEFAULT_CLI_VERSION);
//    		}
//        }
//
//        String baseDir = Utils.doInstall(cliVersion, logger);
//        if (baseDir.equals("Failed")) {
//        	logger.println("Error during installation process");
//        	return;
//        }
//
//        String cmd = Config.CLI_CMD.replace("filepath", this.getFile());
//        cmd = baseDir + cmd;
//        logger.println("Contribution towards anonymous usage stats is set to " + this.getConsentTelemetry());
//        logger.println("Analysis Begins");
//        Map<String, String> envs = new HashMap<>();
//        envs.put("PATH", jenkinsPath);
//        envs.put("CRDA_KEY", crdaUuid);
//        envs.put("CONSENT_TELEMETRY", String.valueOf(this.getConsentTelemetry()));
//        String results = Utils.doExecute(cmd, logger, envs);
//
//        if (results.equals("") || results.equals("0") || ! Utils.isJSONValid(results)) {
//        	logger.println("Analysis returned no results.");
//        	return;
//        }
//        else {
//
//        	logger.println("....Analysis Summary....");
//        	JSONObject res = new JSONObject(results);
//	        Iterator<String> keys = res.keys();
//	        String key;
//	        while(keys.hasNext()) {
//	            key = keys.next();
//	            logger.println("\t" + key.replace("_", " ") + " : " + res.get(key));
//	        }
//
//	        logger.println("Click on the CRDA Stack Report icon to view the detailed report");
//	        logger.println("----- CRDA Analysis Ends -----");
//	        run.addAction(new CRDAAction(crdaUuid, res));
//        }
    }

    @Extension
    public static final class BuilderDescriptorImpl extends BuildStepDescriptor<Builder> {

        public BuilderDescriptorImpl() {
            load();
        }

        public FormValidation doCheckFile(@QueryParameter String file)
                throws IOException, ServletException {
            if (file.length() == 0) {
                return FormValidation.error(Messages.CRDABuilder_DescriptorImpl_errors_missingFileName());
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckCrdaKeyId(@QueryParameter String crdaKeyId)
                throws IOException, ServletException {
            int len = crdaKeyId.length();
            if (len == 0) {
                return FormValidation.error(Messages.CRDABuilder_DescriptorImpl_errors_missingUuid());
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckCliVersion(@QueryParameter String cliVersion)
                throws IOException, ServletException {
            int len = cliVersion.length();
            if (len == 0) {
                return FormValidation.ok();
            }
            if (!Utils.urlExists(Config.CLI_URL.replace("version", cliVersion))) {
                return FormValidation.error(Messages.CRDABuilder_DescriptorImpl_errors_incorrectCli());
            }

            DefaultArtifactVersion cli = new DefaultArtifactVersion(cliVersion.replace("v", ""));
            DefaultArtifactVersion cliCompatible = new DefaultArtifactVersion("0.2.0");
            if (cli.compareTo(cliCompatible) < 0) {
                return FormValidation.error(Messages.CRDABuilder_DescriptorImpl_errors_oldCli());
            }
            return FormValidation.ok();
        }

        @SuppressWarnings("deprecation")
        public ListBoxModel doFillCrdaKeyIdItems(@AncestorInPath Item item, @QueryParameter String crdaKeyId) {
            StandardListBoxModel model = new StandardListBoxModel();
            if (item == null) {

                Jenkins jenkins = Jenkins.getInstance();
                if (!jenkins.hasPermission(Jenkins.ADMINISTER)) {
                    return model.includeCurrentValue(crdaKeyId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return model.includeCurrentValue(crdaKeyId);
                }
            }
            return model.includeEmptyValue()
                    .includeAs(ACL.SYSTEM, item, CRDAKey.class)
                    .includeCurrentValue(crdaKeyId);
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.CRDABuilder_DescriptorImpl_DisplayName();
        }
    }

//    private DepAnalysisDTO processResponse(Response response, TaskListener listener) throws JsonProcessingException {
//        Map<String, String> params = response.getMediaType().getParameters();
//        ObjectMapper mapper = new ObjectMapper();
//        String body = response.readEntity(String.class);
//        try {
//            return new DepAnalysisDTO(mapper.readValue(body, AnalysisReport.class), body);
//        } catch (JsonProcessingException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//            return null;
//        }
//    }

    private void processReport(CompletableFuture<AnalysisReport> report, TaskListener listener) throws ExecutionException, InterruptedException {
        PrintStream logger = listener.getLogger();
        DependenciesSummary dependenciesSummary = report.get().getSummary().getDependencies();
        VulnerabilitiesSummary vulnerabilitiesSummary = report.get().getSummary().getVulnerabilities();
        logger.println("Summary");
        logger.println("  Dependencies");
        logger.println("    Scanned dependencies:    " + dependenciesSummary.getScanned());
        logger.println("    Transitive dependencies: " + dependenciesSummary.getScanned());
        logger.println("  Vulnerabilities");
        logger.println("    Total: " + vulnerabilitiesSummary.getTotal());
        logger.println("    Direct: " + vulnerabilitiesSummary.getDirect());
        logger.println("    Critical: " + vulnerabilitiesSummary.getCritical());
        logger.println("    High: " + vulnerabilitiesSummary.getHigh());
        logger.println("    Medium: " + vulnerabilitiesSummary.getMedium());
        logger.println("    Low: " + vulnerabilitiesSummary.getLow());
        logger.println("");
    }

    private void saveHtmlReport(String html, TaskListener listener, FilePath workspace) throws IOException, InterruptedException {
        PrintStream logger = listener.getLogger();
        logger.println("saveHtml");
        logger.println("Path: " + Paths.get(workspace.toURI()));
//        try {
           // Path temp = Files.createTempFile("dependency-analysis-report", ".html");
       //     Path temp = Files.createFile(Paths.get(workspace.toURI())+"/dependency-analysis-report.html");
           // Path reportPath = Files.createFile(Paths.get(workspace.toURI() + "/dependency-analysis-report.html"));
            Path reportPath = Paths.get("/Users/olgalavtar/temp/dependency-analysis-report.html");
            logger.println("reportPath: " + reportPath);
            BufferedWriter writer = Files.newBufferedWriter(reportPath);
            writer.append(html);
            writer.close();
            logger.println("You can find the detailed HTML report in: " + reportPath);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
    }

}