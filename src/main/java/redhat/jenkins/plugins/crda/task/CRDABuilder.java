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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.ecosystemappeng.crda.api.AnalysisReport;
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
import redhat.jenkins.plugins.crda.client.BackendOptions;
import redhat.jenkins.plugins.crda.client.DepAnalysisDTO;
import redhat.jenkins.plugins.crda.credentials.CRDAKey;
import redhat.jenkins.plugins.crda.service.PackageManagerService;
import redhat.jenkins.plugins.crda.utils.Config;
import redhat.jenkins.plugins.crda.utils.Utils;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Map;


public class CRDABuilder extends Builder implements SimpleBuildStep {

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
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener) throws IOException {
        PrintStream logger = listener.getLogger();
        logger.println("----- CRDA Analysis Begins -----");
        logger.println("----- CRDA Analysis New Backend CRDABuilder -----");

        BackendOptions options = new BackendOptions();
        options.setVerbose(true);
        options.setSnykToken("a8e5da4e-e5fc-482b-a0ce-e848d6932a05");
        //options.setSnykToken("--snyk-token");
        logger.println("----- CRDA options ");
        PackageManagerService svc = redhat.jenkins.plugins.crda.service.PackageManagerServiceProvider.get(new File(this.getFile()));
        logger.println("----- CRDA svc: " + svc.getName());
        logger.println("----- CRDA path: " + new File(this.getFile()).toPath());

        try (Client client = ClientBuilder.newClient()) {
            logger.println("----- CRDA client ");
            WebTarget target = client.target("http://crda-backend-dev-crda.apps.sssc-cl01.appeng.rhecoeng.com/api/v3/dependency-analysis/");
            target = target.path(svc.getName());
            logger.println("----- CRDA target: " + target.path(svc.getName()));
            target = target.queryParam("verbose", options.isVerbose());
            Invocation.Builder builder = target.request(MediaType.APPLICATION_JSON_TYPE);
            builder = builder.header("crda-snyk-token", options.getSnykToken());
//            String sbom = svc.generateSbom(new File(this.getFile()).toPath());
//            logger.println("----- CRDA SBOM generated: " + sbom);
            try (Response response = builder.post(Entity.entity(svc.generateSbom(new File(this.getFile()).toPath()),MediaType.APPLICATION_JSON)) ) {
                logger.println("----- CRDA response ");
                logger.println(response.getStatus());
                logger.println(response.getStringHeaders());
                DepAnalysisDTO dto = processResponse(response);
                processReport(dto.getReport(), listener);
            }
        }
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

    private DepAnalysisDTO processResponse(Response response) {
        Map<String, String> params = response.getMediaType().getParameters();
        ObjectMapper mapper = new ObjectMapper();
        String boundary = params.get("boundary");
        if (boundary == null) {
            System.out.println("Missing response boundary");
            return null;
        }
        String body = response.readEntity(String.class);
        String[] lines = body.split("\n");
        int cursor = 0;
        while (!lines[cursor].contains(boundary)) {
            cursor++;
        }
        cursor++;
        while (lines[cursor].startsWith("Content-") || lines[cursor].isBlank()) {
            cursor++;
        }
        StringBuffer json = new StringBuffer();
        while (!lines[cursor].contains(boundary)) {
            json.append(lines[cursor++]);
        }
        while (!lines[cursor].contains(boundary)) {
            cursor++;
        }
        cursor++;
        while (lines[cursor].startsWith("Content-") || lines[cursor].isBlank()) {
            cursor++;
        }
        StringBuffer html = new StringBuffer();
        while (!lines[cursor].contains(boundary)) {
            html.append(lines[cursor++]);
        }
        try {
            return new DepAnalysisDTO(mapper.readValue(json.toString(), AnalysisReport.class), html.toString());
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    private void processReport(AnalysisReport report, TaskListener listener) {
        PrintStream logger = listener.getLogger();
        logger.println("Summary");
        logger.println("  Dependencies");
        logger.println("    Scanned dependencies:    " + report.summary().dependencies().scanned());
        logger.println("    Transitive dependencies: " + report.summary().dependencies().transitive());
        logger.println("  Vulnerabilities");
        logger.println("    Total: " + report.summary().vulnerabilities().total());
        logger.println("    Direct: " + report.summary().vulnerabilities().direct());
        logger.println("    Critical: " + report.summary().vulnerabilities().critical());
        logger.println("    High: " + report.summary().vulnerabilities().high());
        logger.println("    Medium: " + report.summary().vulnerabilities().medium());
        logger.println("    Low: " + report.summary().vulnerabilities().low());
        logger.println("");
    }

//    private void saveHtmlReport(String html) {
//        try {
//            Path temp = Files.createTempFile("dependency-analysis-report", ".html");
//            BufferedWriter writer = Files.newBufferedWriter(temp);
//            writer.append(html);
//            writer.close();
//            System.out.println("You can find the detailed HTML report in: " + temp);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//    }

}