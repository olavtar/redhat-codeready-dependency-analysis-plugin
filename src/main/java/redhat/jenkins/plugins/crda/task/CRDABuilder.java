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
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import redhat.jenkins.plugins.crda.action.CRDAAction;
import redhat.jenkins.plugins.crda.credentials.CRDAKey;
import redhat.jenkins.plugins.crda.utils.Utils;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Serializable;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;


public class CRDABuilder extends Builder implements SimpleBuildStep, Serializable {

    private String file;
    private String crdaKeyId;
    private boolean consentTelemetry = false;

    @DataBoundConstructor
    public CRDABuilder(String file, String crdaKeyId, boolean consentTelemetry) {
        this.file = file;
        this.crdaKeyId = crdaKeyId;
        this.consentTelemetry = consentTelemetry;
    }

    public String getFile() {
        return file;
    }

    @DataBoundSetter
    public void setFile(String file) {
        this.file = file;
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

        logger.println("Build Path" + run.getRootDir().getPath());

        EnvVars envVars = run.getEnvironment(listener);
        logger.println("MVN: " + envVars.get("CRDA_MVN_PATH"));
//        logger.println("SNYK: " + envVars.get("CRDA_SNYK_TOKEN"));
        logger.println("BACKEND: " + envVars.get("CRDA_BACKEND_URL"));
        // setting system properties to pass to java-api
        System.setProperty("CRDA_MVN_PATH", envVars.get("CRDA_MVN_PATH"));
        System.setProperty("CRDA_SNYK_TOKEN", snykToken);
        System.setProperty("CRDA_BACKEND_URL", envVars.get("CRDA_BACKEND_URL"));
        System.setProperty("hudson.model.DirectoryBrowserSupport.CSP", "");

        // to get build directory
       // run.getRootDir().getPath();

        Path manifestPath = Paths.get(getFile());
        if (manifestPath.getParent() == null) {
            manifestPath = Paths.get(workspace.child(getFile()).toURI());
        }

        // instantiate the Crda API implementation
        var crdaApi = new CrdaApi();
        // get a byte array future holding a html report
        CompletableFuture<byte[]> htmlReport = crdaApi.stackAnalysisHtml(manifestPath.toString());

        // get a AnalysisReport future holding a deserialized report
        CompletableFuture<AnalysisReport> analysisReport = crdaApi.stackAnalysis(manifestPath.toString());
        try {
            processReport(analysisReport.get(), listener);
            saveHtmlReport(htmlReport.get(), listener, workspace);
            logger.println("Click on the CRDA Stack Report icon to view the detailed report");
            logger.println("----- CRDA Analysis Ends -----");
            run.addAction(new CRDAAction(snykToken, analysisReport.get(), workspace + "/dependency-analysis-report.html"));
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
    }

    @Extension
    public static final class BuilderDescriptorImpl extends BuildStepDescriptor<Builder> {

        public BuilderDescriptorImpl() {
            load();
        }

        public FormValidation doCheckFile(@QueryParameter String file) {
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

    private void processReport(AnalysisReport report, TaskListener listener) throws ExecutionException, InterruptedException {
        PrintStream logger = listener.getLogger();
        DependenciesSummary dependenciesSummary = report.getSummary().getDependencies();
        VulnerabilitiesSummary vulnerabilitiesSummary = report.getSummary().getVulnerabilities();
        logger.println("Summary");
        logger.println("  Dependencies");
        logger.println("    Scanned dependencies:    " + dependenciesSummary.getScanned());
        logger.println("    Transitive dependencies: " + dependenciesSummary.getTransitive());
        logger.println("  Vulnerabilities");
        logger.println("    Total: " + vulnerabilitiesSummary.getTotal());
        logger.println("    Direct: " + vulnerabilitiesSummary.getDirect());
        logger.println("    Critical: " + vulnerabilitiesSummary.getCritical());
        logger.println("    High: " + vulnerabilitiesSummary.getHigh());
        logger.println("    Medium: " + vulnerabilitiesSummary.getMedium());
        logger.println("    Low: " + vulnerabilitiesSummary.getLow());
        logger.println("");
    }

    private void saveHtmlReport(byte[] html, TaskListener listener, FilePath workspace) throws IOException, InterruptedException {
        PrintStream logger = listener.getLogger();
        File file = new File(workspace + "/dependency-analysis-report.html");
        FileUtils.writeByteArrayToFile(file, html);
        logger.println("You can find the detailed HTML report in your workspace.");
    }

}
