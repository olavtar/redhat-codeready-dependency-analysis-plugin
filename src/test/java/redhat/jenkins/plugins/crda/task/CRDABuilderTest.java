package redhat.jenkins.plugins.crda.task;

import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.JenkinsRule;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import redhat.jenkins.plugins.crda.utils.Utils;


@RunWith(PowerMockRunner.class)
@PrepareForTest({Utils.class, CRDABuilder.class})
@PowerMockIgnore({"javax.net.ssl.*", "javax.crypto.*", "jdk.internal.reflect.*", "javax.management.", "com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "org.w3c.dom.*", "com.sun.org.apache.xalan.*", "javax.activation.*"})


public class CRDABuilderTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    public String retStr = "{'total_scanned_dependencies': 0, 'total_scanned_transitives': 0, 'total_vulnerabilities': 0,"
    		+ "'direct_vulnerable_dependencies': 0,"
    		+ "'low_vulnerabilities': 0, 'medium_vulnerabilities': 0, 'high_vulnerabilities': 0, 'critical_vulnerabilities': 0}";

    @Test
    public void testCRDATask() throws Exception {
        FreeStyleProject project = jenkins.createFreeStyleProject();
        CRDABuilder crdb = new CRDABuilder("/tmp/pom.xml", "ede6d550-b75e-4a2e-bfac-22222e77b48b",false);
        CRDABuilder mockObj = PowerMockito.mock(crdb.getClass());
        PowerMockito.mockStatic(Utils.class);
        PowerMockito.when(Utils.getCRDACredential("ede6d550-b75e-4a2e-bfac-22222e77b48b")).thenReturn("1234");
        PowerMockito.when(Utils.isJSONValid(retStr)).thenReturn(true);
        project.getEnvironment(mockObj.)
        project.getBuildersList().add(crdb);
        FreeStyleBuild build = jenkins.buildAndAssertSuccess(project);
        jenkins.assertLogContains("----- CRDA Analysis Begins -----", build);
        jenkins.assertLogContains("Click on the CRDA Stack Report icon to view the detailed report", build);
        jenkins.assertLogContains("----- CRDA Analysis Ends -----", build);
    }
}