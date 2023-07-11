//package redhat.jenkins.plugins.crda.step;
//
//import hudson.model.Label;
//import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
//import org.jenkinsci.plugins.workflow.job.WorkflowJob;
//import org.jenkinsci.plugins.workflow.job.WorkflowRun;
//import org.junit.Rule;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.jvnet.hudson.test.JenkinsRule;
//import org.powermock.api.mockito.PowerMockito;
//import org.powermock.core.classloader.annotations.PowerMockIgnore;
//import org.powermock.core.classloader.annotations.PrepareForTest;
//import org.powermock.modules.junit4.PowerMockRunner;
//import redhat.jenkins.plugins.crda.utils.Utils;
//
//@RunWith(PowerMockRunner.class)
//@PrepareForTest({Utils.class, CRDAStep.class})
//@PowerMockIgnore({"javax.net.ssl.*", "javax.crypto.*", "jdk.internal.reflect.*", "javax.management.", "com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "org.w3c.dom.*", "com.sun.org.apache.xalan.*", "javax.activation.*"})
//public class CRDAStepTest {
//
//	@Rule
//    public JenkinsRule jenkins = new JenkinsRule();
//
////    public String retStr = "{'total_scanned_dependencies': 0, 'total_scanned_transitives': 0, 'total_vulnerabilities': 0,"
////    		+ "'publicly_available_vulnerabilities': 0, 'vulnerabilities_unique_to_synk': 0, 'direct_vulnerable_dependencies': 0,"
////    		+ "'low_vulnerabilities': 0, 'medium_vulnerabilities': 0, 'high_vulnerabilities': 0, 'critical_vulnerabilities': 0,"
////    		+ "'report_link': 'http://www.example.com'}";
//
//    public String retStr = "{'total_scanned_dependencies': 0, 'total_scanned_transitives': 0, 'total_vulnerabilities': 0,"
//            + "'direct_vulnerable_dependencies': 0,"
//            + "'low_vulnerabilities': 0, 'medium_vulnerabilities': 0, 'high_vulnerabilities': 0, 'critical_vulnerabilities': 0}";
//
//
//    @Test
//    public void testCRDAStep() throws Exception {
//        String agentLabel = "my-agent";
//        jenkins.createOnlineSlave(Label.get(agentLabel));
//        WorkflowJob job = jenkins.createProject(WorkflowJob.class, "test-scripted-pipeline");
//        PowerMockito.mockStatic(Utils.class);
//        PowerMockito.when(Utils.getCRDACredential("ede6d550-b75e-4a2e-bfac-22222e77b48b")).thenReturn("1234");
//        PowerMockito.when(Utils.isJSONValid(retStr)).thenReturn(true);
//        String pipelineScript
//                = "node {\n"
//                + "  String msg = crdaAnalysis file:'/tmp/package.json', crdaKeyId:'ede6d550-b75e-4a2e-bfac-22222e77b48b', consentTelemetry:false\n"
//                + "    echo msg \n"
//                + "}";
//        job.setDefinition(new CpsFlowDefinition(pipelineScript, true));
//        WorkflowRun build = jenkins.assertBuildStatusSuccess(job.scheduleBuild2(0));
//        jenkins.assertLogContains("----- CRDA Analysis Begins -----", build);
//        jenkins.assertLogContains("Click on the CRDA Stack Report icon to view the detailed report", build);
//        jenkins.assertLogContains("----- CRDA Analysis Ends -----", build);
//    }
//}
