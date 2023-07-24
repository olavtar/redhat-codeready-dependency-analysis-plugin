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

package redhat.jenkins.plugins.crda.action;

import com.redhat.exhort.api.AnalysisReport;
import hudson.model.Run;
import jenkins.model.RunAction2;

public class CRDAAction implements RunAction2 {

    private transient Run run;
    private String uuid;
    private AnalysisReport report;
    private String url;

    public String getUrl() {
        return url;
    }

    @Override
    public void onAttached(Run<?, ?> run) {
        this.run = run;
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run;
    }

    public Run getRun() {
        return run;
    }

    public CRDAAction(String uuid, AnalysisReport report, String url) {
        this.uuid = uuid;
        this.report = report;
        this.url = url;

    }

    public String getUuid() {
            return uuid;
    }

    public AnalysisReport getReport() {
        return report;
	}

    @Override
    public String getIconFileName() {
        return "/plugin/redhat-codeready-dependency-analysis/icons/redhat.png";
    }

    @Override
    public String getDisplayName() {
        return "CRDA Stack Report";
    }

    @Override
    public String getUrlName() {
        return "stack_report";
    }
}