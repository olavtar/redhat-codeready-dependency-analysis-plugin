package redhat.jenkins.plugins.crda.client;

import jdk.jfr.Registered;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
@Registered
public interface DependencyAnalysisService {

    public static final String SNYK_TOKEN_HEADER = "crda-snyk-token";
    public static final String VERBOSE_MODE_HEADER = "verbose";
    public static final String TEXT_VND_GRAPHVIZ_TYPE = "text/vnd.graphviz";
    public static final String MULTIPART_MIXED_TYPE = "multipart/mixed";

    @POST
    @Path("/{pkgManager}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MULTIPART_MIXED_TYPE)
    Response createReport(
            @PathParam("pkgManager") String pkgManager,
            @QueryParam(VERBOSE_MODE_HEADER) boolean verbose,
            @HeaderParam(SNYK_TOKEN_HEADER) String snykToken,
            String fileContent
    );

}
