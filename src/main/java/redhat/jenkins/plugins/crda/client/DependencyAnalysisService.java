package redhat.jenkins.plugins.crda.client;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jdk.jfr.Registered;

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
