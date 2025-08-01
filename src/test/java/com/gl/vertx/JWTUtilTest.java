package com.gl.vertx;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.HttpException;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.MessageFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/*

User:
curl --header "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicm9sZXMiOlsidXNlciJdLCJpYXQiOjE3NTQwNzI4MDB9.X-guOamf0kSLDj-2D9_EvYoA0hY_EqYTZBbINJclszs" "http://localhost:8080/protected/"

Admin:
curl --header "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZXMiOlsiYWRtaW4iXSwiaWF0IjoxNzU0MDcyODAwfQ.MBGVBSQq7F9P1viPW9BDG_AwtiZFlan57A8iMEVE6N8" "http://localhost:8080/protected/admin/"

 */
public class JWTUtilTest {
    private static final String JWT_SECRET = "very long password+very long password+very long password+very long password+very long password";
    private static final String TOKEN_USER = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicm9sZXMiOlsidXNlciJdLCJpYXQiOjE3NTQwNzI4MDB9.X-guOamf0kSLDj-2D9_EvYoA0hY_EqYTZBbINJclszs";
    private static final String TOKEN_ADMIN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbInVzZXIiLCJhZG1pbiJdLCJpYXQiOjE3NTQwNzU0NzF9.2DLP7eZ1A_-r0-Tgeen1ltiQZ76FVXvPWwZeRQfB6IA";

    @Test
    void testGenerateTokens() {
        Vertx vertx = Vertx.vertx();
        String token = JWTUtil.generateToken(vertx, "user", List.of("user"), JWT_SECRET);
        System.out.println("Generated user token: " + token);

        token = JWTUtil.generateToken(vertx, "admin", List.of("user", "admin"), JWT_SECRET);
        System.out.println("Generated admin token: " + token);
    }

    @Test
    void testParseTokenAsync() {
        JWTUtil.parseTokenAsync(TOKEN_ADMIN, JWT_SECRET)
                .onSuccess(token -> {
                    System.out.println("Parsed token: " + token);
                    assertEquals("admin", token.user());
                    assertEquals(List.of("user", "admin"), token.roles());
                })
                .onFailure(Throwable::printStackTrace);
    }

    @Test
    void testParseToken() {
        JWTUtil.Token token = JWTUtil.parseToken(TOKEN_USER, JWT_SECRET);
        System.out.println("Parsed token: " + token);
        assertEquals("user", token.user());
        assertEquals(List.of("user"), token.roles());
    }

    @Test
    void testAccessToVerticle() {
        Vertx vertx = Vertx.vertx();

        vertx.deployVerticle(new TestVerticle())
                .onComplete(deployment -> {
                    if (deployment.succeeded()) {
                        System.out.println("Test verticle deployed successfully.");
                        testAccessToProtectedRoute(vertx);
                    } else {
                        System.err.println("Failed to deploy test verticle: " + deployment.cause());
                    }
                });
        try {
            Thread.sleep(5000);
        } catch (InterruptedException aE) {
        }
    }

    private void testAccessToProtectedRoute(Vertx vertx) {
        HttpClient client = HttpClient.newHttpClient();

        String path = "/";
        testPath(path, null, client, 200);
        testPath(path, null, client, 200);

        path = "/protected/";
        testPath(path, TOKEN_USER, client, 200);
        testPath(path, TOKEN_ADMIN, client, 200);

        path = "/protected/admin/";
        testPath(path, TOKEN_USER, client, 403);
        testPath(path, JWTUtilTest.TOKEN_ADMIN, client, 200);

        vertx.close();
    }

    private static void testPath(String path, String token, HttpClient client, int code) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("http://" + HOST + ":" + PORT + path));
        if (token != null)
            builder = builder .header("Authorization", "Bearer " + token);
        HttpRequest request = builder
                .GET()
                .build();

        HttpResponse<String> response = null;
        try {
            String user = "<NO USER>";
            if (token != null)
                user = token.equals(TOKEN_USER) ? "user" : "admin";
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(code, response.statusCode());
            System.out.println(MessageFormat.format("Response for path - \"{0}\" and user - \"{1}\": {2}", path, user, response.body()));
        } catch (Exception e) {
            fail(e);
        }
    }

    public static final int PORT = 8080;
    public static final String HOST = "localhost";

    static class TestVerticle extends AbstractVerticle {
        @Override
        public void start(Promise<Void> startPromise) {
            Router router = Router.router(vertx);

            cretaeFailurehandler(router);

            router.route().handler(BodyHandler.create());

            JWTUtil.applyAuth(vertx, router, "/protected/*", JWT_SECRET);

            router.get("/protected/admin/*").handler(JWTUtil.guardedHandler("admin", ctx -> {
                ctx.response().end("Admin protected route accessed");
            }));

            router.get("/protected/*").handler(JWTUtil.guardedHandler("user", ctx -> {
                ctx.response().end("User protected route accessed");
            }));

            router.get("/*").handler(ctx -> {
                ctx.response().end("Public route accessed");
            });

            createHttpServer(startPromise, router);
        }

        private void createHttpServer(Promise<Void> startPromise, Router router) {
            vertx.createHttpServer()
                    .requestHandler(router)
                    .listen(8080, HOST)
                    .onComplete(http -> {
                        if (http.succeeded()) {
                            System.out.println("Test verticle started on port: " + PORT);
                            startPromise.complete();
                        } else {
                            System.out.println("Test verticle failed to start on port: " + PORT);
                            startPromise.fail(http.cause());
                        }
                    });
        }

        private static void cretaeFailurehandler(Router router) {
            router.route().failureHandler(ctx -> {
                Throwable failure = ctx.failure();
                if (failure instanceof HttpException) {
                    HttpException httpEx = (HttpException) failure;
                    if (httpEx.getStatusCode() == 401) {
                        ctx.response()
                                .setStatusCode(401)
                                .end("Unauthorized: " + httpEx.getMessage());
                        return;
                    }
                }
                // For other errors, you can handle or propagate
                ctx.next();
            });
        }
    }
}
