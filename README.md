# JWT Utility for Vert.x
The JWTUtil class provides utility methods for working with JSON Web Tokens (JWT) in Vert.x applications. It simplifies the process of creating, signing, and verifying JWTs, applying JWT authentication and authorization to handlers, making it easier to implement authentication and authorization mechanisms.

## Working with Tokens

To create a JWT token, you need to have the username, roles and a long password or a string with a key in PEM format. The password is used to sign the token. The token can be created using the `createToken` method:

```java
String token = JWTUtil.createToken(vertx, "john-doe", List.of("user", "admin"), <SECRET KEY OR PASSWORD>);
```

To parse a token, you can use the `parseTokenAsync` method, which returns a `Future<JsonObject>` containing the payload of the token:
```java
JWTUtil.parseTokenAsync(TOKEN_ADMIN, JWT_SECRET)
        .onSuccess(token -> {
            System.out.println("Parsed token: " + token);
        })
        .onFailure(Throwable::printStackTrace);
```

Or you can use synchronous `parseToken` method. **Do NOT call this method on Vert.x event loop threads.**
```java
String token = "your.jwt.token";
Token token = JWTUtil.parseToken(vertx, token, <SECRET KEY OR PASSWORD>);
```
To apply JWT authentication and authorization to a Vert.x router, you can use the `applyAuth(...)` method. This method takes a Vert.x instance, a router, a path pattern, and a secret key or password. It sets up the necessary handlers to authenticate requests using JWT tokens. For example, to allow access to all routes under _"/protected/*"_ only for authenticated users, you can do the following:

```java
class TestVerticle extends AbstractVerticle {
    @Override
    public void start(Promise<Void> startPromise) {
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        JWTUtil.applyAuth(vertx, router, "/protected/*", <SECRET KEY OR PASSWORD>);
        
        // add all other routes and initializations
    }
}
```

To protect specific routes, you can use the `guardedHandler` method. This method takes a role and a handler, and it will only allow access to the route if the JWT token contains the specified role. For example, to allow access for _"/protected/admin/*"_ only to users with the "admin" role, you can do the following:

```java
router.get("/protected/admin/*").handler(JWTUtil.guardedHandler("admin", ctx -> {
    ctx.response().end("Admin protected route accessed");
}));
```

## Adding to Your Build
To add JWTUtil to your build: copy com.gl.vertx.JWTUtil.java to your project and add 
it to your classpath.

## License
The JWTUtil is licensed under the terms of the [MIT License](https://opensource.org/license/mit).
