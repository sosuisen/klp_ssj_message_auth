package com.example.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.security.enterprise.authentication.mechanism.http.FormAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.LoginToContinue;

/*
 * 要認証のパスへのアクセスは、
 * loginPageに指定されたパスへのアクセスへ読み変えられます。
 * つまり下の場合 @GET @Path("login")のメソッドが呼ばれます。
 * 
 * この呼び出しは、useForwardToLoginがfalseのときはredirectで、
 * trueのときはforwardで行われます。デフォルトはtrue。
 * いずれも@GET @Path("login")のメソッドが呼ばれますが、
 * forwardの場合、URLは元のパス（例えば/msg/list）のままで
 * redirectの場合、URLは/msg/login に変わります。通常はtrueで良いです。
 */
@FormAuthenticationMechanismDefinition(
    loginToContinue = @LoginToContinue(
        loginPage="/msg/login",
        errorPage="/msg/login?error=invalid_user",
        useForwardToLogin = true
    )
)
@ApplicationScoped
public class AuthenticationMechanismConfig {
}