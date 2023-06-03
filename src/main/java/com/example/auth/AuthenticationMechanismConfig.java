package com.example.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.security.enterprise.authentication.mechanism.http.CustomFormAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.LoginToContinue;

@CustomFormAuthenticationMechanismDefinition(
    loginToContinue = @LoginToContinue(
        loginPage="/msg/login",
        errorPage="/msg/login",
        useForwardToLogin = false
    )
)
@ApplicationScoped
public class AuthenticationMechanismConfig {
}