package com.example.security5.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private AuthenticationServerProxy proxy;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String code = String.valueOf(authentication.getCredentials());

        boolean result = proxy.sendOtp(username, code);

        // OTP 가 맞나요? -> HTTP 응답에 토큰 실어보냄
        if (result) {
            return new OtpAuthentication(username, code);
        }
        // 아니라면 ? -> 예외
        throw new BadCredentialsException("BAD CREDENTIALS");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
