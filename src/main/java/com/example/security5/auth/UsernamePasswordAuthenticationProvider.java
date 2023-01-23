package com.example.security5.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private AuthenticationServerProxy proxy;

    /**
     * 객체가 인증된 건 아니고
     * 일단 넣어서 확인
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());

        // 프록시로 인증 서버를 호출하고,
        // SMS 를 통해 클라이언트에 OTP 전송
        proxy.sendAuth(username, password);

        // 인증 준비 ON, Authentication 객체 만들기
        return new UsernamePasswordAuthenticationToken(username, password);
    }

    // Authentication 의 UsernamePasswordAuthentication 형식을 지원하는 Provider 는 누굽니까?
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
    }
}
