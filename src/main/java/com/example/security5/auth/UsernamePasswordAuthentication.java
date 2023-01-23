package com.example.security5.auth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * 사용자 이름과 암호를 이용한 인증
 */
public class UsernamePasswordAuthentication extends UsernamePasswordAuthenticationToken {

    /**
     * 인증 객체가 인증이 안 된 상태로 유지
     * 처음 Authentication 객체를 생성할 때 만든다
     * 아직 인증되지 않은 Authentication
     */
    public UsernamePasswordAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }

    /**
     * Authentication 객체가 요청을 인증할 때 사용
     * 인증 된 객체가 된다
     */
    public UsernamePasswordAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
