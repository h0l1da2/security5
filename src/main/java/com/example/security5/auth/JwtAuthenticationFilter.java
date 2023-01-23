package com.example.security5.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * /login 외에
 * 다른 모든 경로에 대한 요청을 처리하는 필터
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.signing.key}")
    private String signingKey;


    /**
     * 헤더에서 토큰을 확인하고
     * 복호화를 시도,
     * 유저의 권한을 가져와서 authentication 인증
     * 인증된 Authentication 을
     * SecurityContext 에 집어 넣음
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = request.getHeader("Authorization");

        SecretKey key = Keys.hmacShaKeyFor(
                signingKey.getBytes(StandardCharsets.UTF_8));

        // 토큰을 가져와서 서명 검증,
        // 유효하지 않은 서명이면 예외 발생
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJwt(jwt)
                .getBody();

        String username = String.valueOf(claims.get("username"));

        // SecurityContext 에 추가할 Authentication 인스턴스 만들기
        // 여기서는 권한과 유저네임을 넣었다
        GrantedAuthority authority = new SimpleGrantedAuthority("user");
        UsernamePasswordAuthentication auth =
                new UsernamePasswordAuthentication(username, null, List.of(authority));

        // SecurityContext 에 Authentication 객체 추가
        SecurityContextHolder.getContext()
                .setAuthentication(auth);

        // 필터 체인 다음 필터 호출
        filterChain.doFilter(request, response);
    }

    // /login 경로 요청이면 동작하지 않는 필터로 설정
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath()
                .equals("/login");
    }
}