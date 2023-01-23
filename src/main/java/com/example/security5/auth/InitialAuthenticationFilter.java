package com.example.security5.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class InitialAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    @Value("${jwt.signing.key}")
    private String signingKey;

    public InitialAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * 요청에 따른 올바른 인증을 요구하도록
     * doFilterInternal 재정의
     * -
     * 여기서는 모든 사용자가 같은 키를 이용하지만
     * 원래는 각각 다른 키를 이용해야함
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String username = request.getHeader("username");
        String password = request.getHeader("password");
        String code = request.getHeader("code");

        // HTTP 요청에 OTP 가 없으면, 사용자 이름과 암호로 인증해야 함
        if (code == null) {
            Authentication authentication = new UsernamePasswordAuthentication(username, password);
            // UsernamePasswordAuthentication 의 인스턴스로
            // AuthenticationManager 호출
            authenticationManager.authenticate(authentication);
        } else { // OTP 인증일 경우

            // OtpAuthentication 형식의 객체를 만들고,
            Authentication authentication = new OtpAuthentication(username, code);

            // OtpAuthentication 으로 보내 올바른 공급자(Provider)를 찾도록 함
            authentication = authenticationManager.authenticate(authentication);

            // 토큰 서명을 위한 키(대칭키)
            // 대칭키? -> 암호화, 복호화에 같은 키를 쓰는 경우 대칭키
            SecretKey key = Keys.hmacShaKeyFor(
                    signingKey.getBytes(StandardCharsets.UTF_8));

            // jwt 토큰을 만든다
            // 사용자 이름을 클레임 중 하나로 지정,
            // 서명은 키를 이용
            String jwt = Jwts.builder()
                    .setClaims(Map.of("username", username))
                    .signWith(key)
                    .compact();

            // 토큰을 HTTP 헤더 Authorization 에 추가함
            response.setHeader("Authorization", jwt);
        }
    }

    /**
     * /login 경로에만 해당 필터 적용
     * /login 이 아니면 해당 필터 동작 X
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/login");
    }
}
