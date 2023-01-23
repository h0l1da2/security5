package com.example.security5.auth;

import com.example.security5.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class AuthenticationServerProxy {

    /**
     * RestTemplate 을 이용해
     * REST 엔드 포인트를 노출하는
     * 일반적인 방법
     */
    @Autowired
    private RestTemplate restTemplate;

    @Value("${auth.server.base.url}")
    private String baseUrl;

    /**
     * 인증을 위해 요청과 암호가 필요한 메서드
     */
    public void sendAuth(String username, String password) {

        String url = baseUrl + "/user/auth";

        User body = new User();
        body.setUsername(username);
        body.setPassword(password);

        HttpEntity<User> request = new HttpEntity<>(body);

        restTemplate.postForEntity(url, request, Void.class);
    }

    /**
     * 인증을 위해 OTP 코드가 필요한 메서드
     */
    public boolean sendOtp(String username, String code) {
        String url = baseUrl + "/otp/check";

        User body = new User();
        body.setUsername(username);
        body.setCode(code);

        HttpEntity<User> request = new HttpEntity<>(body);

        ResponseEntity<Void> response = restTemplate.postForEntity(url, request, Void.class);

        // HTTP 응답 상태가 200이면 true, 아니면 false
        return response
                .getStatusCode()
                .equals(HttpStatus.OK);
    }
}
