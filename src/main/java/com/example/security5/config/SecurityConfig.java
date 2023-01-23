package com.example.security5.config;

import com.example.security5.auth.InitialAuthenticationFilter;
import com.example.security5.auth.JwtAuthenticationFilter;
import com.example.security5.auth.OtpAuthenticationProvider;
import com.example.security5.auth.UsernamePasswordAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final OtpAuthenticationProvider otpAuthenticationProvider;
    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    public SecurityConfig(OtpAuthenticationProvider otpAuthenticationProvider, UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider) {
        this.otpAuthenticationProvider = otpAuthenticationProvider;
        this.usernamePasswordAuthenticationProvider = usernamePasswordAuthenticationProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(otpAuthenticationProvider)
                .authenticationProvider(usernamePasswordAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // csrf 보호 비활성화
        http.csrf().disable()
                // 커스텀 필터 추가
                .addFilterAt(new InitialAuthenticationFilter(authenticationManager()), BasicAuthenticationFilter.class)
                .addFilterAfter(new JwtAuthenticationFilter(), BasicAuthenticationFilter.class)

                // 모든 요청은 인증받은 사람만 진입 가능
                .authorizeRequests()
                .anyRequest().authenticated();
    }

    // 필터에서 자동 주입할 수 있게 하려고
    // 스프링 컨텍스트에 빈으로 추가
    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
