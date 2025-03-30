package com.suppleit.backend.config;

import com.suppleit.backend.security.jwt.JwtFilter;
import com.suppleit.backend.security.jwt.JwtTokenProvider;
import com.suppleit.backend.security.jwt.JwtTokenBlacklistService;
import com.suppleit.backend.service.MemberDetailsService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberDetailsService memberDetailsService;
    private final JwtTokenBlacklistService tokenBlacklistService;

    // 비밀번호 암호화 (BCrypt)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 보안 필터 체인 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .authorizeHttpRequests(requests -> requests
                // 관리자 전용 경로
                .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                
                // OAuth2 관련 경로
                .requestMatchers("/api/auth/oauth2/**").permitAll()
                .requestMatchers("/login/oauth2/code/**").permitAll()
                .requestMatchers("/oauth2/authorization/**").permitAll()
                .requestMatchers("/oauth2/success").permitAll()
                
                // 소셜 로그인 API
                .requestMatchers("/api/social/**").permitAll()
                .requestMatchers("/api/social/login/**").permitAll()
                
                // 인증이 필요한 API
                .requestMatchers("/api/member/auth/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_USER")
                .requestMatchers("/api/logout").authenticated()
                
                // 공개 API
                .requestMatchers("/api/member/verify-email").permitAll()
                .requestMatchers("/api/auth/refresh").permitAll()
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/reviews/**").permitAll()
                .requestMatchers("/api/notice/image/**").permitAll()
                .requestMatchers("/api/notice/attachment/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/notice/**").permitAll()
                
                // 관리자 권한이 필요한 공지사항 관리
                .requestMatchers(HttpMethod.POST, "/api/notice").hasAuthority("ROLE_ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/notice/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/notice/**").hasAuthority("ROLE_ADMIN")
                
                // 그 외 모든 요청은 허용
                .anyRequest().permitAll()
            )
            .addFilterBefore(jwtFilter(), UsernamePasswordAuthenticationFilter.class)
            .logout(logout -> logout
                .logoutUrl("/api/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.setStatus(200);
                    response.getWriter().write("{\"message\": \"Logout successful\"}");
                })
            );
            
        return http.build();
    }

    // JWT 필터 등록
    @Bean
    public JwtFilter jwtFilter() {
        return new JwtFilter(jwtTokenProvider, memberDetailsService, tokenBlacklistService);
    }

    // CORS 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // 모든 출처 허용 (프로덕션에서는 제한하는 것이 좋음)
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        
        // 허용할 HTTP 메서드
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // 허용할 헤더
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        
        // 인증 정보 허용
        configuration.setAllowCredentials(true);
        
        // 노출할 헤더
        configuration.setExposedHeaders(Arrays.asList("Authorization"));
        
        // 설정을 모든 경로에 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}