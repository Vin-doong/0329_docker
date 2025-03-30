package com.suppleit.backend.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.util.UUID;

/**
 * 소셜 로그인 인증 시작 컨트롤러
 * 프론트엔드에서 백엔드 API를 호출하여 OAuth 흐름을 시작하도록 함
 */
@Slf4j
@RestController
@RequestMapping("/api/auth/oauth2")
@RequiredArgsConstructor
public class OAuth2AuthController {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String googleRedirectUri;

    @Value("${spring.security.oauth2.client.registration.naver.redirect-uri}")
    private String naverRedirectUri;

    /**
     * 구글 OAuth 인증 시작
     * 프론트엔드에서 /api/auth/oauth2/google을 호출하면 구글 로그인 페이지로 리디렉션
     */
    @GetMapping("/google")
    public RedirectView startGoogleAuth() {
        log.info("구글 OAuth 인증 시작");
        String state = UUID.randomUUID().toString();
        
        String authUrl = "https://accounts.google.com/o/oauth2/auth" +
                "?client_id=" + googleClientId +
                "&redirect_uri=" + googleRedirectUri +
                "&response_type=code" +
                "&scope=email%20profile" +
                "&state=" + state;
        
        log.info("구글 인증 URL: {}", authUrl);
        return new RedirectView(authUrl);
    }

    /**
     * 네이버 OAuth 인증 시작
     * 프론트엔드에서 /api/auth/oauth2/naver를 호출하면 네이버 로그인 페이지로 리디렉션
     */
    @GetMapping("/naver")
    public RedirectView startNaverAuth() {
        log.info("네이버 OAuth 인증 시작");
        String state = UUID.randomUUID().toString();
        
        String authUrl = "https://nid.naver.com/oauth2.0/authorize" +
                "?client_id=" + naverClientId +
                "&redirect_uri=" + naverRedirectUri +
                "&response_type=code" +
                "&state=" + state;
        
        log.info("네이버 인증 URL: {}", authUrl);
        return new RedirectView(authUrl);
    }
}