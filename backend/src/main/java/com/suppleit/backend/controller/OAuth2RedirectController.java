package com.suppleit.backend.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.suppleit.backend.service.SocialLoginService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;

@RestController
@RequestMapping("/login/oauth2/code")
@RequiredArgsConstructor
@Slf4j
public class OAuth2RedirectController {

    private final SocialLoginService socialLoginService;

    @GetMapping("/google")
    public RedirectView processGoogleCallback(@RequestParam("code") String code, @RequestParam(value = "state", required = false) String state) {
        try {
            log.info("구글 OAuth 콜백 처리 - 코드: {}, 상태: {}", code.substring(0, Math.min(10, code.length())) + "...", state);
            Map<String, Object> tokenResponse = socialLoginService.getGoogleMember(code);
            
            // 프론트엔드로 리디렉션 (accessToken, refreshToken 포함)
            String redirectUrl = (String) tokenResponse.getOrDefault("redirectUrl", "/oauth2/success");
            
            log.info("구글 로그인 성공 - 리디렉션: {}", redirectUrl);
            return new RedirectView(redirectUrl);
        } catch (Exception e) {
            log.error("구글 OAuth 콜백 처리 중 오류: {}", e.getMessage(), e);
            return new RedirectView("/login?error=google_oauth_failed&message=" + e.getMessage());
        }
    }

    @GetMapping("/naver")
    public RedirectView processNaverCallback(@RequestParam("code") String code, @RequestParam(value = "state", required = false) String state) {
        try {
            log.info("네이버 OAuth 콜백 처리 - 코드: {}, 상태: {}", code.substring(0, Math.min(10, code.length())) + "...", state);
            Map<String, Object> tokenResponse = socialLoginService.getNaverMember(code);
            
            // 프론트엔드로 리디렉션 (accessToken, refreshToken 포함)
            String redirectUrl = (String) tokenResponse.getOrDefault("redirectUrl", "/oauth2/success");
            
            log.info("네이버 로그인 성공 - 리디렉션: {}", redirectUrl);
            return new RedirectView(redirectUrl);
        } catch (Exception e) {
            log.error("네이버 OAuth 콜백 처리 중 오류: {}", e.getMessage(), e);
            return new RedirectView("/login?error=naver_oauth_failed&message=" + e.getMessage());
        }
    }
}