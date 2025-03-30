package com.suppleit.backend.controller;

import com.suppleit.backend.dto.ApiResponse;
import com.suppleit.backend.service.SocialLoginService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/social")
@RequiredArgsConstructor
@CrossOrigin(origins = {"https://suppleit.shop", "http://suppleit.shop", "http://localhost:3000", "http://localhost"}, allowCredentials = "true")
public class SocialLoginController {

    private final SocialLoginService socialLoginService;

    @GetMapping("/status")
    public ResponseEntity<?> getStatus() {
        // 간단한 상태 체크 엔드포인트
        return ResponseEntity.ok(Map.of("status", "online", "message", "Social login API is working"));
    }

    /**
     * 구글 로그인 API
     */
    @PostMapping("/login/google")
    public ResponseEntity<?> loginWithGoogle(@RequestBody Map<String, String> request) {
        try {
            String code = request.get("code");
            
            if (code == null || code.isEmpty()) {
                log.warn("구글 로그인 요청 - 인증 코드 없음");
                return ResponseEntity.badRequest().body(ApiResponse.error("인증 코드가 필요합니다"));
            }
            
            log.info("구글 로그인 요청 - 인증 코드 수신됨");
            
            // 먼저 간단한 응답을 반환하여 API 접근성 테스트
            if ("test".equals(code)) {
                log.info("구글 로그인 테스트 모드");
                Map<String, Object> testResponse = new HashMap<>();
                testResponse.put("accessToken", "test_token");
                testResponse.put("refreshToken", "test_refresh_token");
                testResponse.put("member", Map.of("email", "test@example.com", "memberRole", "USER"));
                
                return ResponseEntity.ok(ApiResponse.success("구글 로그인 테스트 성공", testResponse));
            }
            
            // 실제 구글 로그인 처리
            Map<String, Object> result = socialLoginService.getGoogleMember(code);
            log.info("구글 로그인 성공");
            return ResponseEntity.ok(ApiResponse.success("구글 로그인 성공", result));
            
        } catch (Exception e) {
            log.error("구글 로그인 오류: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("구글 로그인 처리 중 오류: " + e.getMessage()));
        }
    }

    /**
     * 네이버 로그인 API
     */
    @PostMapping("/login/naver")
    public ResponseEntity<?> loginWithNaver(@RequestBody Map<String, String> request) {
        try {
            String code = request.get("code");
            
            if (code == null || code.isEmpty()) {
                log.warn("네이버 로그인 요청 - 인증 코드 없음");
                return ResponseEntity.badRequest().body(ApiResponse.error("인증 코드가 필요합니다"));
            }
            
            log.info("네이버 로그인 요청 - 인증 코드 수신됨");
            
            // 먼저 간단한 응답을 반환하여 API 접근성 테스트
            if ("test".equals(code)) {
                log.info("네이버 로그인 테스트 모드");
                Map<String, Object> testResponse = new HashMap<>();
                testResponse.put("accessToken", "test_token");
                testResponse.put("refreshToken", "test_refresh_token");
                testResponse.put("member", Map.of("email", "test@example.com", "memberRole", "USER"));
                
                return ResponseEntity.ok(ApiResponse.success("네이버 로그인 테스트 성공", testResponse));
            }
            
            // 실제 네이버 로그인 처리
            Map<String, Object> result = socialLoginService.getNaverMember(code);
            log.info("네이버 로그인 성공");
            return ResponseEntity.ok(ApiResponse.success("네이버 로그인 성공", result));
            
        } catch (Exception e) {
            log.error("네이버 로그인 오류: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("네이버 로그인 처리 중 오류: " + e.getMessage()));
        }
    }
}