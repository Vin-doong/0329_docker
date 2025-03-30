package com.suppleit.backend.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.suppleit.backend.constants.MemberRole;
import com.suppleit.backend.constants.SocialType;
import com.suppleit.backend.dto.MemberDto;
import com.suppleit.backend.mapper.MemberMapper;
import com.suppleit.backend.model.Member;
import com.suppleit.backend.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SocialLoginService {

    private final MemberMapper memberMapper;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;
    
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;
    
    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;
    
    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String naverClientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String googleRedirectUri;

    @Value("${spring.security.oauth2.client.registration.naver.redirect-uri}")
    private String naverRedirectUri;

    @Value("${app.frontend.url:http://localhost}")
    private String frontendUrl;

    @Value("${app.frontend.oauth-success-redirect:/oauth2/success}")
    private String oauthSuccessRedirectPath;

    // 구글 로그인
    public Map<String, Object> getGoogleMember(String code) {
        try {
            log.info("구글 인증 코드 처리 시작: {}", code);
            
            // 1. 인증 코드로 액세스 토큰 요청
            HttpHeaders tokenHeaders = new HttpHeaders();
            tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> tokenRequest = new LinkedMultiValueMap<>();
            tokenRequest.add("code", code);
            tokenRequest.add("client_id", googleClientId);
            tokenRequest.add("client_secret", googleClientSecret);
            tokenRequest.add("redirect_uri", googleRedirectUri);
            tokenRequest.add("grant_type", "authorization_code");

            log.info("구글 클라이언트 ID: {}", googleClientId);
            log.info("구글 리디렉션 URI: {}", googleRedirectUri);
            
            HttpEntity<MultiValueMap<String, String>> tokenEntity = new HttpEntity<>(tokenRequest, tokenHeaders);
            
            log.info("구글 토큰 요청: {}", tokenRequest);
            
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    "https://oauth2.googleapis.com/token",
                    HttpMethod.POST,
                    tokenEntity,
                    String.class
            );
            
            log.info("구글 토큰 응답: {}", tokenResponse.getBody());
            
            // 2. 응답에서 액세스 토큰 추출
            JsonNode tokenJson = objectMapper.readTree(tokenResponse.getBody());
            String accessToken = tokenJson.get("access_token").asText();
            
            log.info("구글 액세스 토큰 획득: {}", accessToken);
            
            // 3. 사용자 정보 요청 처리
            return getGoogleUserInfo(accessToken);
        } catch (Exception e) {
            log.error("구글 로그인 처리 중 오류 발생: {}", e.getMessage(), e);
            throw new RuntimeException("구글 로그인 처리 중 오류 발생: " + e.getMessage(), e);
        }
    }
    
    // 구글 사용자 정보 요청
    private Map<String, Object> getGoogleUserInfo(String accessToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);

            HttpEntity<?> entity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            JsonNode jsonNode = objectMapper.readTree(response.getBody());
            log.info("구글 API 응답: {}", jsonNode.toString());

            String email = jsonNode.has("email") ? jsonNode.get("email").asText() : null;
            String nickname = jsonNode.has("name") ? jsonNode.get("name").asText() : "구글 사용자";

            if (email == null || email.isEmpty()) {
                throw new IllegalArgumentException("구글 계정에서 이메일을 제공하지 않았습니다. 이메일 제공에 동의해주세요.");
            }

            return processSocialLogin(email, nickname, SocialType.GOOGLE);
        } catch (Exception e) {
            log.error("구글 사용자 정보 조회 중 오류: {}", e.getMessage());
            throw new RuntimeException("구글 사용자 정보 조회 중 오류 발생: " + e.getMessage(), e);
        }
    }

    // 네이버 로그인
    public Map<String, Object> getNaverMember(String code) {
        try {
            log.info("네이버 인증 코드 처리 시작 - 코드: {}", code);
            
            // 1. 인증 코드로 액세스 토큰 요청
            HttpHeaders tokenHeaders = new HttpHeaders();
            tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> tokenRequest = new LinkedMultiValueMap<>();
            tokenRequest.add("grant_type", "authorization_code");
            tokenRequest.add("client_id", naverClientId);
            tokenRequest.add("client_secret", naverClientSecret);
            tokenRequest.add("code", code);
            tokenRequest.add("redirect_uri", naverRedirectUri);
            
            HttpEntity<MultiValueMap<String, String>> tokenEntity = new HttpEntity<>(tokenRequest, tokenHeaders);
            
            log.info("네이버 토큰 요청: {}", tokenRequest);
            
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    "https://nid.naver.com/oauth2.0/token",
                    HttpMethod.POST,
                    tokenEntity,
                    String.class
            );
            
            log.info("네이버 토큰 응답: {}", tokenResponse.getBody());
            
            // 2. 응답에서 액세스 토큰 추출
            JsonNode tokenJson = objectMapper.readTree(tokenResponse.getBody());
            String accessToken = tokenJson.get("access_token").asText();
            
            log.info("네이버 액세스 토큰 획득: {}", accessToken);
            
            // 3. 사용자 정보 요청 처리
            return getNaverUserInfo(accessToken);
        } catch (Exception e) {
            log.error("네이버 로그인 처리 중 오류 발생: {}", e.getMessage(), e);
            throw new RuntimeException("네이버 로그인 처리 중 오류 발생: " + e.getMessage(), e);
        }
    }
    
    // 네이버 사용자 정보 요청
    private Map<String, Object> getNaverUserInfo(String accessToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);

            HttpEntity<?> entity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(
                    "https://openapi.naver.com/v1/nid/me",
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            JsonNode jsonNode = objectMapper.readTree(response.getBody());
            log.info("네이버 API 응답: {}", jsonNode.toString());

            // 네이버 API는 response 객체 안에 실제 데이터가 있음
            JsonNode responseData = jsonNode.get("response");
            
            String email = responseData.has("email") ? responseData.get("email").asText() : null;
            String nickname = responseData.has("nickname") ? responseData.get("nickname").asText() : 
                    responseData.has("name") ? responseData.get("name").asText() : "네이버 사용자";

            if (email == null || email.isEmpty()) {
                throw new IllegalArgumentException("네이버 계정에서 이메일을 제공하지 않았습니다. 이메일 제공에 동의해주세요.");
            }

            return processSocialLogin(email, nickname, SocialType.NAVER);
        } catch (Exception e) {
            log.error("네이버 사용자 정보 조회 중 오류: {}", e.getMessage());
            throw new RuntimeException("네이버 사용자 정보 조회 중 오류 발생: " + e.getMessage(), e);
        }
    }

    // 소셜 로그인 공통 처리 메서드
    public Map<String, Object> processSocialLogin(String email, String nickname, SocialType socialType) {
        Member existingMember = memberMapper.getMemberByEmail(email);
        String jwtToken;
        String refreshToken;
        MemberDto memberDto;

        if (existingMember != null) {
            // 이미 등록된 회원인 경우
            log.info("기존 {} 계정으로 로그인: {}", socialType, email);
            
            // 소셜 타입이 다른 경우 오류 발생
            if (existingMember.getSocialType() != socialType && existingMember.getSocialType() != SocialType.NONE) {
                throw new IllegalArgumentException("이미 다른 소셜 계정(" + existingMember.getSocialType() + ")으로 가입된 이메일입니다.");
            }
            
            String role = existingMember.getMemberRole().name();
            jwtToken = jwtTokenProvider.createToken(email, role);
            refreshToken = jwtTokenProvider.createRefreshToken(email);
            memberDto = MemberDto.fromEntity(existingMember);
        } else {
            // 신규 회원 등록
            // 소셜 로그인 이용자는 랜덤 패스워드 부여 (로컬 로그인 불가)
            String randomPassword = UUID.randomUUID().toString();
            String encodedPassword = passwordEncoder.encode(randomPassword);
            
            Member newMember = Member.builder()
                    .email(email)
                    .password(encodedPassword) // 암호화된 랜덤 비밀번호
                    .nickname(nickname)
                    .memberRole(MemberRole.USER) // 기본 사용자 권한
                    .socialType(socialType)
                    .build();

            memberMapper.insertMember(newMember);
            log.info("{} 계정 신규 등록: {}", socialType, email);
            
            // 방금 등록한 회원 정보 조회
            Member savedMember = memberMapper.getMemberByEmail(email);
            
            jwtToken = jwtTokenProvider.createToken(email, MemberRole.USER.name());
            refreshToken = jwtTokenProvider.createRefreshToken(email);
            memberDto = MemberDto.fromEntity(savedMember);
        }

        // 응답 데이터 구성
        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", jwtToken);
        response.put("refreshToken", refreshToken);
        response.put("member", memberDto);
        response.put("redirectUrl", frontendUrl + oauthSuccessRedirectPath + 
                "?token=" + jwtToken + 
                "&refreshToken=" + refreshToken + 
                "&email=" + email);

        return response;
    }
    
    // 문자열에서 SocialType으로 변환하는 메소드
    public Map<String, Object> processSocialLogin(String email, String nickname, String providerString) {
        SocialType socialType;
        try {
            socialType = SocialType.valueOf(providerString);
        } catch (IllegalArgumentException e) {
            log.error("지원하지 않는 소셜 로그인 제공자: {}", providerString);
            throw new IllegalArgumentException("지원하지 않는 소셜 로그인 제공자입니다: " + providerString);
        }
        
        return processSocialLogin(email, nickname, socialType);
    }
}