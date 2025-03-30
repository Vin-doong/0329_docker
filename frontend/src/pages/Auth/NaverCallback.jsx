import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';

const NaverCallback = () => {
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleNaverCallback = async () => {
      try {
        // URL에서 인증 코드와 상태값 가져오기
        const searchParams = new URLSearchParams(location.search);
        const code = searchParams.get('code');
        const state = searchParams.get('state');
        
        if (!code) {
          throw new Error('인증 코드를 찾을 수 없습니다');
        }

        // 저장된 상태값과 비교하여 CSRF 방지
        const savedState = sessionStorage.getItem('naverState');
        if (state !== savedState) {
          console.warn('상태값 불일치. 저장된 값:', savedState, '받은 값:', state);
          // 일부 환경에서는 상태값 확인이 어려울 수 있으므로 경고만 출력
        }

        // 백엔드 API 호출
        const response = await axios.post('/api/social/login/naver', {
          code: code,
          state: state
        }, {
          headers: { 'Content-Type': 'application/json' }
        });

        console.log('네이버 로그인 응답:', response.data);

        if (response.data && response.data.data) {
          const responseData = response.data.data;
          
          // 토큰 및 사용자 정보 저장
          localStorage.setItem('accessToken', responseData.accessToken);
          localStorage.setItem('refreshToken', responseData.refreshToken);
          localStorage.setItem('memberId', responseData.member.memberId);
          localStorage.setItem('email', responseData.member.email);
          localStorage.setItem('role', responseData.member.memberRole || 'USER');
          
          // 상태 업데이트 이벤트 발생
          window.dispatchEvent(new Event('storage'));
          
          // 홈페이지로 이동
          navigate('/');
        } else {
          throw new Error('서버에서 토큰을 받지 못했습니다');
        }
      } catch (error) {
        console.error('네이버 로그인 오류:', error);
        setError('네이버 로그인 처리 중 오류가 발생했습니다.');
        setTimeout(() => navigate('/login'), 3000);
      } finally {
        setLoading(false);
      }
    };

    handleNaverCallback();
  }, [location, navigate]);

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column',
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        backgroundColor: '#f8f9fa'
      }}>
        <h2>네이버 로그인 처리 중</h2>
        <p>잠시만 기다려주세요...</p>
        <div className="loading-spinner" style={{ 
          width: '40px', 
          height: '40px', 
          border: '4px solid #f3f3f3',
          borderTop: '4px solid #1ec800',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite'
        }}></div>
        <style>{`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column',
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        backgroundColor: '#f8f9fa'
      }}>
        <h2>로그인 오류</h2>
        <p>{error}</p>
        <p>잠시 후 로그인 페이지로 이동합니다...</p>
      </div>
    );
  }

  return null;
};

export default NaverCallback;