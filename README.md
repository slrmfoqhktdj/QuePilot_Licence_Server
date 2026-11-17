[개요] 실시간 큐시트 연동 시스템 라이센스 서버 - NodeJs 20.1.0
[사용기술] Node.js 20, Express 4, MySQL(mysql2, UUID는 BINARY(16)), JWT(jsonwebtoken),
           bcryptjs, multer(배포 파일 업로드), 정적 HTML 대시보드

[주요기능]
 - 회원 사이트: 가입/로그인, 구독 현황·결제 내역 조회, 구독 신청(Standard 1개월),
   설치 파일 다운로드(공개/회원)
 - 로컬 서버용 API: /api/auth/login(구독 검증 후 24시간 토큰 발급),
   /api/auth/refresh(토큰 갱신·구독 상태 재확인), /api/auth/logout
 - 관리자 콘솔: 관리자 계정 CRUD, 회원 CRUD, 기간 연장, 결제 승인/통계,
   활성 세션(activations) 조회와 강제 로그아웃(kick), 배포 파일 관리
   (업로드/활성화/삭제), 통계

[핵심 시스템 구조와 구현 방식]
 - 데이터: users(플랜, max_users, grace_days, expires_at, is_active), payments,
   activations(토큰·마지막 확인 시각), admins(role, 활성 여부), 배포 파일 테이블.
 - 토큰 + 서버측 활성화 기록: 요청마다 JWT 서명 확인 후 activations 테이블에서 해당 토큰이
   유효한지 확인 → 관리자가 kick(행 삭제)하면 즉시 무효화.
 - grace_days(유예 일수)를 사용자별로 중앙 제어 → 로컬 서버가 오프라인이어도 일정 기간 동작 허용.
 - 일반 회원/관리자 인증 영역과 미들웨어(requireMember, requireAdmin, requirePageAuth)를 분리.

[데이터 흐름]
 로컬 서버 로그인 → 라이선스 서버(구독 확인) → JWT + {플랜, 최대 사용자, 만료일, 유예일}
   → 로컬 서버가 주기적으로 refresh 하며 상태 동기화
 관리자 콘솔 → 결제 승인/연장/kick → DB 반영 → 다음 refresh에서 로컬 서버에 반영
