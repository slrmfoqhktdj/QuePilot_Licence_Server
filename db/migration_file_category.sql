-- 파일 카테고리 구분: server_files 테이블에 category 컬럼 추가
-- 'server'  = 로컬서버 설치 파일 (로그인 + 활성 구독 필요)
-- 'desktop' = 데스크탑 앱 설치 파일 (공개 다운로드, 로그인 불필요)
-- 실행: mysql -u root -p quepilot_license < db/migration_file_category.sql

ALTER TABLE server_files
  ADD COLUMN category VARCHAR(20) NOT NULL DEFAULT 'server' AFTER description;
