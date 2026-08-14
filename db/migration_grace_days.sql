-- Grace days 중앙 제어: users 테이블에 grace_days 컬럼 추가
-- 실행: mysql -u root -p quepilot_license < db/migration_grace_days.sql

ALTER TABLE users
  ADD COLUMN grace_days INT DEFAULT 7 AFTER max_users;
