-- admins 테이블 생성 (JWT 기반 관리자 인증)
CREATE TABLE IF NOT EXISTS admins (
  id BINARY(16) PRIMARY KEY,
  email VARCHAR(120) NOT NULL UNIQUE,
  password VARCHAR(225) NOT NULL,
  role VARCHAR(45) NOT NULL DEFAULT 'admin',
  is_active INT NOT NULL DEFAULT 1,
  last_login_at DATETIME,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
