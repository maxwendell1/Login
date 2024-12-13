INSERT INTO users (username, password, enabled) VALUES ('admin', '{bcrypt}$2a$10$DowJ9fBf5L0Z5frHIkW2VeKKojTlvUVY2YPks3cplc1VvO9EMN6Aa', true);
INSERT INTO authorities (username, authority) VALUES ('admin', 'ROLE_ADMIN');
