CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(50),
    password VARCHAR(50),
    first_name VARCHAR(50),
    last_name VARCHAR(50)
);
INSERT INTO users VALUES ('admin', 'password', 'Admin', 'Istrator');
INSERT INTO users VALUES ('guest', 'guest', 'A', 'Guest');
INSERT INTO users VALUES ('guest2', 'somerandomlongpassword', 'Another', 'Guest');
