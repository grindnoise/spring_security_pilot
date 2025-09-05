create table `eazybank`.users
(
    username varchar(50)  not null primary key,
    password varchar(500) not null,
    enabled  boolean      not null
);
create table `eazybank`.authorities
(
    username  varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);
create unique index ix_auth_username on `eazybank`.authorities (username, authority);

INSERT
    IGNORE
INTO `eazybank`.`users`
VALUES ('user', '{noop}EazyBytes@12345', '1');
INSERT
    IGNORE
INTO `eazybank`.`authorities`
VALUES ('user', 'read');

INSERT
    IGNORE
INTO `eazybank`.`users`
VALUES ('admin', '{bcrypt}$2a$12$88.f6upbBvy0okEa7OfHFuorV29qeK.sVbB9VQ6J6dWM1bW6Qef8m', '1');
INSERT
    IGNORE
INTO `eazybank`.`authorities`
VALUES ('admin', 'admin');

CREATE TABLE eazybank.`customer`
(
    `id`    int          NOT NULL AUTO_INCREMENT,
    `email` varchar(45)  NOT NULL,
    `pwd`   varchar(200) NOT NULL,
    `role`  varchar(45)  NOT NULL,
    PRIMARY KEY (`id`)
);