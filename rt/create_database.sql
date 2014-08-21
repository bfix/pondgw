
drop database if exists pondgw;
create database pondgw;

use pondgw;

-- --------------------------------------------------------------------
-- EMAIL-related tables
-- --------------------------------------------------------------------

create table email (
    id int not null auto_increment,
    ts timestamp default current_timestamp on update current_timestamp,
    status int default 0,
    addr varchar(128) not null,
    pubkey mediumblob not null,
    token varchar(32) not null,
    primary key(id)
);

create index mail_idx on email(addr);

-- --------------------------------------------------------------------
-- POND-related tables
-- --------------------------------------------------------------------

create table pond (
    id int not null auto_increment,
    ts timestamp default current_timestamp on update current_timestamp,
    status int default 0,
    peer varchar(16) not null,
    primary key(id)
);

create index pond_idx on pond(peer);

-- --------------------------------------------------------------------
-- user management
-- --------------------------------------------------------------------

-- drop user 'pondgw'@'localhost';
-- create user 'pondgw'@'localhost' identified by 'pondgw';
-- grant select,delete,update,insert on pondgw.* to 'pondgw'@'localhost';
