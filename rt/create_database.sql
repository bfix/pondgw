
drop database if exists pondgw;
create database pondgw;

use pondgw;

create table email (
    id   int not null auto_increment,
    ts   timestamp default now(),
    status int default 0,
    addr varchar(128) not null,
    pubkey mediumblob not null,
    primary key(id)
);

-- drop user 'pondgw'@'localhost';
-- create user 'pondgw'@'localhost' identified by 'pondgw';
-- grant select,delete,update,insert on pondgw.* to 'pondgw'@'localhost';
