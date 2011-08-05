CREATE TABLE  `your_db_name`.`users` (
`id` INT (11) NOT NULL ,
`email` VARCHAR( 255 ) NOT NULL ,
`password` VARCHAR( 40 ) NOT NULL ,
`group` SMALLINT( 8 ) NOT NULL ,
PRIMARY KEY (  `id` ) ,
INDEX (  `group` ) ,
UNIQUE ( `email` )
)