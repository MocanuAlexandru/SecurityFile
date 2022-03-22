-- Create table for users
CREATE SEQUENCE public."USERS_user_id_seq"
    INCREMENT 1
    START 1
    MINVALUE 1
    MAXVALUE 2147483647
    CACHE 1;

ALTER SEQUENCE public."USERS_user_id_seq"
    OWNER TO admin;

CREATE TABLE public."USERS"
(
    user_id integer NOT NULL DEFAULT nextval('"USERS_user_id_seq"'::regclass),
    username character varying(200) COLLATE pg_catalog."default" NOT NULL,
    hash_password character(64) COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT "USERS_pkey" PRIMARY KEY (user_id)
)

    TABLESPACE pg_default;

ALTER TABLE public."USERS"
    OWNER to admin;


-- Create table for encrypted files
CREATE SEQUENCE public."ENCRYPTED_FILES_file_id_seq"
    INCREMENT 1
    START 1
    MINVALUE 1
    MAXVALUE 2147483647
    CACHE 1;

ALTER SEQUENCE public."ENCRYPTED_FILES_file_id_seq"
    OWNER TO admin;

CREATE TABLE public."ENCRYPTED_FILES"
(
    file_id integer NOT NULL DEFAULT nextval('"ENCRYPTED_FILES_file_id_seq"'::regclass),
    user_id integer NOT NULL,
    file_path character varying(300) COLLATE pg_catalog."default" NOT NULL,
    hash_enc_key character(64) COLLATE pg_catalog."default" NOT NULL,
    hash_del_key character(64) COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT "ENCRYPTED_FILES_pkey" PRIMARY KEY (file_id),
    CONSTRAINT "ENCRYPTED_FILES_user_id_fkey" FOREIGN KEY (user_id)
        REFERENCES public."USERS" (user_id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

    TABLESPACE pg_default;

ALTER TABLE public."ENCRYPTED_FILES"
    OWNER to admin;