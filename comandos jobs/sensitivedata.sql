CREATE LANGUAGE plpythonu;

create or replace function get_my_public_key() returns text as $$
return open('/var/lib/postgresql/*/public.key').read()
$$
language plpythonu;

revoke all on function get_my_public_key() from public;

create or replace function get_my_secret_key() returns text as $$
return open('/var/lib/postgresql/*/secret.key').read()
$$
language plpythonu;

revoke all on function get_my_secret_key() from public;


create or replace function encrypt_using_my_public_key(
cleartext text,
ciphertext out bytea
)
AS $$
DECLARE
pubkey_bin bytea;
BEGIN
-- text version of public key needs to be passed through function dearmor() to get to raw key
pubkey_bin := dearmor(get_my_public_key());
ciphertext := pgp_pub_encrypt(cleartext, pubkey_bin);
END;
$$ language plpgsql security definer;

revoke all on function encrypt_using_my_public_key(text) from public;

grant execute on function encrypt_using_my_public_key(text) to postgres;


create or replace function decrypt_using_my_secret_key(
ciphertext bytea,
cleartext out text
)
AS $$
DECLARE
secret_key_bin bytea;
BEGIN
secret_key_bin := dearmor(get_my_secret_key());
cleartext := pgp_pub_decrypt(ciphertext, secret_key_bin);
END;
$$ language plpgsql security definer;

revoke all on function decrypt_using_my_secret_key(bytea) from public;

grant execute on function decrypt_using_my_secret_key(bytea) to postgres;

select encrypt_using_my_public_key('Vamos testar a nossa Criptografia');

select decrypt_using_my_secret_key(encrypt_using_my_public_key('Vamos testar a nossa Criptografia'));


































