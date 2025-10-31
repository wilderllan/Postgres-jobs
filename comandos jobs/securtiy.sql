create or replace function debugging_info_on()
returns void
security definer
as
$$
begin
set client_min_messages to 'DEBUG1';
set log_min_messages to 'DEBUG1';
set log_error_verbosity to 'VERBOSE';
set log_min_duration_statement to 0;
end;
$$ language plpgsql;



revoke all on function debugging_info_on() from public;
grant execute on function debugging_info_on() to bob;



create or replace function debugging_info_reset()
returns void
security definer
as
$$
begin
set client_min_messages to DEFAULT;
set log_min_messages to DEFAULT;
set log_error_verbosity to DEFAULT;
set log_min_duration_statement to DEFAULT;
end;
$$ language plpgsql;
