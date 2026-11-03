-- HALO TV Phase 6: session revocation, stale-command isolation and cleanup
-- Execute in Supabase SQL Editor as project owner.
begin;
alter table public.halo_tv_sessions
  add column if not exists paired_at timestamptz;
-- Existing paired sessions are treated as newly paired at migration time;
-- old queued commands are intentionally discarded.
update public.halo_tv_sessions
set paired_at = now()
where paired_phone_user_id is not null and paired_at is null;

create or replace function public.halo_set_paired_at()
returns trigger language plpgsql set search_path = ''
as $
begin
  if new.paired_phone_user_id is distinct from old.paired_phone_user_id then
    new.paired_at := case when new.paired_phone_user_id is null then null else now() end;
  end if;
  return new;
end;
$;
drop trigger if exists halo_set_paired_at_trigger on public.halo_tv_sessions;
create trigger halo_set_paired_at_trigger
before update on public.halo_tv_sessions
for each row execute function public.halo_set_paired_at();

create or replace function public.halo_revoke_phone()
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := auth.uid(); v_session uuid;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  select id into v_session from public.halo_tv_sessions
  where tv_user_id = v_uid for update;
  if v_session is null then return jsonb_build_object('revoked',false,'error','No TV session'); end if;
  update public.halo_tv_sessions
  set paired_phone_user_id = null, pairing_code_hash = null,
      pairing_expires_at = null, paired_at = null
  where id = v_session;
  delete from public.halo_tv_commands where session_id = v_session;
  return jsonb_build_object('revoked',true);
end;
$$;

create or replace function public.halo_get_commands(p_after_id bigint default 0)
returns table(id bigint, command text, value integer)
language sql security definer set search_path = ''
as $$
  select c.id, c.command, c.value
  from public.halo_tv_commands c
  join public.halo_tv_sessions s on s.id = c.session_id
  where s.tv_user_id = auth.uid()
    and s.paired_phone_user_id is not null
    and s.paired_at is not null
    and c.created_at >= s.paired_at
    and c.created_at >= now() - interval '30 seconds'
    and c.id > greatest(coalesce(p_after_id,0),0)
  order by c.id asc
  limit 100;
$$;

create or replace function public.halo_cleanup_commands()
returns integer language plpgsql security definer set search_path = ''
as $$
declare v_count integer;
begin
  -- Explicitly restricted to project administrator/service role.
  if auth.role() <> 'service_role' and current_user <> 'postgres' then
    raise exception 'Not authorized';
  end if;
  delete from public.halo_tv_commands
  where created_at < now() - interval '1 day';
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

revoke all on function public.halo_revoke_phone() from public, anon;
revoke all on function public.halo_get_commands(bigint) from public, anon;
revoke all on function public.halo_cleanup_commands() from public, anon, authenticated;
grant execute on function public.halo_revoke_phone() to authenticated;
grant execute on function public.halo_get_commands(bigint) to authenticated;
grant execute on function public.halo_cleanup_commands() to service_role;
commit;

-- Run manually in SQL Editor when desired:
-- select public.halo_cleanup_commands();
-- For automatic cleanup, schedule this call using Supabase Cron.
-- Pairing timestamp is maintained by the trigger above.
