-- نظام إدارة وتسجيل التدريب 2027 — تجهيز المزامنة بين الأجهزة
-- كل الجداول والدوال تبدأ بـ trs_ فقط؛ لا يتم حذف أو تعديل أي شيء خاص بأنظمة أخرى (مثل plan2027).

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.trs_state (
  id int primary key default 1 check (id = 1),
  data jsonb,
  version int not null default 0,
  updated_at timestamptz default now(),
  updated_by text
);
insert into public.trs_state (id) values (1) on conflict do nothing;

create table if not exists public.trs_secret (
  id int primary key default 1 check (id = 1),
  pw_hash text not null
);

-- Lock the tables: no direct read/write, only through the functions below
alter table public.trs_state  enable row level security;
alter table public.trs_secret enable row level security;
revoke all on public.trs_state, public.trs_secret from anon, authenticated;

create or replace function public.trs_pw_ok(pw text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select exists(select 1 from public.trs_secret where pw_hash = extensions.crypt(pw, pw_hash));
$$;
revoke all on function public.trs_pw_ok(text) from public, anon, authenticated;

create or replace function public.trs_check_pw(pw text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select public.trs_pw_ok(pw);
$$;

create or replace function public.trs_get_state(pw text, known_version int default -1) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare r public.trs_state;
begin
  if not public.trs_pw_ok(pw) then return jsonb_build_object('ok', false, 'error', 'bad_pw'); end if;
  select * into r from public.trs_state where id = 1;
  if r.version = known_version then
    return jsonb_build_object('ok', true, 'version', r.version, 'unchanged', true);
  end if;
  return jsonb_build_object('ok', true, 'version', r.version, 'data', r.data,
                            'updated_at', r.updated_at, 'updated_by', r.updated_by);
end $$;

create or replace function public.trs_save_state(pw text, new_data jsonb, base_version int, device text default '')
returns jsonb
language plpgsql volatile security definer set search_path = public, extensions as $$
declare v int;
begin
  if not public.trs_pw_ok(pw) then return jsonb_build_object('ok', false, 'error', 'bad_pw'); end if;
  if new_data is null or jsonb_typeof(new_data) <> 'object' then
    return jsonb_build_object('ok', false, 'error', 'bad_data');
  end if;
  if coalesce(jsonb_typeof(new_data->'recs'), '') <> 'object' then
    return jsonb_build_object('ok', false, 'error', 'bad_data');
  end if;
  update public.trs_state
     set data = new_data, version = version + 1, updated_at = now(), updated_by = device
   where id = 1 and version = base_version
  returning version into v;
  if v is null then
    return jsonb_build_object('ok', false, 'error', 'conflict',
                              'version', (select version from public.trs_state where id = 1));
  end if;
  return jsonb_build_object('ok', true, 'version', v);
end $$;

revoke all on function public.trs_check_pw(text), public.trs_get_state(text, int),
                       public.trs_save_state(text, jsonb, int, text) from public;
grant execute on function public.trs_check_pw(text), public.trs_get_state(text, int),
                          public.trs_save_state(text, jsonb, int, text) to anon, authenticated;
