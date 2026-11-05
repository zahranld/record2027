-- حماية قراءة بيانات الخطة (نظام الاحتياجات) — التشغيل الأول: إضافة فقط، لا يغيّر أي شيء موجود
create extension if not exists pgcrypto with schema extensions;

-- كلمة سر العرض (اختيارية بجانب كلمة سر التعديل الحالية)
create table if not exists public.plan_view_secret (
  id int primary key default 1 check (id = 1),
  pw_hash text not null
);
alter table public.plan_view_secret enable row level security;
revoke all on public.plan_view_secret from anon, authenticated;

-- صحيحة لو كانت كلمة سر التعديل الحالية أو كلمة سر العرض
create or replace function public.plan_view_ok(pw text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select coalesce(public.check_pw(pw), false)
      or exists (select 1 from public.plan_view_secret where pw_hash = extensions.crypt(pw, pw_hash));
$$;
revoke all on function public.plan_view_ok(text) from public, anon, authenticated;

-- قراءة الخطة لنظام الاحتياجات (بكلمة سر العرض أو التعديل)
create or replace function public.get_plan_state(pw text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare r record;
begin
  if not public.plan_view_ok(pw) then return jsonb_build_object('ok', false, 'error', 'bad_pw'); end if;
  select data, version into r from public.app_state where id = 1;
  return jsonb_build_object('ok', true, 'data', r.data, 'version', r.version);
end $$;

-- قراءة الخطة لنظام التدريب (بكلمة سر نظام التدريب)
create or replace function public.trs_get_plan(pw text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare r record;
begin
  if not public.trs_pw_ok(pw) then return jsonb_build_object('ok', false, 'error', 'bad_pw'); end if;
  select data, version into r from public.app_state where id = 1;
  return jsonb_build_object('ok', true, 'data', r.data, 'version', r.version);
end $$;

revoke all on function public.get_plan_state(text), public.trs_get_plan(text) from public;
grant execute on function public.get_plan_state(text), public.trs_get_plan(text) to anon, authenticated;
