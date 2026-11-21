-- VOLT V2.3 — profiles table and row-level security
-- Run in Supabase SQL Editor only when an authorized project is available.
-- The browser app must use the public publishable/anon key, never service_role.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'VOLT User'
    check (char_length(display_name) between 2 and 30),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- A profile is created automatically when Supabase Auth creates a user.
create or replace function public.volt_handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(
      nullif(left(trim(new.raw_user_meta_data ->> 'display_name'), 30), ''),
      'VOLT User'
    )
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke all on function public.volt_handle_new_user() from public;
revoke all on function public.volt_handle_new_user() from anon;
revoke all on function public.volt_handle_new_user() from authenticated;

drop trigger if exists volt_create_profile_after_signup on auth.users;
create trigger volt_create_profile_after_signup
after insert on auth.users
for each row execute procedure public.volt_handle_new_user();

-- Remove old policies before recreating the intended owner-only policies.
drop policy if exists "Users can read their own VOLT profile" on public.profiles;
drop policy if exists "Users can create their own VOLT profile" on public.profiles;
drop policy if exists "Users can update their own VOLT profile" on public.profiles;
drop policy if exists "Users can delete their own VOLT profile" on public.profiles;

create policy "Users can read their own VOLT profile"
  on public.profiles for select to authenticated
  using ((select auth.uid()) = id);

create policy "Users can create their own VOLT profile"
  on public.profiles for insert to authenticated
  with check ((select auth.uid()) = id);

create policy "Users can update their own VOLT profile"
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- No delete policy is exposed to clients. Account deletion requires a trusted
-- server-side workflow; never put a service-role key in browser JavaScript.
revoke all on table public.profiles from anon;
grant select, insert, update on table public.profiles to authenticated;
