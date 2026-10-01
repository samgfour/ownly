-- Ownly multi-user schema. Run in Supabase SQL Editor on a FRESH project
-- (if you ran the old single-user schema, drop those 3 tables first).

create table profiles (
  user_id uuid primary key default auth.uid() references auth.users on delete cascade,
  username text unique not null check (username ~ '^[a-z0-9_]{3,20}$' and username !~ '^(app|api|login|admin)$'),
  name text default '', bio text default '', avatar text default '',
  color text default '#2563eb', style text default 'fill', bg text default '#f4f4f1'
);
create table links (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  title text not null, url text not null, emoji text default '🔗', position int default 0
);
create table clicks (
  id bigint generated always as identity primary key,
  link_id bigint not null references links(id) on delete cascade,
  created_at timestamptz default now()
);
create table subscriptions (
  user_id uuid primary key references auth.users on delete cascade,
  expires_at timestamptz not null
);
create table settings (
  id int primary key default 1 check (id = 1),
  price int not null default 300, period_days int not null default 30,
  till text not null default '000000', till_name text default ''
);
insert into settings (id) values (1);
create table admins (user_id uuid primary key references auth.users on delete cascade);
create table claims (               -- a customer says "I paid, here is my M-Pesa code"
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users on delete cascade,
  code text unique not null, phone text,
  status text not null default 'pending',   -- pending | approved | rejected
  created_at timestamptz default now()
);
create table received_codes (       -- codes you paste from your own M-Pesa SMS
  code text primary key, amount int, used boolean not null default false,
  created_at timestamptz default now()
);
create index on links(user_id);
create index on clicks(link_id);

-- 7-day free trial on signup (change the interval, or set to '0 days')
create function new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into subscriptions(user_id, expires_at) values (new.id, now() + interval '7 days'); return new; end $$;
create trigger on_signup after insert on auth.users for each row execute function new_user();

create function is_active(uid uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from subscriptions where user_id = uid and expires_at > now()) $$;

alter table profiles      enable row level security;
alter table links         enable row level security;
alter table clicks        enable row level security;
alter table subscriptions enable row level security;

-- THE PAYWALL: a page is only publicly readable while its owner's subscription is active
create policy "public read profiles" on profiles for select using (is_active(user_id) or user_id = auth.uid());
create policy "public read links"    on links    for select using (is_active(user_id) or user_id = auth.uid());
create policy "own profile" on profiles for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "own links"   on links    for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
-- visitors log clicks (only on visible links); owners read their own clicks
create policy "log click"   on clicks for insert to anon, authenticated with check (exists (select 1 from links where id = link_id));
create policy "own clicks"  on clicks for select to authenticated using (exists (select 1 from links l where l.id = clicks.link_id and l.user_id = auth.uid()));
-- users can read (never write) their own subscription
create policy "own sub"      on subscriptions for select to authenticated using (user_id = auth.uid());

-- Give yourself free lifetime access (after you sign up):
-- update subscriptions set expires_at = '2099-01-01' where user_id = (select id from auth.users where email = 'you@example.com');

-- ===== Manual M-Pesa verification =====
-- 1. Set your till:   update settings set till = '123456', till_name = 'Your business name', price = 300;
-- 2. Make yourself admin (after signing up):
--    insert into admins select id from auth.users where email = 'you@example.com';

create function is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from admins where user_id = auth.uid()) $$;

create function extend_sub(uid uuid) returns void language plpgsql security definer set search_path = public as $$
declare d int; begin
  select period_days into d from settings where id = 1;
  insert into subscriptions(user_id, expires_at) values (uid, now() + make_interval(days => d))
  on conflict (user_id) do update set expires_at = greatest(subscriptions.expires_at, now()) + make_interval(days => d);
end $$;
revoke execute on function extend_sub(uuid) from public, anon, authenticated;

-- customer submits a code: instantly approved if you already recorded it, otherwise waits for you
create function submit_claim(p_code text, p_phone text) returns text language plpgsql security definer set search_path = public as $$
declare c text := upper(regexp_replace(p_code, '\s', '', 'g')); cid bigint; rc received_codes%rowtype; s settings%rowtype;
begin
  if auth.uid() is null then raise exception 'Please log in'; end if;
  if c !~ '^[A-Z0-9]{10}$' then raise exception 'That does not look like an M-Pesa code (10 letters/numbers)'; end if;
  if (select count(*) from claims where user_id = auth.uid() and status = 'pending') >= 3 then
    raise exception 'You already have payments waiting for approval'; end if;
  select * into s from settings where id = 1;
  begin insert into claims(user_id, code, phone) values (auth.uid(), c, left(p_phone, 20)) returning id into cid;
  exception when unique_violation then raise exception 'That code has already been submitted'; end;
  select * into rc from received_codes where code = c and not used;
  if found and (rc.amount is null or rc.amount >= s.price) then
    update received_codes set used = true where code = c;
    update claims set status = 'approved' where id = cid;
    perform extend_sub(auth.uid());
    return 'approved';
  end if;
  return 'pending';
end $$;

-- admin: record a code from your SMS (activates the customer immediately if they already submitted it)
create function add_received(p_code text, p_amount int) returns text language plpgsql security definer set search_path = public as $$
declare c text := upper(regexp_replace(p_code, '\s', '', 'g')); cl claims%rowtype; s settings%rowtype;
begin
  if not is_admin() then raise exception 'admin only'; end if;
  if c !~ '^[A-Z0-9]{10}$' then raise exception 'Code must be 10 letters/numbers'; end if;
  select * into s from settings where id = 1;
  insert into received_codes(code, amount) values (c, p_amount) on conflict (code) do nothing;
  select * into cl from claims where code = c and status = 'pending';
  if found and p_amount >= s.price then
    update received_codes set used = true where code = c;
    update claims set status = 'approved' where id = cl.id;
    perform extend_sub(cl.user_id);
    return 'matched and activated';
  end if;
  return 'saved';
end $$;

create function approve_claim(p_id bigint) returns void language plpgsql security definer set search_path = public as $$
declare u uuid; begin
  if not is_admin() then raise exception 'admin only'; end if;
  update claims set status = 'approved' where id = p_id and status = 'pending' returning user_id into u;
  if u is not null then perform extend_sub(u); end if;
end $$;
create function reject_claim(p_id bigint) returns void language plpgsql security definer set search_path = public as $$
begin if not is_admin() then raise exception 'admin only'; end if;
  update claims set status = 'rejected' where id = p_id and status = 'pending'; end $$;

alter table settings       enable row level security;
alter table admins         enable row level security;
alter table claims         enable row level security;
alter table received_codes enable row level security;
create policy "read settings" on settings for select using (true);
create policy "see self admin" on admins for select to authenticated using (user_id = auth.uid());
create policy "own or admin claims" on claims for select to authenticated using (user_id = auth.uid() or is_admin());
-- no insert/update policies on claims or received_codes: all writes go through the functions above
