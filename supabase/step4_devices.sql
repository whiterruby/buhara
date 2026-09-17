-- 4. adım: katılım protokolü (cihaz onay tablosu)
-- SQL Editor'da koş. Giriş artık sadece e-posta+şifre; anahtar grup onayıyla taşınır.

create table if not exists devices(
  group_id uuid references groups(id) on delete cascade not null,
  user_id uuid references auth.users(id) on delete cascade not null,
  ecdh_pub text not null,
  eph_pub text,
  wrapped text,
  wrap_nonce text,
  status text not null default 'pending' check (status in ('pending','ready')),
  created_at timestamptz default now() not null,
  primary key(group_id, user_id)
);
alter table devices enable row level security;

drop policy if exists "uye cihaz okur" on devices;
create policy "uye cihaz okur" on devices for select
  to authenticated using (
    exists (select 1 from group_members m where m.group_id = devices.group_id and m.user_id = auth.uid())
  );
drop policy if exists "kendi cihaz satiri" on devices;
create policy "kendi cihaz satiri" on devices for insert
  to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from group_members m where m.group_id = devices.group_id and m.user_id = auth.uid())
  );
drop policy if exists "kendi satirini gunceller" on devices;
create policy "kendi satirini gunceller" on devices for update
  to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "uye onay yazar" on devices;
create policy "uye onay yazar" on devices for update
  to authenticated using (
    exists (select 1 from group_members m where m.group_id = devices.group_id and m.user_id = auth.uid())
  ) with check (
    exists (select 1 from group_members m where m.group_id = devices.group_id and m.user_id = auth.uid())
  );
drop policy if exists "kendi satirini siler" on devices;
create policy "kendi satirini siler" on devices for delete
  to authenticated using (user_id = auth.uid());

alter publication supabase_realtime add table devices;
