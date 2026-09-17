-- 3. adım: realtime aç + görüldü tablosu + yeni mesaj türleri
-- SQL Editor'da tek seferde koş. "already a member" hatası gelirse o satırı atla, normaldir.

-- 1) Realtime yayını aç (ANLIK MESAJIN SEBEBİ BUDUR: kapalıysa F5 gerekir)
alter publication supabase_realtime add table messages;

-- 2) Yeni ek türleri: video / konum / gif
alter table messages drop constraint if exists messages_kind_check;
alter table messages add constraint messages_kind_check
  check (kind in ('text','image','video','location','gif'));

-- 3) Görüldü tablosu: her üyenin gördüğü EN SON mesaj zamanı (içerik yok, sadece zaman)
create table if not exists read_state(
  group_id uuid references groups(id) on delete cascade not null,
  user_id uuid references auth.users(id) on delete cascade not null,
  last_seen_at timestamptz not null default now(),
  primary key(group_id, user_id)
);
alter table read_state enable row level security;
drop policy if exists "uye goruldu okur" on read_state;
create policy "uye goruldu okur" on read_state for select
  to authenticated using (
    exists (select 1 from group_members m where m.group_id = read_state.group_id and m.user_id = auth.uid())
  );
drop policy if exists "kendi goruldun yazar" on read_state;
create policy "kendi goruldun yazar" on read_state for insert
  to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from group_members m where m.group_id = read_state.group_id and m.user_id = auth.uid())
  );
drop policy if exists "kendi goruldun gunceller" on read_state;
create policy "kendi goruldun gunceller" on read_state for update
  to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

alter publication supabase_realtime add table read_state;
