-- Supabase şeması (server SADECE ciphertext tutar)
create table if not exists groups(id uuid primary key default gen_random_uuid(), name text not null);
create table if not exists group_members(group_id uuid references groups(id) on delete cascade, user_id uuid references auth.users(id) on delete cascade, primary key(group_id, user_id));
create table if not exists messages(
  id uuid primary key default gen_random_uuid(),
  group_id uuid references groups(id) on delete cascade not null,
  sender_id uuid references auth.users(id) not null,
  kind text not null check (kind in ('text','image')),
  packet jsonb not null, -- text için {v,nonce,ct,sig,sender}
  media_path text, media_nonce text,
  created_at timestamptz default now() not null
);
alter table groups enable row level security;
alter table group_members enable row level security;
alter table messages enable row level security;
-- sadece üye okuyabilir/yazabilir (içerik zaten şifreli, bu ikinci katman)
create policy "uye okur" on messages for select using (
  exists (select 1 from group_members m where m.group_id = messages.group_id and m.user_id = auth.uid())
);
create policy "uye yazar" on messages for insert with check (
  exists (select 1 from group_members m where m.group_id = messages.group_id and m.user_id = auth.uid())
);
-- storage: chat-media bucket'ı private aç, policy'yi dashboard'dan aynı mantıkla ekle.
