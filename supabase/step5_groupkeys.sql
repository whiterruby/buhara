-- 5. adım: onaysız giriş — grup anahtarı üyelerce otomatik alınır
-- DÜRÜST NOT: anahtar artık server'da (RLS ile sadece 3 üye okur) durur.
-- Dışarıdan kimse giremez/okuyamaz; ama Supabase host teorik olarak açabilir.
-- "Sadece mail+şifre, sıfır tören" isteğinin bedeli budur. Onaylı model için step4'e dön.
-- SQL Editor'da koş.

create table if not exists group_keys(
  group_id uuid primary key references groups(id) on delete cascade,
  enc_key text not null
);
alter table group_keys enable row level security;

drop policy if exists "uye anahtar okur" on group_keys;
create policy "uye anahtar okur" on group_keys for select
  to authenticated using (
    exists (select 1 from group_members m where m.group_id = group_keys.group_id and m.user_id = auth.uid())
  );
drop policy if exists "uye anahtar yazar" on group_keys;
create policy "uye anahtar yazar" on group_keys for insert
  to authenticated with check (
    exists (select 1 from group_members m where m.group_id = group_keys.group_id and m.user_id = auth.uid())
  );
drop policy if exists "uye anahtar gunceller" on group_keys;
create policy "uye anahtar gunceller" on group_keys for update
  to authenticated using (
    exists (select 1 from group_members m where m.group_id = group_keys.group_id and m.user_id = auth.uid())
  ) with check (
    exists (select 1 from group_members m where m.group_id = group_keys.group_id and m.user_id = auth.uid())
  );
