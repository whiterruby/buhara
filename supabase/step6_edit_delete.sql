-- 6. adım: yanıt/düzenle/sil
-- Yanıt anlığı şifreli paketin içinde taşınır (şema değişmez).
-- Düzenleme bayrağı + UPDATE/DELETE yetkisi için SQL Editor'da koş.

alter table messages add column if not exists edited boolean not null default false;

drop policy if exists "kendi mesajini duzenler" on messages;
create policy "kendi mesajini duzenler" on messages for update
  to authenticated using (sender_id = auth.uid()) with check (sender_id = auth.uid());

drop policy if exists "kendi mesajini siler" on messages;
create policy "kendi mesajini siler" on messages for delete
  to authenticated using (sender_id = auth.uid());
