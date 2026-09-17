-- 2. adım: Storage + grup tohumu (schema.sql'den SONRA çalıştır)
-- Storage bucket'ı dashboard'dan elle aç: Storage > New bucket > isim: chat-media > Private

-- 3 kişi dışında kimse okuyamasın ama v0'da basit tutuyoruz:
-- sadece login olmuş kullanıcı storage'a erişir (zaten sadece siz 3 login olacaksınız)
drop policy if exists "auth okur" on storage.objects;
drop policy if exists "auth yazar" on storage.objects;
create policy "auth okur" on storage.objects for select
  to authenticated using (bucket_id = 'chat-media');
create policy "auth yazar" on storage.objects for insert
  to authenticated with check (bucket_id = 'chat-media');

-- Grup oluştur (1 kere):
-- insert into groups(name) values ('bizim-grup') returning id;
-- dönen id'yi alıp aşağıya koy (örnek: 'XXXX' yerine):
-- insert into group_members(group_id, user_id) values
--   ('GRUP_ID', 'KULLANICI1_UUID'),
--   ('GRUP_ID', 'KULLANICI2_UUID'),
--   ('GRUP_ID', 'KULLANICI3_UUID');
-- Kullanıcı UUID'leri: Authentication > Users tablosunda her kullanıcının satırında yazar.
