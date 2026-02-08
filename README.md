Windows 10 Debloater Script - v2.5

📋 Script Haqqında

Bu PowerShell scripti Windows 10 sistemindən lazımsız və istənməyən proqramları təmizləmək üçün hazırlanıb. Script tam Azərbaycan dilindədir və istifadəsi asandır.

⚠️ ƏHƏMİYYƏTLİ XƏBƏRLƏR

Bu script aşağıdakı Windows komponentlərini TAMAMİLƏ SİLƏCƏK:

🗑️ SİLİNƏCƏKLƏR:

· Windows Defender (tamamilə)
· Microsoft Edge (brauzer, WebView2, yeniləmələr)
· OneDrive (tamamilə)
· Windows Mağazası və bütün UWP proqramları
· Cortana (səsli köməkçi)
· Xbox və bütün oyun xidmətləri
· Məlumat toplama və izləmə xidmətləri
· Lazımsız proqramlar (Spotify, Netflix, TikTok və s.)

⚙️ DEAKTİV EDİLƏCƏKLƏR:

· Windows Yeniləmələri (avtomatik)
· Windows Təhlükəsizlik Mərkəzi
· Windows Rəy Mərkəzi
· Fərdiləşdirilmiş təcrübələr

⚠️ NƏTİCƏLƏR:

1. Windows Defender silinəcək - MÜTLƏQ BAŞQA ANTİVİRUS QURAŞDIRIN!
2. Microsoft Edge silinəcək - YENİ BRAUZER QURAŞDIRMAQ ZƏRURİDİR!
3. Windows Update söndürüləcək - ÖZÜNÜZ YENİLƏMƏLƏR ETMƏLİSİNİZ!
4. OneDrive silinəcək - GOOGLE DRIVE VƏ YA DROPBOX İSTİFADƏ EDİN!

📁 YARADILAN FAYLLAR

Script bu faylları yaradacaq:

1. Gündəlik faylı - %TEMP%\Windows10_Debloat_YYYYMMDD_HHMMSS.log
2. Transkript faylı - %TEMP%\Windows10_Debloat_Transcript_YYYYMMDD_HHMMSS.log
3. Backup qovluğu - %TEMP%\Debloat_Backup_YYYYMMDD_HHMMSS\
4. Sistem Bərpa Nöqtəsi - "Windows 10 Debloat Script" adı ilə

🚀 İSTİFADƏ QAYDASI

1. ƏVVƏLCƏDƏN HAZIRLIQ:

```bash
# 1. Sisteminizin backup-unu edin
# 2. Başqa antivirus proqramı hazırlayın
# 3. İstədiyiniz brauzeri hazırlayın
# 4. Ofis proqramına ehtiyacınız varsa, LibreOffice hazırlayın
```

2. SCRİPTİ İŞƏ SALMAQ:

1. Faylı sağ klikləyin və "Run as Administrator" seçin
2. İki dəfə təsdiq verin ("Y" yazın)
3. Scriptin işləməsini gözləyin (10-20 dəqiqə)
4. Sistemin yenidən başlamasını gözləyin

3. PARAMETRLƏR (İSTƏYƏ BAĞLI):

```powershell
# Nümunələr:
.\WINDOWS 10 ULTRA DEBLOATER.ps1 -SkipWarning           # Xəbərdarlıq göstərmə
.\WINDOWS 10 ULTRA DEBLOATER.ps1 -NoRestart             # Yenidən başlatma
.\WINDOWS 10 ULTRA DEBLOATER.ps1 -SkipApps              # Proqramları silmə
.\WINDOWS 10 ULTRA DEBLOATER.ps1 -SkipServices          # Xidmətlərə toxunma
.\WINDOWS 10 ULTRA DEBLOATER.ps1 -SkipOptimization      # Optimizasiya etmə
.\WINDOWS 10 ULTRA DEBLOATER.ps1 -SkipPrivacy           # Məxfilik ayarlarına toxunma
```

🔒 TƏHLÜKƏSİZLİK XİDMƏTLƏRİ (QORUNUR)

Bu xidmətlərə TOXUNULMAYACAQ:

· Səs xidmətləri (Realtek, Intel, NVIDIA)
· Şəbəkə xidmətləri (Wi-Fi, Ethernet)
· Display driver xidmətləri
· Disk və partition xidmətləri
· USB və PnP xidmətləri
· Printer və skaner xidmətləri
· Task Scheduler (əsas hissəsi)

📊 ƏMƏLİYYAT STATİSTİKASI

Script aşağıdakıları edəcək:

1. Windows Proqramları - 50+ lazımsız proqram silinəcək
2. Microsoft Edge - Tamamilə silinəcək
3. OneDrive - Tamamilə silinəcək
4. Windows Defender - Deaktiv ediləcək
5. Xbox & Oyunlar - Silinəcək
6. Məlumat toplama - 15+ xidmət deaktiv ediləcək
7. Windows Update - Deaktiv ediləcək
8. Planlaşdırılmış tapşırıqlar - 20+ task silinəcək
9. Pagefile - Optimallaşdırılacaq (2048-4096MB)
10. Enerji planı - "Ultimate Performance" aktiv ediləcək
11. Görüntü effektləri - Optimallaşdırılacaq
12. Xidmətlər - 30+ xidmət optimallaşdırılacaq
13. Məxfilik ayarları - Tətbiq ediləcək
14. Disk təmizliyi - Həyata keçiriləcək

🛠️ SONRAKİ ADDIMLAR

Script bitdikdən sonra:

1. Antivirus quraşdırın - Malwarebytes, Kaspersky, Norton
2. Brauzer quraşdırın - Chrome, Firefox, Opera, Brave
3. Ofis proqramı quraşdırın - LibreOffice, Office 365
4. Cloud storage quraşdırın - Google Drive, Dropbox
5. Sisteminizi yoxlayın - Bütün funksiyalar işləyir?

❓ TEZ-TEZ VERİLƏN SUALLAR

S: Scripti necə ləğv edim?
C: İstənilən vaxt Ctrl+C basın və ya təsdiq mərhələsində "N" yazın.

S: Windows Defender-i geri qaytara bilərəmmi?
C: Xeyr, tamamilə silinir. Başqa antivirus quraşdırmalısınız.

S: Windows Update-i yenidən aktiv edə bilərəmmi?
C: Bəli, əllə Servislər pəncərəsindən aktiv edə bilərsiniz.

S: Log fayllarını harada tapa bilərəm?
C: %TEMP% qovluğunda (C:\Users\[adınız]\AppData\Local\Temp)

📞 DƏSTƏK

Script ilə bağlı problem olarsa:

1. Log fayllarına baxın
2. Sistem Bərpa Nöqtəsindən istifadə edin
3. Backup qovluğundakı .reg fayllarını istifadə edin

⚖️ QEYD

Bu script TƏHLÜKƏSİZ DEYİL və İSTİFADƏ ÖZ TƏHLÜKƏNİZDƏDİR. Yalnız təcrübəli istifadəçilər üçün nəzərdə tutulub. Scriptin müəllifi heç bir zərərdən məsul deyil.

---

⚠️ İSTİFADƏDƏN ƏVVƏL BACKUP EDİN! ⚠️