#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Security.Cryptography;
using System.Text;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Befunde krypto-1 und krypto-2: eingefrorene Tresore des Swift-Kerns (windows/tests/Fixtures/README.md, Abschnitt
/// „Swift-Tresore mit besonderen Zeichen“) mit U+FFFE im Eintragspasswort, U+FFFE im Master-Passwort und
/// Unicode-16-Zeichen. Vorher warf der C#-Kern bei U+FFFE eine ArgumentException aus <c>string.Normalize</c> (Tresor
/// weder per Passwort noch per Notfallcode zu öffnen) und rechnete bei Unicode 16 andere Argon2-Bytes als Swift
/// (WrongPassword). Echtes Argon2 (256 MiB), seriell.
/// </summary>
[Collection("EchteProfile")]
public class SwiftUnicodeTests
{
    internal const string FffeEintragMaster = "Fffe-Eintrag#7qLm!2xV9@Rk4";
    internal const string FffeEintragCode = "E1PFH-SGMRG-YD3S3-NT32K-YXW95-E7KDG-SVTYF-9T3BQ-JMYPC-ZV94Q-59Q38";
    internal const string FffeMaster = "Wq7!vTz#2pLm\uFFFE9@Xc4$Rb8&Hn";
    internal const string FffeMasterCode = "NGBNZ-HA1DD-CDCYF-3XR13-KT37Z-EF1KS-605S3-3GZE2-S1XTE-TB1PZ-8TYJG";
    internal const string KiratMaster = "u,F?CfDuMlYWuJASPVQ*6GUG@O\U00016D67\U00016D67";
    internal const string KiratCode = "RH199-JT9ZE-D7Z38-J5A35-BEWEQ-6DK5K-4BGQ7-JDQ66-3TVKW-CNC73-GDJX0";
    private static readonly KdfParameters Kdf256 = new(3, 256UL << 20);

    private static (KernTempDir Dir, VaultStore Store) Copy(string name, string sha256)
    {
        Assert.Equal(sha256, KT.Hex(SHA256.HashData(File.ReadAllBytes(Fixtures.Windows(name)))));
        var dir = new KernTempDir();
        var store = new VaultStore(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        File.Copy(Fixtures.Windows(name), store.VaultPath);
        return (dir, store);
    }

    private static VaultEntry Eintrag(UnlockedVault v, string title) => Assert.Single(v.Entries, e => e.Title == title);

    [Fact]
    public void Fffe_im_Eintragspasswort_Entsperren_Speichern_Import_und_Notfallcode()
    {
        var (dir, store) = Copy("swift_fffe_eintrag.siegel", "7e518e61edafb7f8ab6d708d609b5b2c1de4d19af722c515a38cd9ea98c762ac");
        using (dir)
        {
            var v = KT.Unlocked(store.Unlock(FffeEintragMaster));
            Assert.NotNull(v);
            var e = Eintrag(v!, "Import FFFE");
            Assert.Equal("neu\uFFFEwert", e.Password);
            Assert.Equal(["abc\uFFFEdef"], e.History.Select(h => h.Password));
            Assert.Empty(v!.MasterPasswordReuse);
            // Den reuseTag hat Swift geschrieben; C# rechnet für U+FFFE dieselben Bytes (sonst neue meta beim Speichern).
            var content = v.ContentForTesting!;
            using (content)
            using (var reuseKey = content.ReuseKey())
            {
                Assert.Equal(KT.Hex(content.Meta[e.Id].Tag!), KT.Hex(EntrySealing.ReuseTag(reuseKey, e.Password)!));
            }
            // Speichern mit U+FFFE (vorher: ArgumentException aus ReuseTag beim Persistieren)
            e.Password = "dritt\uFFFEes";
            v.Upsert(e);
            Assert.Equal(["abc\uFFFEdef", "neu\uFFFEwert"], Eintrag(v, "Import FFFE").History.Select(h => h.Password));
            var import = v.ImportEntries([KT.Entry("Import FFFE", "anna", "dritt\uFFFEes", "https://importfffe.example.ch"),
                KT.Entry("Neu", "bert", "x\uFFFEy", "https://neu.example.ch")]);
            Assert.Equal((1, 1, 0), (import.Added, import.SkippedDuplicates, import.Conflicts));
            v.Lock();

            var wieder = KT.Unlocked(store.Unlock(FffeEintragMaster));
            Assert.Equal("dritt\uFFFEes", Eintrag(wieder!, "Import FFFE").Password);
            wieder!.Lock();

            // Notfallweg (vorher: ArgumentException aus MasterTag.IsUsedByEntries)
            var neu = store.Recover(FffeEintragCode, KT.Pw2, Kdf256);
            Assert.Equal(3, neu.Entries.Count);
            neu.Lock();
            Assert.NotNull(KT.Unlocked(store.Unlock(KT.Pw2)));
        }
    }

    [Fact]
    public void Fffe_im_Master_Passwort_Entsperren_Vergleichen_Anlegen_Wechseln()
    {
        var (dir, store) = Copy("swift_fffe_master.siegel", "90cd463118fb026c11ca5288c5d2c856741f47147751e4a5ecc6542bba9d8979");
        using (dir)
        {
            Assert.True(VaultStore.PasswordsMatch(FffeMaster, FffeMaster));
            Assert.True(VaultStore.PasswordsMatch(FffeMaster, FffeMaster.Replace(' ', '\u00A0')));
            Assert.False(VaultStore.PasswordsMatch(FffeMaster, FffeMaster.Replace("\uFFFE", "", StringComparison.Ordinal)));
            using (var bytes = PasswordNormalizer.SecureBytes(FffeMaster))
            using (var l = bytes.Borrow())
            {
                Assert.Equal(Encoding.UTF8.GetBytes(FffeMaster), l.Span.ToArray());
            }
            var v = KT.Unlocked(store.Unlock(FffeMaster));
            Assert.NotNull(v);
            Assert.Equal(["Kette+Sattel-77"], v!.Entries.Select(e => e.Password));
            Assert.True(v.Verify(FffeMaster));
            const string neuesPw = "Neu\uFFFE-v,:f,uX&%!kQ>NiIti@!3c>w:~";
            v.ChangeMasterPassword(FffeMaster, neuesPw);
            v.Lock();
            KT.Throws(SiegelErrorCode.WrongPassword, () => store.Unlock(FffeMaster));
            KT.Unlocked(store.Unlock(neuesPw))!.Lock();

            // Notfallweg mit einem neuen U+FFFE-Passwort
            store.Recover(FffeMasterCode, FffeMaster, Kdf256).Lock();
            KT.Unlocked(store.Unlock(FffeMaster))!.Lock();

            // Neuer Tresor mit diesem Passwort (vorher: ArgumentException aus CheckPolicy)
            using var leer = new KernTempDir();
            var zweiter = new VaultStore(leer.Sub("Siegel"), new InMemoryRollbackGuard());
            var (angelegt, _) = zweiter.Create(FffeMaster, Kdf256);
            angelegt.Lock();
            KT.Unlocked(zweiter.Unlock(FffeMaster))!.Lock();
        }
    }

    [Fact]
    public void Unicode16_Master_Passwort_wie_Swift_und_fuer_Neues_abgelehnt()
    {
        var (dir, store) = Copy("swift_kirat_master.siegel", "1d1cc934303fa1bf841e3c856ecd6a0f67298296879c2b03c15c30f962654277");
        using (dir)
        {
            // Foundation (macOS 26) setzt U+16D67 U+16D67 nicht zusammen; .NET mit ICU 76 täte es (→ WrongPassword).
            Assert.Equal(KiratMaster, PasswordNormalizer.Normalize(KiratMaster));
            var v = KT.Unlocked(store.Unlock(KiratMaster));
            Assert.NotNull(v);
            Assert.Equal(["Kirat", "Todhri", "Gurung", "Tulu", "Zerlegt"], v!.Entries.Select(e => e.Title));
            Assert.Equal("Cafe\u0301-Passwort-12", Eintrag(v, "Zerlegt").Password);
            // reuseTag aller Einträge: dieselbe Normalisierung wie Swift (Kirat Rai/Todhri bleiben, Gurung/Tulu zusammen)
            var content = v.ContentForTesting!;
            using (content)
            using (var reuseKey = content.ReuseKey())
            {
                foreach (var e in v.Entries)
                {
                    Assert.Equal(KT.Hex(content.Meta[e.Id].Tag!), KT.Hex(EntrySealing.ReuseTag(reuseKey, e.Password)!));
                }
            }
            // krypto-4: der Mac-Eintrag „Zerlegt“ (NFD) und dasselbe Passwort in NFC sind für Swift gleich → übersprungen
            var import = v.ImportEntries([KT.Entry("Zerlegt", "anna", "Caf\u00E9-Passwort-12", "https://zerlegt.example.ch")]);
            Assert.Equal((0, 1, 0), (import.Added, import.SkippedDuplicates, import.Conflicts));
            var zerlegt = Eintrag(v, "Zerlegt");
            zerlegt.Password = "Caf\u00E9-Passwort-12";
            v.Upsert(zerlegt);
            Assert.Empty(Eintrag(v, "Zerlegt").History);
            // Regel ab v4.7: neue Passwörter nur mit Zeichen aus Unicode 15.0
            KT.Throws(SiegelErrorCode.PasswordTooWeak, () => v.ChangeMasterPassword(KiratMaster, KT.Pw2 + "\U00016D67", Kdf256));
            v.Lock();
            KT.Throws(SiegelErrorCode.PasswordTooWeak, () => store.Recover(KiratCode, KiratMaster, Kdf256));
            store.Recover(KiratCode, KT.Pw2, Kdf256).Lock();

            using var leer = new KernTempDir();
            var zweiter = new VaultStore(leer.Sub("Siegel"), new InMemoryRollbackGuard());
            KT.Throws(SiegelErrorCode.PasswordTooWeak, () => zweiter.Create(KiratMaster, Kdf256));
            Assert.False(zweiter.VaultExists);
        }
    }
}
#endif
