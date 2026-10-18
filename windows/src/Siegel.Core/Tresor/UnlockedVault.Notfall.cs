using Siegel.Modell;

namespace Siegel.Core;

// Notfallkit im entsperrten Tresor (SPEC §1.5, §15): vorbereiten, bestätigen, bestehendes Kit bestätigen, Sicherungen
// entfernen – wie UnlockedVault+Notfall.swift.
public sealed partial class UnlockedVault
{
    /// <summary>Neues Kit mit dem Schema der Stufe, ohne Faktoren (Stufe 1 bzw. Format v1).</summary>
    public PendingRecovery PrepareRecovery(string masterPassword) =>
        PrepareRecovery(masterPassword, new FactorSecrets(), Level.RecoveryScheme());

    /// <summary>Bereitet ein neues Notfallkit vor (nichts geschrieben, alter Code bleibt gültig). Ein Code mit zwei
    /// Bestätigungsgruppen bzw. drei Teile mit je einer (dann bleibt <c>Code.Formatted</c> leer). Zwei Argon2-Läufe:
    /// Prüfung von Passwort + Faktoren und KEK_pw mit neuem Salz für das spätere Schreiben.</summary>
    public PendingRecovery PrepareRecovery(string masterPassword, FactorSecrets factors, RecoveryScheme scheme)
    {
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        CoreEnvironment.RequireBackgroundThread();
        if (scheme is not (RecoveryScheme.SingleCode or RecoveryScheme.Shamir2Of3)) { throw Fehler.Crypto("header.recoveryScheme"); }
        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
        lock (WriteLock)
        {
            using var scope = Enter();
            var s = scope.State;
            VerifyAccess(pw, factors, s);
            var owned = new List<IDisposable>();
            try
            {
                var r = SecureBuffer.Random(RecoveryKem.RBytes);
                owned.Add(r);
                var pk = RecoveryKem.DerivePublicKeys(r, s.Header.VaultId);
                var header = s.Header.Rebuilt(Zufall.Bytes(Core.Kdf.SaltBytes), recoveryScheme: scheme, pk: pk);
                SecureBuffer kek;
                using (var p = Core.Kdf.DeriveKek(pw, header.Salt, header.Kdf, Store.Limits))
                {
                    kek = FactorKdf.Kek(p, header, factors);
                }
                owned.Add(kek);
                var dek = SecureBuffer.Random(Aead.KeyBytes);
                owned.Add(dek);
                var (tagKey, tag) = NewTags(dek, pw);
                owned.Add(tagKey);
                owned.Add(tag);
                PendingRecovery result;
                if (scheme == RecoveryScheme.SingleCode)
                {
                    result = new PendingRecovery(RecoveryMatching.CodeFor(r, pk), VaultStore.RandomConfirmationGroups());
                }
                else
                {
                    var shares = RecoveryMatching.SharesFor(r, pk);
                    var groups = Enumerable.Range(0, Shamir.ShareCount).Select(_ => (int)Zufall.Uniform(Shamir.FullGroups)).ToList();
                    result = new PendingRecovery(new RecoveryCode("", pk.KitId), [], RecoveryScheme.Shamir2Of3, shares, groups);
                }
                owned.Clear();
                SetPending(new PendingKit(r, scheme, header, kek, dek, tagKey, tag, s.Header.Salt));
                return result;
            }
            catch
            {
                foreach (var o in owned) { o.Dispose(); }
                throw;
            }
        }
    }

    /// <summary>Bestätigt ein Kit: ein Code mit den zwei verlangten Gruppen, Teile mit drei (je Teil eine). Neues Kit →
    /// DEK-Rotation, angeheftete Sicherung „vor-neues-kit“, alter Code ungültig. Bereits gültiges Kit → nur
    /// <c>RecoveryConfirmedAt</c>. Falsche Gruppen → <c>RecoveryConfirmationMismatch</c>, nichts geschrieben. Mit
    /// versiegelten Einträgen braucht ein neues Kit <see cref="CommitRecoveryAsync"/>; hier → <c>FactorMissing</c>.</summary>
    public void CommitRecovery(PendingRecovery pending, IReadOnlyList<string> confirmation) =>
        CommitRecovery(pending, confirmation, new Dictionary<Guid, SecureBuffer>());

    /// <summary>Kern: <paramref name="releasedGroups"/> = ERS je Notfall-Gruppe für das neue Kit (gehören dem Aufrufer).</summary>
    internal void CommitRecovery(PendingRecovery pending, IReadOnlyList<string> confirmation, IReadOnlyDictionary<Guid, SecureBuffer> releasedGroups)
    {
        CheckConfirmation(pending, confirmation);
        using var r = SecretOf(pending);
        lock (WriteLock)
        {
            using var scope = Enter();
            var s = scope.State;
            if (s.Pending is { } p && p.R.ConstantTimeEquals(r))
            {
                if (!p.BasedOnSalt.AsSpan().SequenceEqual(s.Header.Salt)) { throw Fehler.Crypto("recovery.pendingStale"); }
                if (p.Scheme != s.Content.Level.RecoveryScheme()) { throw Fehler.NotAllowedAtLevel(); }
                using var content = s.Content.Clone();
                content.RecoveryConfirmedAt = Clock.Now();
                content.RewrapRecoveryGroups(releasedGroups, p.Header.Pk, s.Header.VaultId);
                var slots = VaultCrypto.MakeSlots(p.Header, p.KekPw, p.Dek);
                // Gleiche Faktoren (der Kopf wurde nur mit neuem Salz und Kit neu gebaut) → F bleibt.
                CommitNewAccess(s, p.Header, slots, p.Dek, p.TagKey, p.MasterTag, s.MasterReuseTags, content, BackupNaming.Reason.NewKit,
                    s.DuressBinding, ownsKeys: false);
            }
            else if (RecoveryKem.Matches(r, s.Header.VaultId, s.Header.Pk))
            {
                using var content = s.Content.Clone();
                content.RecoveryConfirmedAt = Clock.Now();
                Save(s, content, null);
            }
            else
            {
                throw Fehler.Crypto("recovery.pendingStale");
            }
        }
    }

    /// <summary>Prüft die eingetippten Bestätigungsgruppen (Gross/Klein, Leerraum, O/I/L egal).</summary>
    internal static void CheckConfirmation(PendingRecovery pending, IReadOnlyList<string> confirmation)
    {
        Fehler.NotNull(pending);
        Fehler.NotNull(confirmation);
        static bool Same(string typed, string group) => RecoveryCodeCodec.NormalizedGroup(typed) == group;
        if (pending.Scheme == RecoveryScheme.SingleCode)
        {
            var groups = pending.Code.Groups;
            if (pending.ConfirmationGroups.Count != 2 || confirmation.Count != 2 || groups.Count != RecoveryCodeCodec.GroupCount)
            {
                throw Fehler.ConfirmationMismatch();
            }
            for (var k = 0; k < 2; k++)
            {
                var idx = pending.ConfirmationGroups[k];
                if (idx < 0 || idx >= groups.Count || confirmation[k] is null || !Same(confirmation[k], groups[idx])) { throw Fehler.ConfirmationMismatch(); }
            }
            return;
        }
        if (pending.Shares.Count != Shamir.ShareCount || pending.ShareConfirmationGroups.Count != Shamir.ShareCount
            || confirmation.Count != Shamir.ShareCount)
        {
            throw Fehler.ConfirmationMismatch();
        }
        for (var k = 0; k < Shamir.ShareCount; k++)
        {
            var idx = pending.ShareConfirmationGroups[k];
            var groups = pending.Shares[k].Groups;
            if (idx < 0 || idx >= Shamir.FullGroups || idx >= groups.Count || confirmation[k] is null || !Same(confirmation[k], groups[idx]))
            {
                throw Fehler.ConfirmationMismatch();
            }
        }
    }

    /// <summary>R eines vorbereiteten Kits: aus dem Code bzw. aus den Teilen (alle drei müssen dasselbe R ergeben).</summary>
    internal static SecureBuffer SecretOf(PendingRecovery pending)
    {
        if (pending.Scheme == RecoveryScheme.SingleCode) { return RecoveryCodeCodec.Decode(pending.Code.Formatted); }
        if (pending.Shares.Count != Shamir.ShareCount) { throw Fehler.ConfirmationMismatch(); }
        var f = pending.Shares.Select(x => x.Formatted).ToList();
        var r = RecoveryMatching.CombineShares([f[0], f[1]]);
        using var check = RecoveryMatching.CombineShares([f[1], f[2]]);
        if (!r.ConstantTimeEquals(check))
        {
            r.Dispose();
            throw Fehler.ConfirmationMismatch();
        }
        return r;
    }

    /// <summary>Löscht alle Sicherungen dieser vaultID (auch angeheftete) und legt sofort eine des aktuellen Stands an.</summary>
    public PurgeReport PurgeBackups()
    {
        lock (WriteLock)
        {
            using var scope = Enter();
            return Store.PurgeBackups(scope.State.Header.Uuid, scope.State.Generation);
        }
    }

    /// <summary>Bestätigt das bestehende Notfallkit mit dem <b>ganzen</b> Code; passt er nicht → <c>WrongRecoveryCode</c>.</summary>
    public void ConfirmExistingRecovery(string code)
    {
        Fehler.NotNull(code);
        CoreEnvironment.RequireBackgroundThread();
        using var r = RecoveryCodeCodec.Decode(code);
        ConfirmExisting(r);
    }

    /// <summary>Wie <see cref="ConfirmExistingRecovery(string)"/>, mit zwei ganzen Teilen (Stufen 4/5).</summary>
    public void ConfirmExistingRecovery(IReadOnlyList<string> shares)
    {
        CoreEnvironment.RequireBackgroundThread();
        using var r = RecoveryMatching.CombineShares(shares);
        ConfirmExisting(r);
    }

    private void ConfirmExisting(SecureBuffer r)
    {
        lock (WriteLock)
        {
            using var scope = Enter();
            var s = scope.State;
            if (!RecoveryKem.Matches(r, s.Header.VaultId, s.Header.Pk))
            {
                var codeKit = RecoveryKem.DerivePublicKeys(r, s.Header.VaultId).KitId;
                throw Fehler.WrongRecoveryCode(codeKit, s.Header.Pk.KitId);
            }
            if (s.Content.RecoveryConfirmedAt is not null) { return; }
            using var content = s.Content.Clone();
            content.RecoveryConfirmedAt = Clock.Now();
            Save(s, content, null);
        }
    }
}
