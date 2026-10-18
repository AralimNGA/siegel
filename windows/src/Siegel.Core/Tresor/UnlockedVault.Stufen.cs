using Siegel.Modell;

namespace Siegel.Core;

// Sicherheitsstufen und Faktoren (SPEC §13, §14, §16, §22), wie UnlockedVault+Stufen.swift. Der Eintrags-Gerätefaktor
// kann zusätzlich die Windows-Hello-Art sein (SPEC-WINDOWS W4.1).
public sealed partial class UnlockedVault
{
    /// <summary>Faktoren für Einträge einrichten (öffentliche Teile in den Inhalt, §16): Eintrags-Gerätefaktor
    /// (<c>EntryKey</c>, Mac-P-256 oder Windows Hello), Karte, Sicherheitsschlüssel. <c>material.SecureEnclave</c> gehört
    /// zur Stufe und wird hier nicht verwendet. Braucht Master-Passwort und alle Faktoren der Stufe; DEK und Salz
    /// bleiben. Andere Karte als die zum Öffnen → <c>WrongCard</c>; anderer Sicherheitsschlüssel → <c>NotAllowedAtLevel</c>.</summary>
    public void EnrollFactors(NewFactorMaterial material, string masterPassword, FactorSecrets currentFactors)
    {
        Fehler.NotNull(material);
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(currentFactors);
        CoreEnvironment.RequireBackgroundThread();
        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
        ValidateMaterial(material);
        lock (WriteLock)
        {
            using var scope = Enter();
            var s = scope.State;
            VerifyAccess(pw, currentFactors, s);
            var vaultId = s.Header.VaultId;
            var keys = s.Content.EntryFactors;
            if (material.EntryKey is { } ek) { keys = WithEntryKey(keys, ek); }
            if (material.Card is { } card)
            {
                var tag = CardCode.TagBytesFor(card.Q, vaultId);
                if (s.Header.FactorFields.CardTag is { } opening && !opening.AsSpan().SequenceEqual(tag)) { throw Fehler.WrongCard(); }
                keys = keys with { Card = CardKeyFor(card.Q, vaultId) };
            }
            if (material.SecurityKey is { } k)
            {
                if (s.Header.FactorFields.FidoCredentialId is { } cred)
                {
                    if (!k.CredentialId.Span.SequenceEqual(cred) || !Bytes.Same(k.Salt.ToArray(), s.Header.FactorFields.FidoSalt)
                        || currentFactors.SecurityKey is not { } current || !current.ConstantTimeEquals(k.Output))
                    {
                        throw Fehler.NotAllowedAtLevel();
                    }
                }
                keys = keys with { SecurityKey = SecurityKeyFor(k, vaultId) };
            }
            if (keys.Equals(s.Content.EntryFactors)) { return; }
            CheckReplacement(s.Content.EntryFactors, keys, s.Content);
            using var content = s.Content.Clone();
            content.EntryFactors = keys;
            Save(s, content, null);
        }
    }

    /// <summary>
    /// Stufe wechseln (auf- und abwärts, §13). Braucht das Master-Passwort und alle Faktoren der aktuellen Stufe, erneuert
    /// DEK und KDF-Salz und schreibt sofort („vor-stufenwechsel“). Faktoren der Zielstufe: neu aus
    /// <paramref name="newFactors"/> oder die bisherigen aus <paramref name="currentFactors"/>. Verlangt die Zielstufe ein
    /// anderes Notfall-Schema, ist ein neues Kit Pflicht (sonst <c>NotAllowedAtLevel</c>). KDF: Profil der Zielstufe.
    /// Abwärts wird der nicht mehr gebrauchte Entsperr-Schlüssel erst nach dem Schreiben entfernt. Mit versiegelten
    /// Einträgen und neuem Kit → <see cref="ChangeSecurityLevelAsync"/>; hier <c>FactorMissing</c>.
    /// </summary>
    public void ChangeSecurityLevel(SecurityLevel level, string masterPassword, FactorSecrets currentFactors, NewFactorMaterial newFactors,
        PendingRecovery? recovery, IReadOnlyList<string> recoveryConfirmation) =>
        ChangeSecurityLevel(level, masterPassword, currentFactors, newFactors, recovery, recoveryConfirmation,
            new Dictionary<Guid, SecureBuffer>(), null);

    /// <summary>Kern des Stufenwechsels. <paramref name="releasedGroups"/>: ERS je Gruppe; <paramref name="verifiedSalt"/>:
    /// Zugang für genau diesen Kopf schon geprüft (kein zweites Argon2).</summary>
    internal void ChangeSecurityLevel(SecurityLevel level, string masterPassword, FactorSecrets currentFactors, NewFactorMaterial newFactors,
        PendingRecovery? recovery, IReadOnlyList<string> recoveryConfirmation, IReadOnlyDictionary<Guid, SecureBuffer> releasedGroups,
        byte[]? verifiedSalt)
    {
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(currentFactors);
        Fehler.NotNull(newFactors);
        Fehler.NotNull(recoveryConfirmation);
        CoreEnvironment.RequireBackgroundThread();
        if (!level.IsValid()) { throw Fehler.Crypto("level.invalid"); }
        ValidateMaterial(newFactors);
        SecureBuffer? kitR = null;
        try
        {
            if (recovery is not null)
            {
                CheckConfirmation(recovery, recoveryConfirmation);
                if (recovery.Scheme != level.RecoveryScheme()) { throw Fehler.NotAllowedAtLevel(); }
                kitR = SecretOf(recovery);
            }
            using var pw = PasswordNormalizer.SecureBytes(masterPassword);
            lock (WriteLock)
            {
                using var scope = Enter();
                var s = scope.State;
                if (kitR is null && s.Header.RecoveryScheme != level.RecoveryScheme()) { throw Fehler.NotAllowedAtLevel(); }
                var kdf = Store.Limits.Profile(level);
                Store.Limits.Validate(kdf);
                CheckDestructionAllows(level, kdf, s);
                if (verifiedSalt is null || !verifiedSalt.AsSpan().SequenceEqual(s.Header.Salt)) { VerifyAccess(pw, currentFactors, s); }

                var plan = PlanFactors(level, s, currentFactors, newFactors);
                CheckReplacement(s.Content.EntryFactors, plan.EntryKeys, s.Content);

                // Notfallkit: neues (vorbereitet und bestätigt) oder das bisherige.
                var pk = s.Header.Pk;
                var scheme = s.Header.RecoveryScheme;
                using var content = s.Content.Clone();
                if (kitR is not null)
                {
                    if (s.Pending is not { } p || !p.R.ConstantTimeEquals(kitR)) { throw Fehler.Crypto("recovery.pendingStale"); }
                    pk = p.Header.Pk;
                    scheme = p.Scheme;
                    content.RecoveryConfirmedAt = Clock.Now();
                }
                content.Level = level;
                content.EntryFactors = plan.EntryKeys;
                if (!pk.Equals(s.Header.Pk)) { content.RewrapRecoveryGroups(releasedGroups, pk, s.Header.VaultId); }

                var (header, slots, dek) = Store.Rekey(s.Header.VaultId, kdf, plan.Fields, scheme, pk, pw, plan.Secrets);
                SecureBuffer? binding = null;
                SecureBuffer tagKey, tag;
                try
                {
                    // F folgt den Faktoren der Zielstufe (v4.4).
                    binding = DuressCrypto.Binding(header, plan.Secrets);
                    (tagKey, tag) = NewTags(dek, pw);
                }
                catch
                {
                    dek.Dispose();
                    binding?.Dispose();
                    throw;
                }
                CommitNewAccess(s, header, slots, dek, tagKey, tag, s.MasterReuseTags, content, BackupNaming.Reason.LevelChange, binding,
                    ownsKeys: true);
                // Erst nach erfolgreichem Schreiben: nicht mehr gebrauchten Entsperr-Schlüssel entfernen.
                if (s.Header.FactorFields.SeKeyId is { } old && old != plan.Fields.SeKeyId) { Store.RemoveHardwareKey(old); }
            }
        }
        finally
        {
            kitR?.Dispose();
        }
    }

    /// <summary>Selbstvernichtung (§23): eingeschaltet nur in Stufe 4/5; mit Vernichtungs-Passwort kein anderes KDF-Profil.</summary>
    internal static void CheckDestructionAllows(SecurityLevel level, KdfParameters kdf, State s)
    {
        if (s.Content.Destruction is not { } d) { return; }
        if (level < SecurityLevel.Maximal && (d.Settings.AnyTriggerEnabled || s.Content.Destructible.Count > 0 || d.VKey is not null))
        {
            throw Fehler.NotAllowedAtLevel();
        }
        if (d.Duress is not null && kdf != s.Header.Kdf) { throw Fehler.NotAllowedAtLevel(); }
    }

    /// <summary>Eintrags-Faktoren, an denen versiegelte Einträge hängen, dürfen nicht ersetzt werden → <c>NotAllowedAtLevel</c>.</summary>
    internal static void CheckReplacement(EntryFactorKeys old, EntryFactorKeys next, VaultContent content)
    {
        var used = content.SealedKinds;
        if (used.Contains(FactorKind.SecureEnclave) && (!Equals(old.SecureEnclave, next.SecureEnclave) || !Equals(old.WindowsHello, next.WindowsHello)))
        {
            throw Fehler.NotAllowedAtLevel();
        }
        if (used.Contains(FactorKind.Card) && !Equals(old.Card, next.Card)) { throw Fehler.NotAllowedAtLevel(); }
        if (used.Contains(FactorKind.SecurityKey) && !Equals(old.SecurityKey, next.SecurityKey)) { throw Fehler.NotAllowedAtLevel(); }
    }

    internal sealed record FactorPlan(HeaderFactorFields Fields, FactorSecrets Secrets, EntryFactorKeys EntryKeys);

    /// <summary>Kopf-Felder, Faktor-Werte (gehören weiter dem Aufrufer) und Eintrags-Schlüssel der Zielstufe.</summary>
    internal static FactorPlan PlanFactors(SecurityLevel level, State s, FactorSecrets current, NewFactorMaterial next)
    {
        var vaultId = s.Header.VaultId;
        var head = s.Header.FactorFields;
        var entryKeys = s.Content.EntryFactors;
        var fields = HeaderFactorFields.None;
        var secrets = new FactorSecrets();
        if (next.EntryKey is { } ek) { entryKeys = WithEntryKey(entryKeys, ek); }
        if (next.Card is { } nc) { entryKeys = entryKeys with { Card = CardKeyFor(nc.Q, vaultId) }; }
        if (next.SecurityKey is { } nk) { entryKeys = entryKeys with { SecurityKey = SecurityKeyFor(nk, vaultId) }; }

        if (level.Factors().Contains(FactorKind.SecureEnclave))
        {
            if (next.SecureEnclave is { } se)
            {
                fields = fields with { SeKeyId = se.KeyId };
                secrets.SecureEnclave = se.Secret;
            }
            else if (head.SeKeyId is { } id && current.SecureEnclave is { } secret)
            {
                fields = fields with { SeKeyId = id };
                secrets.SecureEnclave = secret;
            }
            else
            {
                throw Fehler.FactorMissing(FactorKind.SecureEnclave);
            }
        }

        if (level.Factors().Contains(FactorKind.Card))
        {
            FactorSecret q;
            if (next.Card is { } card)
            {
                q = card.Q;
            }
            else
            {
                if ((head.CardTag ?? s.Content.EntryFactors.Card?.Tag) is not { } known || current.Card is not { } scanned)
                {
                    throw Fehler.FactorMissing(FactorKind.Card);
                }
                if (!CardCode.TagBytesFor(scanned, vaultId).AsSpan().SequenceEqual(known)) { throw Fehler.WrongCard(); }
                q = scanned;
            }
            fields = fields with { CardTag = CardCode.TagBytesFor(q, vaultId) };
            secrets.Card = q;
            if (entryKeys.Card is null) { entryKeys = entryKeys with { Card = CardKeyFor(q, vaultId) }; }
        }

        if (level.Factors().Contains(FactorKind.SecurityKey))
        {
            if (next.SecurityKey is { } k)
            {
                fields = fields with { FidoCredentialId = k.CredentialId.ToArray(), FidoSalt = k.Salt.ToArray() };
                secrets.SecurityKey = k.Output;
            }
            else if (head.FidoCredentialId is { } cred && head.FidoSalt is { } salt && current.SecurityKey is { } output)
            {
                // Schon im Kopf: beim Prüfen des Zugangs bestätigt.
                fields = fields with { FidoCredentialId = cred, FidoSalt = salt };
                secrets.SecurityKey = output;
            }
            else if (s.Content.EntryFactors.SecurityKey is { } enrolled && current.SecurityKey is { } output2)
            {
                // Nur für Einträge eingerichtet: Ausgabe zum Entsperr-Salz über den Prüfwert bestätigen.
                if (!Bytes.ConstantTimeEqual(FactorKdf.FidoCheck(output2, vaultId), enrolled.Check)) { throw Fehler.WrongPassword(); }
                fields = fields with { FidoCredentialId = enrolled.CredentialId, FidoSalt = enrolled.Salt };
                secrets.SecurityKey = output2;
            }
            else
            {
                throw Fehler.FactorMissing(FactorKind.SecurityKey);
            }
        }
        return new FactorPlan(fields, secrets, entryKeys);
    }

    // MARK: Faktor-Material prüfen und umsetzen

    /// <summary>Längen und Werte des neuen Materials (von der Plattformschicht), bevor gerechnet wird.</summary>
    internal static void ValidateMaterial(NewFactorMaterial m)
    {
        if (m.SecureEnclave is { } se && se.KeyId == Guid.Empty) { throw Fehler.Crypto("factor.keyID"); }
        if (m.SecureEnclave is { } s2) { Fehler.NotNull(s2.Secret); }
        if (m.EntryKey is { } ek)
        {
            if (ek.KeyId == Guid.Empty) { throw Fehler.Crypto("factor.keyID"); }
            _ = DeviceKeyOf(ek);
        }
        if (m.Card is { } c) { Fehler.NotNull(c.Q); }
        if (m.SecurityKey is { } k)
        {
            if (k.CredentialId.Length is < VaultHeader.MinFidoCredential or > VaultHeader.MaxFidoCredential
                || k.Salt.Length != VaultHeader.FidoSaltBytes || k.EntrySalt.Length != VaultHeader.FidoSaltBytes
                || Bytes.AllZero(k.Salt.Span) || Bytes.AllZero(k.EntrySalt.Span) || k.Salt.Span.SequenceEqual(k.EntrySalt.Span)
                || k.Output is null || k.EntryOutput is null)
            {
                throw Fehler.Crypto("factor.securityKey");
            }
        }
    }

    /// <summary>Eintrags-Gerätefaktor aus dem Material: Mac-P-256 (x963, gültiger Punkt) oder Windows Hello (ohne
    /// öffentlichen Teil). Sonst <c>Crypto("factor.publicKey")</c>.</summary>
    internal static object DeviceKeyOf(EntryKeyEnrollment ek)
    {
        switch (ek.Kind)
        {
            case DeviceKeyKind.SecureEnclaveP256:
                if (ek.PublicKey.Length != P256.PublicKeyBytes || !P256.IsValidPublicKey(ek.PublicKey.Span)) { throw Fehler.Crypto("factor.publicKey"); }
                return new EntryFactorKeys.SecureEnclaveKey(ek.KeyId, ek.PublicKey.ToArray());
            case DeviceKeyKind.WindowsHello:
                if (!ek.PublicKey.IsEmpty) { throw Fehler.Crypto("factor.publicKey"); }
                return new EntryFactorKeys.HelloKey(ek.KeyId);
            default:
                throw Fehler.Crypto("factor.publicKey");
        }
    }

    /// <summary>Eintrags-Gerätefaktor ersetzen (die beiden Arten schliessen sich aus).</summary>
    internal static EntryFactorKeys WithEntryKey(EntryFactorKeys keys, EntryKeyEnrollment ek) =>
        DeviceKeyOf(ek) switch
        {
            EntryFactorKeys.SecureEnclaveKey se => keys with { SecureEnclave = se, WindowsHello = null },
            EntryFactorKeys.HelloKey h => keys with { SecureEnclave = null, WindowsHello = h },
            _ => throw Fehler.Crypto("factor.publicKey"),
        };

    /// <summary>Vernichtungsschlüssel V aus dem Material (beide Arten).</summary>
    internal static DestructionConfig.VKeyInfo VKeyOf(EntryKeyEnrollment ek) =>
        DeviceKeyOf(ek) switch
        {
            EntryFactorKeys.SecureEnclaveKey se => new DestructionConfig.VKeyInfo(se.KeyId, se.PublicKey),
            EntryFactorKeys.HelloKey h => new DestructionConfig.VKeyInfo(h.KeyId, [], h.Version),
            _ => throw Fehler.Crypto("factor.publicKey"),
        };

    internal static EntryFactorKeys.CardKey CardKeyFor(FactorSecret q, byte[] vaultId) =>
        new(CardCode.TagBytesFor(q, vaultId), EntryKeyDerivation.CardPublicKeys(q, vaultId));

    internal static EntryFactorKeys.SecurityKeyInfo SecurityKeyFor(SecurityKeyEnrollment k, byte[] vaultId) =>
        new(k.CredentialId.ToArray(), k.Salt.ToArray(), FactorKdf.FidoCheck(k.Output, vaultId), k.EntrySalt.ToArray(),
            EntryKeyDerivation.FidoPublicKeys(k.EntryOutput, vaultId));
}
