#!/bin/bash
# Grep-Sperren (SPEC §5): verbotene Muster in allem, was in die App kommt, Abbruch mit Datei:Zeile.
#
# Aufruf:  skripte/grep_sperren.sh                 prüft Sources/SiegelCore, SiegelUI, SiegelHardware, Siegel
#                                                  und Erweiterungen/SiegelAutofill (falls vorhanden)
#          skripte/grep_sperren.sh <Datei|Ordner>…  prüft nur diese Swift-Dateien
#          skripte/grep_sperren.sh --selbsttest     Positiv- und Negativbeispiele
#
# Gesperrt: try!, print debugPrint dump NSLog NSLogv (als Aufruf, auch `print`( und (print)(, und als Funktionswert,
# z. B. `let d: (String, String?, Int, Int, Int) -> String = dump` – das kompiliert), Dictionary(uniqueKeysWithValues:,
# privacy: .public (dazu %{public} in os_log-Formaten), fatalError( precondition( assert( (auch
# preconditionFailure(, assertionFailure() mit String-Interpolation oder mit einer Meldung, die kein fester Text ist.
#
# Damit es wenig Fehlalarme gibt, blendet ein kleiner Swift-Lexer zuerst Kommentare (auch verschachtelte
# Blockkommentare), den Text von Zeichenketten (normale, mehrzeilige und #"roh"#-Zeichenketten) und
# Regex-Literale aus (#/…/# auch mehrzeilig; /…/ einzeilig, nur nach = ( , [ : { ; ! & | ? + - * < > % ^ ~ oder
# einem Schlüsselwort wie try, await, return, in, case und ohne Leerzeichen nach dem ersten /, sonst ist es eine
# Division). Code in \( … ) bleibt sichtbar. Rückfallnetz (Befund bau-4): Liest die Heuristik ein / als Division,
# obwohl dahinter ein /…"…/ steht (ein " würde sonst eine Zeichenkette öffnen und den Rest ausblenden, bei """ sogar
# die folgenden Zeilen), prüft ein zweiter Lauf die Datei mit /…/ als Regex; gemeldet wird, was einer der Läufe findet.
# Bezeichner wie NSPrintOperation, printPanel, fingerprint, Argument-Labels (print:) und Methodenaufrufe wie
# view.print(nil) oder logger.dump( zählen nicht, Swift.print( und Swift.dump( schon.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

read -r -d '' PRUEFER <<'PERL' || true
use strict;
use warnings;
use File::Find ();
$| = 1;

my $root = shift @ARGV;
my @files;
for my $p (@ARGV) {
    if (-d $p) {
        File::Find::find({ no_chdir => 1,
                           wanted => sub { push @files, $File::Find::name if -f $_ && /\.swift\z/ } }, $p);
    } elsif (-f $p) {
        push @files, $p;
    } else {
        print STDERR "Grep-Sperren: nicht gefunden: $p\n";
        exit 2;
    }
}
@files = sort @files;

sub blank { my $s = shift; $s =~ tr/\n/ /c; return $s }

# Liefert zwei Texte gleicher Länge wie die Quelle (Zeilen bleiben erhalten):
#   masked: ohne Kommentare, Zeichenketten-Inhalt als Leerzeichen, Interpolation \( als "\x01(" + Code
#   plain:  ohne Kommentare, Zeichenketten unverändert
# und als drittes, ob ein / als Division gelesen wurde, hinter dem ein /…"…/ steht (dann zweiter Lauf mit
# $zweiter = 1, der es als Regex-Literal liest).
sub lex {
    my ($src, $zweiter) = @_;
    my $verdacht = 0;
    my ($masked, $plain) = ('', '');
    my @stack = ({ kind => 'code', depth => 0, interp => 0 });
    my $len = length $src;
    pos($src) = 0;
    while (pos($src) < $len) {
        my $ctx = $stack[-1];
        if ($ctx->{kind} eq 'code') {
            if ($src =~ /\G(\/\/[^\n]*)/gc) {
                my $b = blank($1); $masked .= $b; $plain .= $b;
            } elsif ($src =~ /\G\/\*/gc) {
                my ($depth, $start) = (1, pos($src) - 2);
                while ($depth > 0 && pos($src) < $len) {
                    if    ($src =~ /\G\/\*/gc) { $depth++ }
                    elsif ($src =~ /\G\*\//gc) { $depth-- }
                    else  { $src =~ /\G(?:[^\/*]+|.)/gcs }
                }
                my $b = blank(substr($src, $start, pos($src) - $start)); $masked .= $b; $plain .= $b;
            } elsif ($src =~ /\G((#+)\/(?:[^\\\/]|\\.|\/(?!\2))*\/\2)/gcs) {
                # erweitertes Regex-Literal #/…/# (darf mehrzeilig sein): Inhalt ausblenden wie bei Zeichenketten
                my $b = blank($1); $masked .= $b; $plain .= $b;
            } elsif (substr($src, pos($src), 1) eq '/'
                     && defined(my $lit = simple_regex(\$src, \$masked, $zweiter, \$verdacht))) {
                # einfaches Regex-Literal /…/ (nur einzeilig, Escapes wie \/ und \" überspringen)
                my $b = blank($lit); $masked .= $b; $plain .= $b;
            } elsif ($src =~ /\G(#*)("""|")/gc) {
                my ($h, $q) = ($1, $2);
                push @stack, { kind => 'str', hashes => length($h), multi => length($q) == 3 };
                $masked .= '"' . (' ' x (length($h) + length($q) - 1));
                $plain  .= $h . $q;
            } elsif ($src =~ /\G\(/gc) {
                $ctx->{depth}++; $masked .= '('; $plain .= '(';
            } elsif ($src =~ /\G\)/gc) {
                if ($ctx->{interp} && $ctx->{depth} == 0) { pop @stack }
                elsif ($ctx->{depth} > 0) { $ctx->{depth}-- }
                $masked .= ')'; $plain .= ')';
            } else {
                $src =~ /\G([^\/"#()]+|.)/gcs; $masked .= $1; $plain .= $1;
            }
        } else {
            my $h = '#' x $ctx->{hashes};
            my $close = ($ctx->{multi} ? '"""' : '"') . $h;
            if ($src =~ /\G\Q$close\E/gc) {
                pop @stack;
                $masked .= (' ' x (length($close) - 1)) . '"'; $plain .= $close;
            } elsif ($src =~ /\G\\\Q$h\E\(/gc) {
                push @stack, { kind => 'code', depth => 0, interp => 1 };
                $masked .= "\x01" . (' ' x length($h)) . '('; $plain .= "\\$h(";
            } elsif ($src =~ /\G(\\\Q$h\E.)/gcs) {
                $masked .= blank($1); $plain .= $1;
            } elsif (!$ctx->{multi} && $src =~ /\G\n/gc) {
                pop @stack; $masked .= "\n"; $plain .= "\n";   # einzeilige Zeichenkette ohne Ende
            } else {
                $src =~ /\G([^"\\\n]+|.)/gcs; $masked .= blank($1); $plain .= $1;
            }
        }
    }
    return ($masked, $plain, $verdacht);
}

# Steht an pos($$src) ein einfaches Regex-Literal /…/? Liefert es (pos dahinter) oder undef (pos unverändert).
# Erster Lauf: nur wo regex_allowed es erlaubt. Steht dort laut Heuristik eine Division, das /…/ enthält aber ein ",
# wird $$verdacht gesetzt; der zweite Lauf ($zweiter) liest es dann als Regex-Literal.
sub simple_regex {
    my ($src, $masked, $zweiter, $verdacht) = @_;
    my $start = pos($$src);
    return undef unless $$src =~ /\G(\/(?![\s\/*])(?:[^\\\/\n]|\\[^\n])*\/)/gc;
    my $lit = $1;
    return $lit if regex_allowed($masked);
    if ($lit =~ /"/) {
        $$verdacht = 1;
        return $lit if $zweiter;
    }
    pos($$src) = $start;
    return undef;
}

# Darf an dieser Stelle ein einfaches Regex-Literal /…/ beginnen? Nur nach = ( , [ : { ; ! & | ? + - * < > % ^ ~
# (letztes Zeichen der bisher ausgeblendeten Ausgabe ohne Leerraum) oder nach einem Schlüsselwort, hinter dem ein
# Ausdruck beginnt (try, await, return, in, case …); sonst ist / eine Division.
sub regex_allowed {
    my ($r) = @_;
    my $i = length($$r) - 1;
    $i-- while $i >= 0 && substr($$r, $i, 1) =~ /\s/;
    return 0 if $i < 0;
    return 1 if index('=(,[:{;!&|?+-*<>%^~', substr($$r, $i, 1)) >= 0;
    my $vor = $i >= 15 ? substr($$r, $i - 15, 16) : substr($$r, 0, $i + 1);
    return 1 if $vor =~ /(?<![A-Za-z0-9_.`])(?:try|await|in|throw|case|where|else|guard|if|while|switch|return|yield)\z/;
    return 0;
}

# Empfänger vor ".name(": undef = kein Punkt davor, sonst der Bezeichner davor ('' bei .name, x?.name, ).name)
sub receiver {
    my ($t, $p) = @_;
    my $i = $p - 1;
    $i-- while $i >= 0 && substr($t, $i, 1) =~ /\s/;
    return undef if $i < 0 || substr($t, $i, 1) ne '.';
    $i--;
    $i-- while $i >= 0 && substr($t, $i, 1) =~ /\s/;
    my $end = $i;
    $i-- while $i >= 0 && substr($t, $i, 1) =~ /[A-Za-z0-9_]/;
    return substr($t, $i + 1, $end - $i);
}

# Deklaration "func name(" oder "case name(" (eigene Funktion/Enum-Fall, kein Aufruf)
sub declaration {
    my ($t, $p) = @_;
    my $before = substr($t, $p >= 40 ? $p - 40 : 0, $p >= 40 ? 40 : $p);
    return $before =~ /(?<![A-Za-z0-9_])(?:func|case)\s+\z/;
}

# Text zwischen "(" (Position $start = erstes Zeichen danach) und der passenden ")"
sub balanced {
    my ($t, $start) = @_;
    my $depth = 0;
    for (my $i = $start; $i < length $t; $i++) {
        my $c = substr($t, $i, 1);
        if    ($c eq '(' || $c eq '[' || $c eq '{') { $depth++ }
        elsif ($c eq ')' || $c eq ']' || $c eq '}') {
            return substr($t, $start, $i - $start) if $depth == 0;
            $depth--;
        }
    }
    return undef;
}

sub top_level_args {
    my ($args) = @_;
    my @parts;
    my ($cur, $depth) = ('', 0);
    for my $c (split //, $args) {
        if    ($c =~ /[(\[{]/) { $depth++ }
        elsif ($c =~ /[)\]}]/) { $depth-- }
        if ($c eq ',' && $depth == 0) { push @parts, $cur; $cur = ''; next }
        $cur .= $c;
    }
    push @parts, $cur if $args =~ /\S/;
    return @parts;
}

# Verstösse in einer ausgeblendeten Fassung der Quelle: Liste von [Zeile, Grund]
sub verstoesse {
    my ($masked, $plain) = @_;
    my @hits;
    my $hit = sub { my ($p, $why) = @_; push @hits, [(substr($masked, 0, $p) =~ tr/\n//) + 1, $why] };

    while ($masked =~ /(?<![A-Za-z0-9_])try!/g) { $hit->($-[0], 'try!') }

    # Aufruf, auch `print`( und (print)( – sonst als Funktionswert (dump mit ausdrücklichem Typ kompiliert)
    while ($masked =~ /(?<![A-Za-z0-9_`])`?(print|debugPrint|dump|NSLogv?)`?(?![A-Za-z0-9_])/g) {
        my ($name, $p, $e) = ($1, $-[0], $+[0]);
        my $recv = receiver($masked, $p);
        next if defined $recv && $name !~ /\ANSLogv?\z/ && $recv !~ /\A(?:Swift|Foundation|Darwin)\z/;
        next if !defined $recv && declaration($masked, $p);
        my $rest = substr($masked, $e, 200);
        if ($rest =~ /\A\s*\)*\s*\(/) { $hit->($p, "$name("); next }
        next if $rest =~ /\A\s*:(?!:)/;   # Argument- oder Parameter-Label "print:"
        $hit->($p, "$name als Funktionswert");
    }

    while ($masked =~ /(?<![A-Za-z0-9_])uniqueKeysWithValues\s*:/g) {
        $hit->($-[0], 'Dictionary(uniqueKeysWithValues:');
    }

    while ($masked =~ /(?<![A-Za-z0-9_])privacy\s*:\s*(?:OSLogPrivacy\s*)?\.public(?![A-Za-z0-9_])/g) {
        $hit->($-[0], 'privacy: .public');
    }
    while ($plain =~ /%\{public\}/g) { $hit->($-[0], '%{public} im Log-Format') }

    while ($masked =~ /(?<![A-Za-z0-9_`])`?(fatalError|preconditionFailure|precondition|assertionFailure|assert)`?\s*\)*\s*\(/g) {
        my ($name, $p, $open) = ($1, $-[0], $+[0]);
        my $recv = receiver($masked, $p);
        next if defined $recv && $recv ne 'Swift';
        next if !defined $recv && declaration($masked, $p);
        my $args = balanced($masked, $open);
        next unless defined $args;
        if ($args =~ /\x01/) { $hit->($p, "$name( mit String-Interpolation"); next }
        my @unlabeled = grep { !/\A\s*[A-Za-z_][A-Za-z0-9_]*\s*:(?!:)/ } top_level_args($args);
        my $msg = ($name eq 'precondition' || $name eq 'assert') ? $unlabeled[1] : $unlabeled[0];
        if (defined $msg && $msg !~ /\A\s*"[^"]*"\s*\z/) { $hit->($p, "$name( Meldung ist kein fester Text") }
    }
    return @hits;
}

my $total = 0;
for my $file (@files) {
    open(my $fh, '<:raw', $file) or do { print STDERR "Grep-Sperren: nicht lesbar: $file\n"; exit 2 };
    my $src = do { local $/; <$fh> };
    close $fh;
    $src = '' unless defined $src;
    my ($masked, $plain, $verdacht) = lex($src, 0);
    my @hits = verstoesse($masked, $plain);
    if ($verdacht) {
        # Rückfallnetz: /…"…/ hinter einer vermeintlichen Division als Regex-Literal lesen (Befund bau-4)
        my ($masked2, $plain2) = lex($src, 1);
        push @hits, verstoesse($masked2, $plain2);
    }

    my $rel = $file;
    $rel =~ s/\A\Q$root\E\/// if length $root;
    my %seen;
    for my $h (sort { $a->[0] <=> $b->[0] } @hits) {
        next if $seen{"$h->[0]\0$h->[1]"}++;   # gleiche Zeile + gleicher Grund nur einmal
        print "$rel:$h->[0]: $h->[1]\n";
        $total++;
    }
}
print STDERR "Grep-Sperren: " . scalar(@files) . " Dateien geprüft, $total " . ($total == 1 ? "Verstoss" : "Verstösse") . "\n";
exit($total ? 1 : 0);
PERL

pruefen() {
    /usr/bin/perl -e "$PRUEFER" -- "$@"
}

selbsttest() (
    tmp="$(mktemp -d -t siegel_grep)"
    trap 'rm -rf "$tmp"' EXIT
    # Jede Zeile mit «ERWARTET» muss gemeldet werden, keine andere.
    cat > "$tmp/Positiv.swift" <<'SWIFT'
let a = try! JSONDecoder().decode(X.self, from: d)   // ERWARTET
print("hallo")                                         // ERWARTET
print ("mit Leerzeichen")                              // ERWARTET
Swift.print(x)                                         // ERWARTET
debugPrint(entry)                                      // ERWARTET
dump(vault)                                            // ERWARTET
Swift.dump(vault)                                      // ERWARTET
NSLog("x %@", s)                                       // ERWARTET
Foundation.NSLog("x")                                  // ERWARTET
let d = Dictionary(uniqueKeysWithValues: pairs)        // ERWARTET
let e = [String: Int](uniqueKeysWithValues: pairs)     // ERWARTET
let f = Dictionary<String, Int>.init(uniqueKeysWithValues: p) // ERWARTET
logger.info("id \(id, privacy: .public)")              // ERWARTET
logger.info("id \(id, privacy:.public)")               // ERWARTET
logger.info("id \(id, privacy: .public(mask: .hash))") // ERWARTET
os_log("%{public}@", log: l, s)                        // ERWARTET
fatalError("Fehler \(code)")                           // ERWARTET
Swift.fatalError("Fehler \(code)")                     // ERWARTET
precondition(n > 0, "n = \(n)")                        // ERWARTET
assert(ok, "Eintrag \(entry.title)")                   // ERWARTET
preconditionFailure("x\(y)")                           // ERWARTET
assertionFailure("\(y)")                               // ERWARTET
fatalError(error.localizedDescription)                 // ERWARTET
fatalError("Fehler: " + code)                          // ERWARTET
precondition(ok, message)                              // ERWARTET
fatalError(                                            // ERWARTET
    "mehrzeilig \(wert)"
)
let s = "\(try! f())"                                  // ERWARTET
fatalError(#"roh \#(wert)"#)                           // ERWARTET
fatalError("""                                         // ERWARTET
    zeile \(x)
    """)
x = y.map { try! g($0) }                               // ERWARTET
let u = "https://a.b/c"; let v = try! h()             // ERWARTET
/* kommentar */ print("x")                             // ERWARTET
/* a /* b */ print("nicht") */ print("ja")             // ERWARTET
let t = "a \(b ? "x" : "y") c"; dump(t)                // ERWARTET
let bs = "\\"; print("nach Backslash")                 // ERWARTET
let r = #"a "b" c"#; dump(r)                           // ERWARTET
let m = """
    "eingebettet" ""
    """; NSLog("x")                                    // ERWARTET
let r = /"/; print(s)                                  // ERWARTET
let q = #/"/#; dump(s)                                 // ERWARTET
let w = #/"""/#
print(s)                                               // ERWARTET
let rr = /a\/b"/; try! f()                             // ERWARTET
let ml = #/
    a"b
    /#; NSLog("x")                                     // ERWARTET
let m2 = ##/a /# "b/##; dump(m2)                       // ERWARTET
`print`(s)                                             // ERWARTET
(print)(s)                                             // ERWARTET
( print ) (s)                                          // ERWARTET
Swift.`dump`(s)                                        // ERWARTET
`fatalError`("x \(y)")                                 // ERWARTET
(fatalError)("x \(y)")                                 // ERWARTET
let dd: (String, String?, Int, Int, Int) -> String = dump // ERWARTET
let ee = Swift.dump                                    // ERWARTET
xs.forEach(debugPrint)                                 // ERWARTET
let k = a / b; print(k)                                // ERWARTET
let k2 = (a) /b/ c; dump(k2)                           // ERWARTET
let k3 = x! /2/ 3; print(k3)                           // ERWARTET
let m4 = try /[^"]+/.firstMatch(in: s); print(x)       // ERWARTET
let w4 = try await /a"/.firstMatch(in: s); dump(x)     // ERWARTET
let t4 = try /"""/.firstMatch(in: s)
print(x)                                               // ERWARTET
let c4 = s.map { a in /"/.firstMatch(in: a) }; dump(c4) // ERWARTET
let o4 = a ?? -/"/; print(o4)                          // ERWARTET
withVaList([s]) { NSLogv("x %@", $0) }                 // ERWARTET
Foundation.NSLogv("x %@", va)                          // ERWARTET
let rb = Regex {
    "a"
    /b"/; print(x)                                     // ERWARTET
}
SWIFT
    cat > "$tmp/Negativ.swift" <<'SWIFT'
// print("nur ein Kommentar") try! fatalError("\(x)") privacy: .public
/// Doku: dump(x), NSLog(…), Dictionary(uniqueKeysWithValues:)
/* Block: Dictionary(uniqueKeysWithValues: x)
   /* verschachtelt */ print("weiter im Kommentar") */
let op = NSPrintOperation(view: v)
op.printPanel.options = []
op.printInfo.jobDisposition = .spool
let info = NSPrintInfo.shared
view.print(nil)
window.print(self)
self.printOperation.run()
printer?.print(page)
let isPrinted = printed(x)
let fp = fingerprint(x)
let bp = blueprint(x)
reprint(x)
debugPrinter.reset()
dumpState()
let n = NSLogLevel(3)
let text = "print(\"x\") try! fatalError(\"\\(x)\") privacy: .public %{publicx}"
let roh = #"print("x") \(nicht interpoliert) try! "#
let mehr = """
    try! print("x") Dictionary(uniqueKeysWithValues: x)
    """
let url = "https://example.com/print(x)" // print("kommentar")
fatalError("sodium_init")
fatalError()
Swift.fatalError("fest")
precondition(seed.count == 64)
precondition(seed.count == 64, "mlkem.seed")
precondition(a ? b : c, "fest", file: f, line: l)
assert(a == b, "fest")
assert(condition)
assert(list.contains { $0.count > 1 }, "fest")
dispatchPrecondition(condition: .notOnQueue(.main))
assertionFailure()
preconditionFailure("fest")
fatalError("""
    mehrzeilig, aber fest
    """)
logger.error("Speichern fehlgeschlagen: \(code, privacy: .private)")
logger.debug("x \(n)")
logger.info("x \(n, privacy: .publicity)")
let x = try? f()
let y = try f()
let g = Dictionary(grouping: xs, by: f)
let h = Dictionary(xs, uniquingKeysWith: { a, _ in a })
func print(_ s: String) {}
func dump(_ x: Any) {}
enum Ausgabe { case print(String) }
Text("Fehler: \(meldung)")
let interp = "Wert: \(value)"
let r1 = /print\(x\)/
let r2 = #/try! fatalError("\(x)") dump(y) privacy: .public/#
let r3 = #/
    print\(x\) " Dictionary(uniqueKeysWithValues: x)
    /#
let r4 = ##/a /# print(x) "/##
if s.contains(/print"/) { }
return /dump\(/.firstMatch(in: s) != nil
let half = a / 2 / b
let z = x! / 2
func f(print: Bool, dump: Int) {}
f(print: true, dump: 1)
let opts = Options(debugPrint: false, NSLog: 0)
let m2 = x.dump
let m3 = view.print
switch a { case .print: break; case .dump(let v): _ = v }
enum Ziel { case print, datei }
let q4 = try /print\(/.firstMatch(in: s)
let q5 = try await /dump\("/.wholeMatch(in: s)
let q6 = try /"""/.firstMatch(in: s)
let n4 = NSLogvFoo(1)
let half4 = total /2; let s4 = "print(x)"
let p4 = a /b; let u4 = "c/d"
SWIFT
    erwartet="$(grep -n 'ERWARTET' "$tmp/Positiv.swift" | cut -d: -f1 | sed 's/^/Positiv.swift:/' | sort)"
    gefunden="$(pruefen "$tmp" "$tmp" 2>/dev/null | cut -d: -f1,2 | sort || true)"
    if [[ "$erwartet" == "$gefunden" ]]; then
        echo "Selbsttest ok: $(echo "$erwartet" | wc -l | tr -d ' ') Verstösse erkannt, keine Fehlalarme."
        return 0
    fi
    echo "Selbsttest FEHLER"
    diff <(echo "$erwartet") <(echo "$gefunden") | sed 's/^</  nicht erkannt:/; s/^>/  Fehlalarm:/' | grep -v '^[0-9]' || true
    pruefen "$tmp" "$tmp" 2>/dev/null || true
    return 1
)

if [[ "${1:-}" == "--selbsttest" ]]; then
    selbsttest
    exit $?
fi

if [[ $# -eq 0 ]]; then
    # Alles, was in die App kommt (SPEC §5 und Härtestufe v4)
    set -- "$ROOT/Sources/SiegelCore" "$ROOT/Sources/SiegelUI" "$ROOT/Sources/SiegelHardware" "$ROOT/Sources/Siegel"
    if [[ -d "$ROOT/Erweiterungen/SiegelAutofill" ]]; then set -- "$@" "$ROOT/Erweiterungen/SiegelAutofill"; fi
fi
pruefen "$ROOT" "$@"
