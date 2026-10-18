// Rückrufe der SanitizerCoverage (trace-pc-guard) für SiegelFuzz: jede Kante bekommt beim Start eine Nummer, beim
// ersten Erreichen wird sie gezählt. Der Fuzzer vergleicht den Zähler vor und nach einer Eingabe: wächst er, hat die
// Eingabe neuen Code erreicht und kommt in den Korpus. Dieses Ziel selbst wird nicht instrumentiert (nur C, die
// Abdeckungs-Flags gehen nur an swiftc). Gleichzeitige Aufrufe aus mehreren Threads (Notfall-Korrektur) dürfen sich
// überschneiden: höchstens wird eine Kante doppelt gezählt.
#include "SiegelFuzzAbdeckung.h"

#define MAX_KANTEN (1u << 22)

static uint32_t anzahl_kanten = 0;
static uint32_t erreicht = 0;
static uint8_t gesehen[MAX_KANTEN];

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *x = start; x < stop; x++) {
        if (anzahl_kanten + 1 < MAX_KANTEN) anzahl_kanten++;
        *x = anzahl_kanten;
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t g = *guard;
    if (g == 0 || g >= MAX_KANTEN || gesehen[g]) return;
    gesehen[g] = 1;
    erreicht++;
}

uint32_t siegel_abdeckung_erreicht(void) { return erreicht; }
uint32_t siegel_abdeckung_gesamt(void) { return anzahl_kanten; }
