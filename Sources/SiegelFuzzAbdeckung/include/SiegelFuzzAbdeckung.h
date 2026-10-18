#ifndef SIEGEL_FUZZ_ABDECKUNG_H
#define SIEGEL_FUZZ_ABDECKUNG_H
#include <stdint.h>

// Kanten-Abdeckung für SiegelFuzz (SanitizerCoverage `trace-pc-guard`). Nur wirksam, wenn die Swift-Ziele mit
// `-sanitize-coverage=edge,trace-pc-guard` gebaut sind (skripte/fuzz.sh); sonst bleibt alles 0.

/// Anzahl der bisher mindestens einmal erreichten Kanten (wächst nur).
uint32_t siegel_abdeckung_erreicht(void);
/// Anzahl der instrumentierten Kanten (0 = ohne Instrumentierung gebaut).
uint32_t siegel_abdeckung_gesamt(void);

#endif
