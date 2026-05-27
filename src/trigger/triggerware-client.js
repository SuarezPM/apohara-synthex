// TriggerWare.ai — integración de workflows event-driven (OPCIONAL).
//
// HONESTIDAD: la documentación pública de la API de TriggerWare.ai no es accesible
// (no aparece en búsqueda web; es un partner nuevo del hackathon). Por eso este cliente
// define la INTERFAZ esperada pero NO ejecuta llamadas contra endpoints sin confirmar:
// preferimos fallar con un mensaje claro antes que fabricar un endpoint que parezca real.
//
// El camino primario de monitoreo es Monitor (cron), en monitor.js — ese sí es funcional.
//
// TODO(partner): confirmar baseUrl, esquema de auth y endpoints reales con el equipo de
// TriggerWare.ai (o su doc cuando esté disponible) y completar registerWorkflow()/fireEvent()
// con verificación real (test de red opt-in, igual que CLASSIFY/FETCH).

export class TriggerWareClient {
  constructor({ apiKey = process.env.TRIGGERWARE_API_KEY, baseUrl } = {}) {
    this.apiKey = apiKey ?? null;
    this.baseUrl = baseUrl ?? null; // SIN default fabricado a propósito
    this.configured = Boolean(this.apiKey && this.baseUrl);
  }

  /** Registraría un workflow que dispara el pipeline ante un cambio web. Pendiente de API real. */
  async registerWorkflow() {
    if (!this.configured) {
      throw new Error(
        "TriggerWare no configurado: falta baseUrl confirmado por el partner (ver TODO). " +
        "Usá Monitor (cron) como camino primario."
      );
    }
    // TODO(partner): POST `${this.baseUrl}/...` una vez confirmado el esquema real.
    throw new Error("registerWorkflow: endpoint de TriggerWare pendiente de confirmar (no fabricado).");
  }
}
