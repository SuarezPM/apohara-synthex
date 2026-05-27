// Cognee — memoria/knowledge-graph de agente (partner challenge "Best Use of Agent Memory").
//
// HONESTIDAD: el MODO de integración no está decidido en el plan — hay un cognee MCP local
// (~/.cognee, con MiniMax + DBs locales) y existe la opción cloud del partner. Elegir uno es
// una decisión de producto pendiente. Por eso este cliente define la interfaz pero NO fabrica
// llamadas: el camino primario de memoria es MemoryStore (store.js), funcional.
//
// TODO(decisión + integración): elegir local-MCP vs cloud; si local-MCP, consumir el cognee
// MCP como cliente (igual que FETCH consume brightdata-mcp) y conectar ingest()/query() reales
// con test de red opt-in.

export class CogneeClient {
  constructor({ mode = process.env.COGNEE_MODE } = {}) {
    this.mode = mode ?? null; // "local-mcp" | "cloud" — sin decidir aún
    this.configured = Boolean(this.mode);
  }

  async ingest() {
    throw new Error(
      "Cognee no configurado: decisión local-MCP vs cloud pendiente (ver TODO). Usá MemoryStore mientras tanto."
    );
  }
  async query() {
    throw new Error("Cognee no configurado: ver TODO (decisión local-MCP vs cloud).");
  }
}
