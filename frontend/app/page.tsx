"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type Indicator = {
  name: string;
  description: string;
  points: number;
  severity: "low" | "medium" | "high" | string;
};

type MLResult = {
  available: boolean;
  message: string;
  model?: string | null;
  model_version?: string | null;
  phishing_probability?: number | null;
  prediction?: "suspicious" | "low_risk" | null;
};

type Result = {
  url: string;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | string;
  indicators: Indicator[];
  message: string;
  ml?: MLResult | null;
};

type HistoryItem = Result & {
  id: number;
  created_at: string;
};

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function levelLabel(level: string) {
  if (level === "high") return "ALTO";
  if (level === "medium") return "MEDIO";
  return "BAJO";
}

function levelClass(level: string) {
  if (level === "high") return "risk-high";
  if (level === "medium") return "risk-medium";
  return "risk-low";
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState("");
  const [error, setError] = useState("");
  const [mlStatus, setMlStatus] = useState<{ trained: boolean; model?: string } | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      setHistoryLoading(true);
      setHistoryError("");
      const response = await fetch(`${API_URL}/api/history?limit=8`, {
        cache: "no-store",
        credentials: "include",
      });
      if (!response.ok) throw new Error("No fue posible cargar el historial.");
      const data: HistoryItem[] = await response.json();
      setHistory(data);
    } catch {
      setHistoryError("El historial no está disponible. Comprueba que la API esté ejecutándose.");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
    fetch(`${API_URL}/api/ml/status`, { cache: "no-store" })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => { if (data && typeof data.trained === "boolean") setMlStatus(data); })
      .catch(() => setMlStatus(null));
  }, [loadHistory]);

  async function analyze(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data: unknown = await response.json();
      if (!response.ok) {
        const detail = typeof data === "object" && data !== null && "detail" in data
          ? (data as { detail?: unknown }).detail
          : undefined;
        throw new Error(typeof detail === "string" ? detail : "La URL es inválida o no se pudo analizar.");
      }
      setResult(data as Result);
      await loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error desconocido.");
    } finally {
      setLoading(false);
    }
  }


  async function clearHistory() {
    if (!window.confirm("¿Eliminar todos los análisis guardados en este navegador?")) return;
    try {
      const response = await fetch(`${API_URL}/api/history`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!response.ok) throw new Error("No se pudo borrar el historial.");
      setHistory([]);
      setHistoryError("");
    } catch {
      setHistoryError("No se pudo borrar el historial. Comprueba la conexión con la API.");
    }
  }

  return (
    <main className="min-h-screen px-5 py-10 md:px-8 md:py-14">
      <div className="mx-auto max-w-6xl">
        <header className="mb-10 flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="mb-2 text-sm font-semibold uppercase tracking-[0.3em] text-cyan-400">
              Detección de phishing
            </p>
            <h1 className="text-5xl font-black tracking-tight md:text-6xl">CyberLens</h1>
            <p className="mt-4 max-w-2xl text-base leading-7 text-slate-400 md:text-lg">
              Analiza la estructura de una URL, calcula un puntaje de riesgo y explica qué señales
              podrían relacionarse con un intento de phishing.
            </p>
          </div>
          <span className="version-badge">V0.5 · heurística + redirecciones + ML experimental</span>
        </header>

        <section className="panel p-5 md:p-6">
          <form onSubmit={analyze} className="flex flex-col gap-4 md:flex-row">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://ejemplo.com/login"
              required
              inputMode="url"
              className="min-h-14 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-5 text-base outline-none transition focus:border-cyan-400"
            />
            <button
              disabled={loading}
              className="min-h-14 rounded-xl bg-cyan-400 px-8 font-bold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Analizando..." : "Analizar URL"}
            </button>
          </form>

          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-xs text-slate-500">
            <span>✓ No abre el sitio</span>
            <span>✓ No descarga contenido</span>
            <span>✓ Historial privado de este navegador (30 días)</span>
            <span>✓ No guarda rutas, consultas ni contraseñas</span>
          </div>

          {error && (
            <div className="mt-5 rounded-xl border border-red-900 bg-red-950/30 p-4 text-red-300">
              {error}
            </div>
          )}
        </section>

        {result && (
          <section className="mt-7 grid gap-5 md:grid-cols-[300px_1fr]">
            <div className={`panel p-6 ${levelClass(result.risk_level)}`}>
              <p className="text-sm text-slate-400">Nivel de riesgo orientativo</p>
              <p className="mt-3 text-4xl font-black">{levelLabel(result.risk_level)}</p>
              <div className="mt-7 flex items-end gap-2">
                <p className="text-7xl font-black leading-none">{result.risk_score}</p>
                <p className="pb-1 text-slate-500">/ 100</p>
              </div>
              <div className="score-track mt-5">
                <div className="score-fill" style={{ width: `${result.risk_score}%` }} />
              </div>
              <p className="mt-5 text-sm leading-6 text-slate-400">{result.message}</p>
            </div>

            <div className="panel p-6">
              <p className="break-all text-sm text-slate-500" aria-label="URL con datos sensibles omitidos">{result.url}</p>
              <div className="mt-4 flex items-center justify-between gap-4">
                <h2 className="text-2xl font-bold">Indicadores encontrados</h2>
                <span className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-400">
                  {result.indicators.length} señales
                </span>
              </div>

              {result.indicators.length === 0 ? (
                <div className="mt-5 rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-4 text-sm text-emerald-200">
                  No se detectaron indicadores estructurales en este análisis.
                </div>
              ) : (
                <div className="mt-5 space-y-3">
                  {result.indicators.map((indicator, index) => (
                    <div key={`${indicator.name}-${index}`} className="indicator-card">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="mb-2 flex items-center gap-2">
                            <span className={`severity-dot severity-${indicator.severity}`} />
                            <strong>{indicator.name}</strong>
                          </div>
                          <p className="text-sm leading-6 text-slate-400">{indicator.description}</p>
                        </div>
                        <span className="shrink-0 text-sm font-bold text-cyan-300">+{indicator.points}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        )}

        {result && (
          <section className="mt-6 panel p-6" aria-label="Resultado experimental de Machine Learning">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">Etapa 2 · Modelo supervisado</p>
                <h2 className="mt-1 text-xl font-bold">Machine Learning experimental</h2>
              </div>
              <span className={`risk-pill ${result.ml?.available ? "risk-medium" : "text-slate-400"}`}>
                {result.ml?.available ? "MODELO ENTRENADO" : "SIN ENTRENAR"}
              </span>
            </div>
            {result.ml?.available && typeof result.ml.phishing_probability === "number" ? (
              <div className="mt-4 grid gap-4 md:grid-cols-[180px_1fr] md:items-center">
                <div>
                  <span className="text-4xl font-black text-cyan-300">{Math.round(result.ml.phishing_probability * 100)}%</span>
                  <p className="text-xs text-slate-400">Estimación del modelo de la clase phishing</p>
                </div>
                <div className="space-y-2">
                  <p className="font-semibold">{result.ml.model} · {result.ml.prediction === "suspicious" ? "señal ML de precaución" : "señal ML de menor riesgo"}</p>
                  <p className="text-sm leading-6 text-slate-400">{result.ml.message}</p>
                  <p className="text-xs text-slate-500">Este porcentaje NO es una precisión validada ni una garantía; no se suma al puntaje heurístico.</p>
                </div>
              </div>
            ) : (
              <p className="mt-3 text-sm leading-6 text-slate-400">{result.ml?.message || "Modelo ML no disponible. El análisis heurístico sigue funcionando normalmente."} Ejecuta el entrenamiento local indicado en el README.</p>
            )}
            {mlStatus?.trained && <p className="mt-2 text-xs text-slate-500">Modelo activo: {mlStatus.model}</p>}
          </section>
        )}

        <section className="mt-7 panel p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">SQLite</p>
              <h2 className="mt-1 text-2xl font-bold">Historial reciente</h2>
            </div>
            <div className="flex items-center gap-4">
              <button type="button" onClick={loadHistory} className="text-sm text-cyan-300 hover:text-cyan-200">
                Actualizar
              </button>
              <button type="button" onClick={clearHistory} className="text-sm text-rose-300 hover:text-rose-200">
                Borrar mis análisis
              </button>
            </div>
          </div>

          {historyError && <p role="alert" className="mt-4 text-sm text-rose-300">{historyError}</p>}
          <p className="mt-2 text-xs text-slate-500">Historial vinculado a este navegador. Los resultados ML anteriores pueden estar ausentes si fueron analizados antes de entrenar.</p>
          {historyLoading && history.length === 0 ? (
            <p className="mt-5 text-sm text-slate-500">Cargando historial...</p>
          ) : history.length === 0 ? (
            <p className="mt-5 text-sm text-slate-500">Todavía no hay análisis guardados.</p>
          ) : (
            <div className="mt-5 overflow-x-auto">
              <table className="w-full min-w-[680px] border-collapse text-left text-sm">
                <thead className="text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="border-b border-slate-800 px-3 py-3 font-semibold">Fecha</th>
                    <th className="border-b border-slate-800 px-3 py-3 font-semibold">URL</th>
                    <th className="border-b border-slate-800 px-3 py-3 font-semibold">Riesgo</th>
                    <th className="border-b border-slate-800 px-3 py-3 text-right font-semibold">Puntaje</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr key={item.id} className="border-b border-slate-900 last:border-0">
                      <td className="whitespace-nowrap px-3 py-4 text-slate-500">
                        {new Date(item.created_at).toLocaleString("es-CL", {
                          dateStyle: "short",
                          timeStyle: "short",
                        })}
                      </td>
                      <td className="max-w-[440px] truncate px-3 py-4 text-slate-300" title={item.url}>
                        {item.url}
                      </td>
                      <td className="px-3 py-4">
                        <span className={`risk-pill ${levelClass(item.risk_level)}`}>
                          {levelLabel(item.risk_level)}
                        </span>
                      </td>
                      <td className="px-3 py-4 text-right font-bold">{item.risk_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <footer className="mt-10 text-center text-xs leading-5 text-slate-600">
          CyberLens V0.5 — Heurísticas, redirecciones y ML experimental: «BAJO» no significa «SEGURO».
        </footer>
      </div>
    </main>
  );
}
