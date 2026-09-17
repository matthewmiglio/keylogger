import { headers } from "next/headers";
import { getWeather } from "@/lib/weather";

export const dynamic = "force-dynamic";

// Fallback location when Vercel geo headers are absent (e.g. local dev).
const DEFAULT_LAT = 47.6062;
const DEFAULT_LON = -122.3321;

const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function dayName(dateStr: string): string {
  const d = new Date(dateStr + "T12:00:00");
  return DAY_NAMES[d.getDay()];
}

export default async function Home() {
  const h = await headers();
  const lat = parseFloat(h.get("x-vercel-ip-latitude") ?? "");
  const lon = parseFloat(h.get("x-vercel-ip-longitude") ?? "");
  const city = h.get("x-vercel-ip-city") ?? "Seattle";

  const latitude = Number.isFinite(lat) && lat !== 0 ? lat : DEFAULT_LAT;
  const longitude = Number.isFinite(lon) && lon !== 0 ? lon : DEFAULT_LON;

  let weather = null;
  let error: string | null = null;
  try {
    weather = await getWeather(latitude, longitude);
  } catch {
    error = "Forecast temporarily unavailable.";
  }

  return (
    <main>
      <h1>WeatherSync</h1>
      <p className="subtitle">Simple local forecast for {city}.</p>

      {error && <p className="subtitle">{error}</p>}

      {weather && (
        <>
          <div className="card">
            <div className="current">
              <span className="temp">{weather.current.temperature}&deg;</span>
              <span className="desc">{weather.current.description}</span>
            </div>
            <p className="meta">Wind {weather.current.windSpeed} km/h</p>
          </div>

          <div className="days">
            {weather.daily.map((d) => (
              <div className="day" key={d.date}>
                <div className="name">{dayName(d.date)}</div>
                <div className="hi">{d.high}&deg;</div>
                <div className="lo">{d.low}&deg;</div>
              </div>
            ))}
          </div>
        </>
      )}

      <footer>WeatherSync &middot; forecast data by Open-Meteo</footer>
    </main>
  );
}
