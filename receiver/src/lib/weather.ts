export type CurrentWeather = {
  temperature: number;
  description: string;
  windSpeed: number;
};

export type DailyForecast = {
  date: string;
  high: number;
  low: number;
  code: number;
};

export type Weather = {
  current: CurrentWeather;
  daily: DailyForecast[];
};

const CODES: Record<number, string> = {
  0: "clear sky",
  1: "mainly clear",
  2: "partly cloudy",
  3: "overcast",
  45: "fog",
  48: "rime fog",
  51: "light drizzle",
  53: "drizzle",
  55: "heavy drizzle",
  61: "light rain",
  63: "rain",
  65: "heavy rain",
  71: "light snow",
  73: "snow",
  75: "heavy snow",
  80: "rain showers",
  81: "rain showers",
  82: "violent rain showers",
  95: "thunderstorm",
  96: "thunderstorm with hail",
  99: "severe thunderstorm",
};

export function describeCode(code: number): string {
  return CODES[code] ?? "mixed";
}

export async function getWeather(
  latitude: number,
  longitude: number
): Promise<Weather> {
  const url =
    `https://api.open-meteo.com/v1/forecast?latitude=${latitude}&longitude=${longitude}` +
    `&current=temperature_2m,weather_code,wind_speed_10m` +
    `&daily=weather_code,temperature_2m_max,temperature_2m_min&forecast_days=6&timezone=auto`;

  const res = await fetch(url, { next: { revalidate: 600 } });
  if (!res.ok) throw new Error(`open-meteo ${res.status}`);

  const data = await res.json();
  return {
    current: {
      temperature: Math.round(data.current.temperature_2m),
      description: describeCode(data.current.weather_code),
      windSpeed: Math.round(data.current.wind_speed_10m),
    },
    daily: (data.daily.time as string[]).slice(1, 6).map((date, i) => ({
      date,
      high: Math.round(data.daily.temperature_2m_max[i + 1]),
      low: Math.round(data.daily.temperature_2m_min[i + 1]),
      code: data.daily.weather_code[i + 1],
    })),
  };
}
