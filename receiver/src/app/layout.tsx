import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WeatherSync — Local Forecast",
  description: "A quick, simple local weather forecast.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
