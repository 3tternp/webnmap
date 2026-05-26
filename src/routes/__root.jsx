import { Outlet, Link, createRootRoute, HeadContent, Scripts } from "@tanstack/react-router";
import appCss from "../styles.css?url";

function NotFoundComponent() {
  return (
    <div style={{ display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", background: "#070c18", color: "#e2e8f0", fontFamily: "monospace" }}>
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: 64, fontWeight: 700, color: "#1e3a5f" }}>404</div>
        <div style={{ fontSize: 16, marginTop: 8 }}>Page not found</div>
        <Link to="/" style={{ display: "inline-block", marginTop: 16, color: "#4ade80", textDecoration: "none", fontSize: 12 }}>
          ← Return to dashboard
        </Link>
      </div>
    </div>
  );
}

function ErrorComponent({ error, reset }) {
  console.error(error);
  return (
    <div style={{ display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", background: "#070c18", color: "#e2e8f0", fontFamily: "monospace" }}>
      <div style={{ textAlign: "center", maxWidth: 400 }}>
        <div style={{ fontSize: 16, fontWeight: 700 }}>Something went wrong</div>
        <div style={{ fontSize: 11, color: "#64748b", marginTop: 8 }}>{error?.message}</div>
        <div style={{ display: "flex", gap: 10, justifyContent: "center", marginTop: 20 }}>
          <button onClick={reset} style={{ padding: "8px 16px", background: "#052e16", border: "1px solid #166534", color: "#4ade80", borderRadius: 6, cursor: "pointer", fontFamily: "monospace", fontSize: 12 }}>
            Try again
          </button>
          <a href="/" style={{ padding: "8px 16px", background: "#0d1526", border: "1px solid #1e2d45", color: "#94a3b8", borderRadius: 6, textDecoration: "none", fontSize: 12 }}>
            Go home
          </a>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "Nmap Web Dashboard" },
      { name: "description", content: "Self-hosted network intelligence platform. Launch nmap scans from your browser and visualize ports, services, and OS fingerprints." },
    ],
    links: [{ rel: "stylesheet", href: appCss }],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RootShell({ children }) {
  return (
    <html lang="en">
      <head><HeadContent /></head>
      <body>{children}<Scripts /></body>
    </html>
  );
}

function RootComponent() {
  return <Outlet />;
}
