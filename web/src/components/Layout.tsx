import {
  Activity,
  CalendarClock,
  Compass as CompassIcon,
  GitBranch,
  LayoutDashboard,
  Telescope,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  jp: string;
  Icon: React.ComponentType<{ className?: string }>;
}

const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", jp: "全景", Icon: LayoutDashboard },
  { to: "/sentinel", label: "Sentinel", jp: "斥候", Icon: Telescope },
  { to: "/compass", label: "Compass", jp: "羅針", Icon: CompassIcon },
  { to: "/lineage", label: "Lineage", jp: "継", Icon: GitBranch },
  { to: "/chronicle", label: "Chronicle", jp: "歴記", Icon: CalendarClock },
];

export function Layout(): JSX.Element {
  return (
    <div className="flex min-h-screen">
      <aside className="w-64 shrink-0 border-r bg-card">
        <div className="flex items-center gap-2 px-6 py-5">
          <Activity className="h-6 w-6 text-suzaku" />
          <div>
            <div className="text-xl font-bold text-suzaku">Suzaku</div>
            <div className="text-xs text-muted-foreground">
              朱雀 — OSS vuln research
            </div>
          </div>
        </div>
        <Separator />
        <nav className="space-y-1 p-4">
          {NAV.map(({ to, label, jp, Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-accent text-accent-foreground font-medium"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )
              }
            >
              <Icon className="h-4 w-4" />
              <span>{label}</span>
              <span className="ml-auto text-xs text-muted-foreground">{jp}</span>
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="flex-1 overflow-x-hidden p-8">
        <Outlet />
      </main>
    </div>
  );
}
