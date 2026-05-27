import { useQuery } from "@tanstack/react-query";

import { fetchHealth } from "@/api/client";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function DashboardPage(): JSX.Element {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    staleTime: 60_000,
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-bold text-suzaku">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          広い空から異変を見つけ、社会へ伝える。
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>API status</CardTitle>
          <CardDescription>
            ヘルスチェック (
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              GET /api/health
            </code>
            ) の結果。
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading && (
            <p className="text-sm text-muted-foreground">checking…</p>
          )}
          {isError && (
            <p className="text-sm text-destructive">
              error: {String((error as Error).message)}
            </p>
          )}
          {data && (
            <dl className="grid grid-cols-3 gap-x-6 gap-y-2 text-sm">
              <dt className="font-medium text-muted-foreground">name</dt>
              <dd className="col-span-2 font-mono">{data.name}</dd>
              <dt className="font-medium text-muted-foreground">version</dt>
              <dd className="col-span-2 font-mono">{data.version}</dd>
              <dt className="font-medium text-muted-foreground">mode</dt>
              <dd className="col-span-2 font-mono">{data.mode}</dd>
            </dl>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Modules (v1 scope)</CardTitle>
          <CardDescription>
            Phase 3-A は読み取り系 4 モジュールを GUI 化。Witness / Herald / Reader
            は CLI でのみ操作可能。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="space-y-1 text-sm">
            <li>
              <strong>Sentinel</strong> — 8 シグナル評価による OSS ターゲット選定
            </li>
            <li>
              <strong>Compass</strong> — 危険関数 grep + パターン scan
            </li>
            <li>
              <strong>Lineage</strong> — CVE variant analysis (ingest / extract /
              scan)
            </li>
            <li>
              <strong>Chronicle</strong> — 90 日タイムラインの参照
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
