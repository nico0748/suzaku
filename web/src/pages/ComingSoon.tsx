import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface ComingSoonProps {
  title: string;
  jp: string;
  description: string;
  cliExample: string;
  nextPr: string;
}

export function ComingSoonPage(props: ComingSoonProps): JSX.Element {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-bold text-suzaku">
          {props.title}{" "}
          <span className="text-xl text-muted-foreground">({props.jp})</span>
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">{props.description}</p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Coming soon</CardTitle>
          <CardDescription>
            このページは Phase 3-A の後続 PR ({props.nextPr}) で実装される。現状は
            CLI から実行できる。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="overflow-x-auto rounded-md bg-muted p-4 text-xs">
            <code>{props.cliExample}</code>
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
