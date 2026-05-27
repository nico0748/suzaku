import { ComingSoonPage } from "./ComingSoon";

export function LineagePage(): JSX.Element {
  return (
    <ComingSoonPage
      title="Lineage"
      jp="継"
      description="CVE 修正パッチから VariantRule を抽出し、他リポへ横展開検索するパイプラインを 3 ステップでブラウザから組む。"
      cliExample={`suzaku lineage ingest --cve CVE-2026-42281 --out cve.json
suzaku lineage extract cve.json --out rules.json
suzaku lineage scan /path/to/target --rules rules.json`}
      nextPr="PR #6"
    />
  );
}
