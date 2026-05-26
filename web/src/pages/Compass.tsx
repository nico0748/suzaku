import { ComingSoonPage } from "./ComingSoon";

export function CompassPage(): JSX.Element {
  return (
    <ComingSoonPage
      title="Compass"
      jp="羅針"
      description="ripgrep + Semgrep ベースの危険関数 / パターンスキャン。ルール ON/OFF と hit 件数の可視化を提供する。"
      cliExample="suzaku compass scan /path/to/target --rule danger_funcs_php"
      nextPr="PR #5"
    />
  );
}
