import { ComingSoonPage } from "./ComingSoon";

export function SentinelPage(): JSX.Element {
  return (
    <ComingSoonPage
      title="Sentinel"
      jp="斥候"
      description="8 シグナル評価による OSS ターゲット選定。GitHub Search の結果をブラウザで一覧 / 重み調整できるようにする。"
      cliExample="suzaku sentinel scan --language php --min-stars 100 --top 20 --json"
      nextPr="PR #5"
    />
  );
}
