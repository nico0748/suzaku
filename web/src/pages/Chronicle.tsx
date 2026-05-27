import { ComingSoonPage } from "./ComingSoon";

export function ChroniclePage(): JSX.Element {
  return (
    <ComingSoonPage
      title="Chronicle"
      jp="歴記"
      description="90 日開示タイムラインの参照。Day 経過 / vendor_state / 推奨アクションを一覧表示する。Phase 3-A では publish は CLI からのみ。"
      cliExample="suzaku chronicle status S-001"
      nextPr="PR #6"
    />
  );
}
