import { attackTypeBadgeClass } from "../shared";

export default function AttackTypeChip({
  attackType,
}: {
  attackType: string | null | undefined;
}) {
  const v = attackType || "unknown";
  return (
    <span className={`badge badge-xs mono ${attackTypeBadgeClass(v)}`}>
      {v}
    </span>
  );
}
