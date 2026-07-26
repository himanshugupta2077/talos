import { categoryChipClass } from "../shared";

const LABELS: Record<string, string> = {
  secret: "secret",
  infrastructure_disclosure: "infra",
  sensitive_info: "sensitive",
};

export default function CategoryBadge({ category }: { category: string }) {
  return (
    <span className={`badge badge-sm ${categoryChipClass(category)}`} title={category}>
      {LABELS[category] || category || "—"}
    </span>
  );
}
