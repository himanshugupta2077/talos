import { categoryBadgeClass } from "../shared";

export default function CategoryBadge({
  category,
  className = "",
}: {
  category: string;
  className?: string;
}) {
  return (
    <span
      className={`badge badge-sm ${categoryBadgeClass(category)} ${className}`}
    >
      {category || "—"}
    </span>
  );
}
