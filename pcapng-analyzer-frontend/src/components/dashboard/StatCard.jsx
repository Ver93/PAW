
export default function StatCard({
  icon,
  label,
  value,
  sub,
}) {
  return (
    <div className="stat-card">
      <div className="stat-card-top">
        <div className="stat-icon-wrapper">
          {icon}
        </div>
      </div>

      <div className="stat-label">
        {label}
      </div>

      <div className="stat-value">
        {value}
      </div>

      {sub && (
        <div className="stat-sub">
          {sub}
        </div>
      )}
    </div>
  );
}

