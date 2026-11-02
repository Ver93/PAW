
import "./DataCard.css";

export default function DataCard({
  title,
  right,
  children,
}) {
  return (
    <section className="data-card">
      <div className="data-card-header">
        <h3>{title}</h3>

        {right && (
          <div>{right}</div>
        )}
      </div>

      {children}
    </section>
  );
}
