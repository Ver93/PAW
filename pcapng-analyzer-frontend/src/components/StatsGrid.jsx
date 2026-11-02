export default function StatsGrid({ stats }) {
  return (
    <div className="stats-grid">
      <div className="stat-card"><h4>Interfaces</h4><p>{stats.interfaces}</p></div>
      <div className="stat-card"><h4>Packets</h4><p>{stats.packets}</p></div>
      <div className="stat-card"><h4>Captured Bytes</h4><p>{stats.packet_stats.captured_bytes}</p></div>
      <div className="stat-card"><h4>Min Packet</h4><p>{stats.packet_stats.min_length}</p></div>
      <div className="stat-card"><h4>Max Packet</h4><p>{stats.packet_stats.max_length}</p></div>
    </div>
  );
}
