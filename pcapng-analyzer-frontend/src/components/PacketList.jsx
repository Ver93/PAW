export default function PacketList({ packets }) {
  return (
    <div className="section-card">
      <h3>Packet List</h3>

      <table className="nice-table">
        <thead>
          <tr>
            <th>No</th>
            <th>Timestamp</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Length</th>
            <th>Info</th>
          </tr>
        </thead>

        <tbody>
          {packets.map((pkt, index) => (
            <tr key={index}>
              <td>{index + 1}</td>
              <td>{pkt.timestamp}</td>
              <td>{pkt.src}</td>
              <td>{pkt.dst}</td>
              <td>{pkt.protocol}</td>
              <td>{pkt.length}</td>
              <td>{pkt.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
